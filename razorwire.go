package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/jetstack/cert-manager/third_party/crypto/acme"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// The acme module only includes production, which is bad for testing.
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

var args struct {
	Email       string   `arg:"required" help:"e-mail to register with LetsEncrypt"`
	ProxyDomain string   `arg:"required" help:"domain pointed at this server"`
	Hostname    string   `arg:"required" help:"hostname pointed at this server"`
	IP          string   `arg:"required" help:"IP address of this proxy"`
	DNSPort     uint     `help:"Port to open for DNS server"`
	HTTPSPort   uint     `help:"Port to open for HTTPS server"`
	Username    string   `arg:"required"`
	Password    string   `arg:"required"`
	CertName    string   `arg:"-"`
	Zone        string   `arg:"-"`
	Proxy       []string `arg:"separate" help:"hosts to proxy, 'name,http://somehost/', multiple are allowed"`
}

type proxy struct {
	backendURLMap map[string]*url.URL
	clientMap     map[string]*http.Client
}

var proxyRegexp = regexp.MustCompile("^(http|https|nohttps)-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)(?:-([0-9]+))?$")

func newClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// newProxy initializes a new proxy based on commandline arguments
func newProxy() proxy {
	p := proxy{}
	p.backendURLMap = make(map[string]*url.URL)
	p.clientMap = make(map[string]*http.Client)
	for _, n := range args.Proxy {
		vals := strings.Split(n, ",")
		if len(vals) != 2 {
			panic(fmt.Sprintf("Error with --proxyname arg: %s", n))
		}
		k, v := vals[0], vals[1]
		u, err := url.Parse(v)
		if err != nil {
			panic(fmt.Sprintf("error parsing --proxyname URL: %s", err))
		}
		fmt.Printf("Adding proxy mapping %s->%s\n", vals[0], vals[1])
		p.backendURLMap[k] = u
	}
	return p
}

func (p proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"authenticate\"")
		http.Error(w, "error in basic auth", 401)
		return
	}
	if user != args.Username || password != args.Password {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"authenticate\"")
		http.Error(w, "error in basic auth", 401)
		return
	}
	s := strings.Split(r.Host, ".")
	cl, ok := p.clientMap[s[0]]
	if !ok {
		fmt.Printf("Creating new http.Client for %s\n", s[0])
		cl = newClient()
		p.clientMap[s[0]] = cl
	}
	u, ok := p.backendURLMap[s[0]]
	var err error
	if !ok {
		if sm := proxyRegexp.FindStringSubmatch(s[0]); sm != nil {
			var ur string
			if sm[1] == "nohttps" {
				sm[1] = "https"
				if cl.Transport == nil {
					t := http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					}
					cl.Transport = &t
				}
			}
			if len(sm) < 7 || sm[6] == "" {
				ur = fmt.Sprintf("%s://%s.%s.%s.%s/", sm[1], sm[2], sm[3], sm[4], sm[5])
			} else {
				ur = fmt.Sprintf("%s://%s.%s.%s.%s:%s/", sm[1], sm[2], sm[3], sm[4], sm[5], sm[6])
			}
			u, err = url.Parse(ur)
			if err != nil {
				http.Error(w, fmt.Sprintf("unknown host: %s", s[0]), 404)
			}
		} else {
			http.Error(w, fmt.Sprintf("unknown host: %s", s[0]), 404)
			return
		}
	}
	(&proxyRequest{
		client:     cl,
		backendURL: u,
	}).ServeHTTP(w, r)
}

type proxyRequest struct {
	client     *http.Client
	backendURL *url.URL
}

func (p *proxyRequest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := make(http.Header)
	for k, v := range r.Header {
		// should probably be case insensitive matches
		if k == "Authorization" || k == "Close" || k == "Host" || k == "Accept-Encoding" {
			continue
		}
		fmt.Printf("Adding header %s: %v\n", k, v)
		header[k] = v
	}
	u, err := url.Parse(fmt.Sprintf("%s://%s%s", p.backendURL.Scheme, p.backendURL.Host, r.RequestURI))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	req := http.Request{
		URL:           u,
		Method:        r.Method,
		Header:        header,
		Body:          r.Body,
		ContentLength: r.ContentLength,
		Trailer:       r.Trailer,
	}
	fmt.Printf("Sending a request to %+v\n", req)
	resp, err := p.client.Do(&req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Printf("Got response code %d\n", resp.StatusCode)
	var redirectURL *url.URL
	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		fmt.Printf("Running redirect check\n")
		redirectURL, err = p.checkRedirect(r, resp)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	for k, v := range resp.Header {
		if k == "Connection" || k == "X-Forwarded-Proto" || k == "Strict-Transport-Security" {
			continue
		}
		if redirectURL != nil {
			if k == "Location" {
				w.Header().Add("Location", redirectURL.String())
			}
		}
		for _, vs := range v {
			w.Header().Add(k, vs)
		}
		w.Header().Add("Strict-Transport-Security", "max-age=31536000;")
		w.Header().Add("X-Forwarded-Proto", "https")
		w.Header().Add("X-Forwarded-For", r.RemoteAddr)
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *proxyRequest) checkRedirect(req *http.Request, resp *http.Response) (*url.URL, error) {
	loc, found := resp.Header["Location"]
	if !found {
		return nil, fmt.Errorf("Location header not found in redirect request")
	}
	fmt.Printf("Found location header %s\n", loc[0])
	u, err := url.Parse(loc[0])
	if err != nil {
		return nil, fmt.Errorf("Error parsing URL in redirect request, %v", err)
	}
	// If the 301 or 302 points at the same host/port/scheme that we just talked to, redirect to the same.
	// TODO: if the redirect points at another proxyable resource besides the origin, rewrite that too.
	fmt.Printf("%s %s %s vs %s %s %s", u.Hostname(), u.Port(), u.Scheme, p.backendURL.Hostname(), p.backendURL.Port(), p.backendURL.Scheme)
	if u.Hostname() == p.backendURL.Hostname() && u.Port() == p.backendURL.Port() && u.Scheme == p.backendURL.Scheme {
		n, err := url.Parse(fmt.Sprintf("%s://%s/%s", req.URL.Scheme, req.URL.Host, u.RequestURI()))
		if err != nil {
			return nil, fmt.Errorf("Error parsing generated URL for redirect: %v", err)
		}
		fmt.Printf("Location matched - patching redirect to %s\n", n.String())
		return n, nil
	}
	fmt.Printf("Location didn't match, not rewriting redirect\n")
	return nil, nil
}

func main() {
	args.HTTPSPort = 8443
	args.DNSPort = 5335
	arg.MustParse(&args)
	args.CertName = "*." + args.ProxyDomain
	args.Zone = args.ProxyDomain + "."
	fmt.Println("Hello world")
	cache := autocert.DirCache(".")
	ctx := context.Background()
	client, err := makeClient(ctx, cache)
	if err != nil {
		panic(err)
	}
	go runDNS(ctx)
	tlscert, err := getCert(ctx, cache, args.CertName)
	if err != nil {
		fmt.Printf("Error fetching cert from cache, getting it from acme: %s\n", err)
		tlscert, err = validateCert(ctx, cache, client)
		if err != nil {
			panic(err)
		}
	}
	x509cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		panic("error parsing cert")
	}
	remaining := time.Until(x509cert.NotAfter)
	fmt.Printf("%d days remaining before certificate expiration\n", int(remaining.Hours())/24)
	// TODO: eventually changing certs on the fly will require using a tls.Listener
	cfg := &tls.Config{Certificates: []tls.Certificate{*tlscert}}
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", args.HTTPSPort),
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
		Handler:      newProxy(),
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

var txtRecord = "foo"

func queryResponse(m *dns.Msg) {
	host := args.Hostname + "."
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", q.Name, args.IP))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeTXT:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN TXT %s", q.Name, txtRecord))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeNS:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN NS %s", q.Name, host))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSOA:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN SOA %s hostmaster.%s 1 86400 3600 259200 300", args.Zone, host, args.Zone))
			if err == nil && q.Name == args.Zone {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func handleDNSQuery(w dns.ResponseWriter, r *dns.Msg) {
	//fmt.Printf("Received query for %+v\n", *r)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if r.Opcode == dns.OpcodeQuery {
		queryResponse(m)
	}
	if len(m.Answer) > 0 {
		w.WriteMsg(m)
		return
	}
	host := args.Hostname + "."
	soa := fmt.Sprintf("%s 300 IN SOA %s hostmaster.%s 1 86400 3600 259200 300", args.Zone, host, args.Zone)
	rr, err := dns.NewRR(soa)
	if err != nil {
		return
	}
	fmt.Printf("Received unexpected query %v, returning NXDOMAIN\n", *r)
	m.SetRcode(r, 3 /* NXDOMAIN */)
	// return an SOA record in authority along with the NXDOMAIN
	m.Ns = append(m.Ns, rr)
	w.WriteMsg(m)
}

func runDNS(ctx context.Context) {
	dns.HandleFunc(args.Zone, handleDNSQuery)

	// start server
	// can redirect with something like
	// iptables -t nat -A PREROUTING -p udp  --dport 53 -j REDIRECT --to-ports 5335
	server := &dns.Server{Addr: fmt.Sprintf(":%d", args.DNSPort), Net: "udp"}
	log.Printf("Starting at %d\n", args.DNSPort)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
	<-ctx.Done()
	server.Shutdown()
}

func validateCert(ctx context.Context, cache autocert.DirCache, client *acme.Client) (*tls.Certificate, error) {
	// order:
	// createorder, getauthorization, waitforauthorization, waitfororder, CreateCert
	order := acme.NewOrder(args.CertName)
	order, err := client.CreateOrder(ctx, order)
	if err != nil {
		return nil, err
	}
	if len(order.Authorizations) != 1 {
		return nil, fmt.Errorf("Received more than 1 authorization for 1 cert request")
	}
	auth, err := client.GetAuthorization(ctx, order.Authorizations[0])
	if err != nil {
		return nil, err
	}
	var challenge *acme.Challenge
	for _, c := range auth.Challenges {
		fmt.Printf("Available challenge: %s\n", c.Type)
		if c.Type == "dns-01" {
			challenge = c
		}
	}
	if challenge == nil {
		return nil, fmt.Errorf("Challenge dns-01 not found")
	}
	rec, err := client.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return nil, err
	}
	txtRecord = rec
	fmt.Printf("Accepting challenge\n")
	client.AcceptChallenge(ctx, challenge)
	auth, err = client.WaitAuthorization(ctx, auth.URL)
	if err != nil {
		return nil, err
	}
	key, err := getKey(ctx, cache, args.CertName)
	if err != nil {
		return nil, err
	}
	csr, err := makeCSR(key, args.CertName)
	cert, err := client.FinalizeOrder(ctx, order.FinalizeURL, csr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Certificate successfully finalized!\n")
	var buf bytes.Buffer
	encodeCert(&buf, cert)
	cache.Put(ctx, fmt.Sprintf("*.%s-cert", args.CertName), buf.Bytes())

	return getCert(ctx, cache, args.CertName)
}

func getCert(ctx context.Context, cache autocert.DirCache, name string) (*tls.Certificate, error) {
	key, err := cache.Get(ctx, name+"-key")
	if err != nil {
		return nil, err
	}
	cert, err := cache.Get(ctx, name+"-cert")
	if err != nil {
		return nil, err
	}
	x509cert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	return &x509cert, nil
}

func makeClient(ctx context.Context, cache autocert.DirCache) (*acme.Client, error) {
	client := acme.Client{
		//DirectoryURL: letsEncryptStagingURL,
		UserAgent: "razorwire proxy",
	}
	acc := acme.Account{
		Contact:     []string{fmt.Sprintf("mailto:%s", args.Email)},
		TermsAgreed: true,
	}
	key, err := getAccountKey(ctx, cache, &acc)
	if err != nil {
		return nil, err
	}
	client.Key = key
	fmt.Printf("About to make registration call\n")
	_, err = client.CreateAccount(ctx, &acc)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// conflict indicates the key is already registered
		fmt.Println("Account already exists")
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func getAccountKey(ctx context.Context, cache autocert.DirCache, account *acme.Account) (*ecdsa.PrivateKey, error) {
	accountKey := fmt.Sprintf("acme_account_key")
	return getKey(ctx, cache, accountKey)
}

func makeCSR(key crypto.Signer, cn string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

// getKey gets a key from the cache, or generates a new one if it did not exist.
func getKey(ctx context.Context, cache autocert.DirCache, name string) (*ecdsa.PrivateKey, error) {
	data, err := cache.Get(ctx, name+"-key")
	if err == autocert.ErrCacheMiss {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := encodeECDSAKey(&buf, key); err != nil {
			return nil, err
		}
		if err := cache.Put(ctx, name+"-key", buf.Bytes()); err != nil {
			return nil, err
		}
		return key, nil
	}
	d, _ := pem.Decode(data)
	if d == nil {
		return nil, errors.New("Failed to decode PEM data")
	}
	key, err := x509.ParseECPrivateKey(d.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func encodeCert(w io.Writer, data [][]byte) error {
	for _, b := range data {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		err := pem.Encode(w, pb)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}
