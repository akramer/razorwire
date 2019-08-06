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
	"strconv"
	"time"

	"github.com/jetstack/cert-manager/third_party/crypto/acme"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// The acme module only includes production, which is bad for testing.
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func main() {
	fmt.Println("Hello world")
	cache := autocert.DirCache(".")
	ctx := context.Background()
	client, err := makeClient(ctx, cache)
	if err != nil {
		panic(err)
	}
	go runDNS(ctx)
	tlscert, err := getCert(ctx, cache, "*.proxy.zomg.net")
	if err != nil {
		fmt.Printf("Error fetching cert from cache, getting it from acme: %s\n", err)
		tlscert, err = validateCert(ctx, cache, client)
		if err != nil {
			panic(err)
		}
	}
	// TODO: eventually changing certs on the fly will require using a tls.Listener
	cfg := &tls.Config{Certificates: []tls.Certificate{*tlscert}}
	srv := &http.Server{
		Addr:         ":8443",
		TLSConfig:    cfg,
		ReadTimeout:  time.Minute,
		WriteTimeout: time.Minute,
	}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

var txtRecord = "foo"
var domainName = "proxy.zomg.net."

func queryResponse(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN A %s", q.Name, "144.202.87.245"))
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
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN NS %s", q.Name, "razorwire.zomg.net."))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSOA:
			log.Printf("Query for %s\n", q.Name)
			rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN SOA razorwire.zomg.net. hostmaster.zomg.net. 1 86400 3600 259200 300", "proxy.zomg.net."))
			if err == nil && q.Name == domainName {
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
	rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN SOA razorwire.zomg.net. hostmaster.zomg.net. 1 86400 3600 259200 300", "proxy.zomg.net."))
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
	dns.HandleFunc("proxy.zomg.net.", handleDNSQuery)

	// start server
	// can redirect with something like
	// iptables -t nat -A PREROUTING -p udp  --dport 53 -j REDIRECT --to-ports 5353
	port := 5353
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Starting at %d\n", port)
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
	order := acme.NewOrder("*.proxy.zomg.net")
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
	key, err := getKey(ctx, cache, "*.proxy.zomg.net")
	if err != nil {
		return nil, err
	}
	csr, err := makeCSR(key, "*.proxy.zomg.net")
	cert, err := client.FinalizeOrder(ctx, order.FinalizeURL, csr)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Certificate successfully finalized!\n")
	var buf bytes.Buffer
	encodeCert(&buf, cert)
	cache.Put(ctx, "*.proxy.zomg.net-cert", buf.Bytes())

	return getCert(ctx, cache, "*.proxy.zomg.net")
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
		Contact:     []string{"mailto:akramer@gmail.com"},
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
