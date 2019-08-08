package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
)

// Proxy represents a reverse proxy that handles several configured backends.
type Proxy struct {
	backendURLMap      map[string]*url.URL
	proxyMap           map[string]*httputil.ReverseProxy
	username, password string
}

var proxyRegexp = regexp.MustCompile("^(http|https|nohttps)-([0-9]+)-([0-9]+)-([0-9]+)-([0-9]+)(?:-([0-9]+))?$")

// newProxy initializes a new proxy based on commandline arguments
func New(args []string, username, password string) *Proxy {
	p := Proxy{
		username: username,
		password: password,
	}
	p.backendURLMap = make(map[string]*url.URL)
	p.proxyMap = make(map[string]*httputil.ReverseProxy)
	for _, n := range args {
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
	return &p
}

func newReverseProxy(backend *url.URL, validateCert bool) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{}
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Set("Strict-Transport-Security", "max-age=31536000;")
		return nil
	}
	rp.Director = func(req *http.Request) {
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Del("Authorization")
		req.Header.Del("Close")
		req.URL.Scheme = backend.Scheme
		req.URL.Host = backend.Host
		req.Host = backend.Host
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
		fmt.Printf("Proxying request %+v\n", req)
	}
	if !validateCert {
		rp.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}
	return rp
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"authenticate\"")
		http.Error(w, "error in basic auth", 401)
		return
	}
	if user != p.username || password != p.password {
		w.Header().Add("WWW-Authenticate", "Basic realm=\"authenticate\"")
		http.Error(w, "error in basic auth", 401)
		return
	}
	s := strings.Split(r.Host, ".")
	var err error
	validate := true
	u, ok := p.backendURLMap[s[0]]
	if !ok {
		if sm := proxyRegexp.FindStringSubmatch(s[0]); sm != nil {
			var ur string
			if sm[1] == "nohttps" {
				sm[1] = "https"
				validate = false
			}
			if len(sm) < 7 || sm[6] == "" {
				ur = fmt.Sprintf("%s://%s.%s.%s.%s/", sm[1], sm[2], sm[3], sm[4], sm[5])
			} else {
				ur = fmt.Sprintf("%s://%s.%s.%s.%s:%s/", sm[1], sm[2], sm[3], sm[4], sm[5], sm[6])
			}
			u, err = url.Parse(ur)
			if err != nil {
				http.Error(w, fmt.Sprintf("unknown host: %s", s[0]), 404)
				return
			}
		} else {
			http.Error(w, fmt.Sprintf("unknown host: %s", s[0]), 404)
			return
		}
	}
	pr, ok := p.proxyMap[s[0]]
	if !ok {
		fmt.Printf("Creating new httputil.ReverseProxy for %s, url: %+v\n", s[0], u)
		pr = newReverseProxy(u, validate)
		p.proxyMap[s[0]] = pr
	}
	pr.ServeHTTP(w, r)
}

func checkRedirect(req *http.Request, resp *http.Response) (*url.URL, error) {
	/*	loc, found := resp.Header["Location"]
		if !found {
			return nil, fmt.Errorf("Location header not found in redirect request")
		}
		fmt.Printf("Found location header %s\n", loc[0])
		u, err := url.Parse(loc[0])
		if err != nil {
			return nil, fmt.Errorf("Error parsing URL in redirect request, %v", err)
		}*/
	// If the 301 or 302 points at the same host/port/scheme that we just talked to, redirect to the same.
	// TODO: if the redirect points at another proxyable resource besides the origin, rewrite that too.
	//fmt.Printf("%s %s %s vs %s %s %s", u.Hostname(), u.Port(), u.Scheme, p.backendURL.Hostname(), p.backendURL.Port(), p.backendURL.Scheme)
	/*	if u.Hostname() == p.backendURL.Hostname() && u.Port() == p.backendURL.Port() && u.Scheme == p.backendURL.Scheme {
			n, err := url.Parse(fmt.Sprintf("%s://%s/%s", req.URL.Scheme, req.URL.Host, u.RequestURI()))
			if err != nil {
				return nil, fmt.Errorf("Error parsing generated URL for redirect: %v", err)
			}
			fmt.Printf("Location matched - patching redirect to %s\n", n.String())
			return n, nil
		}
		fmt.Printf("Location didn't match, not rewriting redirect\n")*/
	return nil, nil
}
