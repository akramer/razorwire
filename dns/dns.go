package dns

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// TODO: update DNS using https://support.google.com/domains/answer/6147083?hl=en

// LookupMyAddress returns the ipv4 and ipv6 addresses of this host.
// Value will be an empty string if a particular IP version fails.
func LookupMyAddress() (string, string) {
	r := net.Resolver{}
	var ipv4, ipv6 []string
	for _, a := range []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"} {
		addrs, err := r.LookupHost(context.Background(), a)
		if err != nil {
			fmt.Printf("Error looking up %s: %s", a, err)
		}
		for _, addr := range addrs {
			if strings.IndexByte(addr, '.') != -1 {
				fmt.Printf("Found ipv4 address %s for %s\n", addr, a)
				ipv4 = append(ipv4, addr)
			}
			if strings.IndexByte(addr, ':') != -1 {
				fmt.Printf("Found ipv6 address %s for %s\n", addr, a)
				ipv6 = append(ipv6, addr)
			}
		}
	}
	var myipv4, myipv6 string
	var err error
	for _, a := range ipv4 {
		myipv4, err = myAddressVia(a)
		if err == nil {
			break
		} else {
			fmt.Printf("Error resolving my hostname, %s", err)
		}
	}
	for _, a := range ipv6 {
		myipv6, err = myAddressVia(fmt.Sprintf("[%s]", a))
		if err == nil {
			break
		} else {
			fmt.Printf("Error resolving my hostname, %s", err)
		}
	}
	fmt.Printf("My ipv4 address is %s, ipv6 address is %s\n", myipv4, myipv6)
	return myipv4, myipv6
}

func myAddressVia(addr string) (string, error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{"o-o.myaddr.l.google.com.", dns.TypeTXT, dns.ClassINET}
	c := new(dns.Client)
	in, _, err := c.Exchange(m, fmt.Sprintf("%s:53", addr))
	if err != nil {
		return "", err
	}
	if len(in.Answer) == 0 {
		return "", fmt.Errorf("Zero responses to the lookup query")
	}
	if t, ok := in.Answer[0].(*dns.TXT); ok {
		if len(t.Txt) > 0 {
			return t.Txt[0], nil
		}
	}
	return "", fmt.Errorf("TXT record not found in response")
}
