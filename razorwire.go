package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// The acme module only includes production, which is bad for testing.
	letsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func main() {
	fmt.Println("Hello world")
	cache := autocert.DirCache(".")
	_, err := makeClient(cache)
	if err != nil {
		fmt.Printf("Error making client: %s", err)
	}
}

func makeClient(cache autocert.DirCache) (*acme.Client, error) {
	client := acme.Client{
		DirectoryURL: letsEncryptStagingURL,
		UserAgent:    "razorwire proxy",
	}
	acc := acme.Account{
		Contact: []string{"mailto:akramer@gmail.com"},
	}
	key, err := getAccountKey(cache, &acc)
	if err != nil {
		return nil, err
	}
	client.Key = key
	fmt.Printf("About to make registration call")
	_, err = client.Register(context.Background(), &acc, acme.AcceptTOS)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// conflict indicates the key is already registered
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

func getAccountKey(cache autocert.DirCache, account *acme.Account) (*ecdsa.PrivateKey, error) {
	accountKey := fmt.Sprintf("acme_account_key:%s", account.Contact)
	data, err := cache.Get(context.Background(), accountKey)
	if err == autocert.ErrCacheMiss {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		if err := encodeECDSAKey(&buf, key); err != nil {
			return nil, err
		}
		if err := cache.Put(context.Background(), accountKey, buf.Bytes()); err != nil {
			return nil, err
		}
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}
	return nil, errors.New("Failed to parse key")
}

func encodeECDSAKey(w io.Writer, key *ecdsa.PrivateKey) error {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	return pem.Encode(w, pb)
}
