/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Composes three obfs layers in one process — port hopping (obfs/hop), browser TLS
 * mimicry (obfs/tlscamo), and traffic shaping (obfs) inside the tunnel — over a plain
 * echo service:
 *
 *     client:  hop.Dialer -> tlscamo.Client (outermost) -> obfs.Wrap (shaping, inside)
 *     server:  hop.MultiListener -> crypto/tls server   -> obfs.Wrap (shaping, inside)
 *
 *     GOWORK=off go run .
 *
 * The layering rule: the fingerprint-bearing TLS layer is OUTERMOST (what the censor
 * sees), and traffic shaping goes INSIDE the encrypted tunnel. Apply every layer
 * symmetrically on both peers.
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"go.arpabet.com/obfs"
	"go.arpabet.com/obfs/hop"
	"go.arpabet.com/obfs/tlscamo"
)

// shaping is applied symmetrically inside the tunnel on both ends.
var shaping = obfs.Policy{
	CellSize: 512,
	Front:    &obfs.FrontConfig{Window: 500 * time.Millisecond, MaxCount: 8},
}

func main() {
	cert, pool := genCert()

	// Reserve three local addresses for the server to hop across.
	addrs := []string{freeAddr(), freeAddr(), freeAddr()}

	// --- server: listen on all hop addresses; TLS-terminate, then shape inside ---
	lis, err := hop.MultiListener(addrs, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	go func() {
		for {
			raw, err := lis.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				tlsConn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
				shaped := obfs.Wrap(tlsConn, shaping)
				io.Copy(shaped, shaped) // echo
			}(raw)
		}
	}()

	// --- client: hop-dial, mimic a browser ClientHello, shape inside ---
	dial, err := hop.Dialer(addrs, 30*time.Second, nil)
	if err != nil {
		log.Fatal(err)
	}
	raw, err := dial()
	if err != nil {
		log.Fatal(err)
	}
	tlsConn, err := tlscamo.Client(raw, tlscamo.Config{
		ServerName:  "localhost",
		RootCAs:     pool,
		Fingerprint: tlscamo.Chrome,
	})
	if err != nil {
		log.Fatal(err)
	}
	shaped := obfs.Wrap(tlsConn, shaping)
	defer shaped.Close()

	const msg = "hello through hop + tlscamo + shaping"
	if _, err := shaped.Write([]byte(msg)); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(shaped, buf); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("hopped %d addresses, browser-mimicked TLS, shaped into %d-byte cells:\n  echo -> %q\n",
		len(addrs), shaping.CellSize, string(buf))
}

// freeAddr returns a currently-free localhost address (small race before re-binding,
// acceptable for a demo).
func freeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// genCert builds a self-signed certificate for localhost and a pool that trusts it.
func genCert() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
