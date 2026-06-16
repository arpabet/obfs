/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package tlscamo_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"go.arpabet.com/obfs/tlscamo"
)

// genCert returns a self-signed certificate valid for localhost/127.0.0.1 and a
// pool that trusts it.
func genCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// tlsEchoServer starts a standard crypto/tls echo server (the unchanged server
// side) and returns its address.
func tlsEchoServer(t *testing.T, alpn []string) string {
	t.Helper()
	cert, _ := serverCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}

// serverCert/pool are shared per test via a package-level cache keyed by test, so
// the listener and the client trust the same self-signed cert.
var testCert tls.Certificate
var testPool *x509.CertPool

func serverCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	if testPool == nil {
		testCert, testPool = genCert(t)
	}
	return testCert, testPool
}

func TestClient_HandshakeEchoALPN(t *testing.T) {
	addr := tlsEchoServer(t, []string{"h2"})
	_, pool := serverCert(t)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := tlscamo.Client(raw, tlscamo.Config{
		ServerName:  "localhost",
		RootCAs:     pool,
		Fingerprint: tlscamo.Chrome,
		NextProtos:  []string{"h2", "http/1.1"},
	})
	if err != nil {
		raw.Close()
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}

	cs, ok := conn.(interface {
		ConnectionState() utls.ConnectionState
	})
	if !ok {
		t.Fatal("conn does not expose ConnectionState")
	}
	st := cs.ConnectionState()
	if st.Version != utls.VersionTLS13 {
		t.Errorf("TLS version = %#x, want TLS 1.3", st.Version)
	}
	if st.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN = %q, want h2", st.NegotiatedProtocol)
	}
}

func TestDialer_EndToEnd(t *testing.T) {
	addr := tlsEchoServer(t, []string{"h2"})
	_, pool := serverCert(t)

	dial := tlscamo.Dialer("tcp", addr, tlscamo.Config{ServerName: "localhost", RootCAs: pool})
	conn, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("echo = %q", buf)
	}
}

// TestRoll_HandshakesAcrossFingerprints: rotating the fingerprint still completes
// the handshake on each connection.
func TestRoll_HandshakesAcrossFingerprints(t *testing.T) {
	addr := tlsEchoServer(t, nil)
	_, pool := serverCert(t)

	for i := 0; i < 6; i++ {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conn, err := tlscamo.Client(raw, tlscamo.Config{
			ServerName: "localhost",
			RootCAs:    pool,
			Roll:       true,
		})
		if err != nil {
			raw.Close()
			t.Fatalf("rolled handshake %d: %v", i, err)
		}
		conn.Close()
	}
}

func TestClient_VerificationFailsForWrongName(t *testing.T) {
	addr := tlsEchoServer(t, nil)
	_, pool := serverCert(t)

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	// ServerName the cert is not valid for, with verification on -> must fail.
	if _, err := tlscamo.Client(raw, tlscamo.Config{
		ServerName: "wrong.example",
		RootCAs:    pool,
	}); err == nil {
		t.Fatal("expected verification failure for an unmatched server name")
	}
}
