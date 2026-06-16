/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package reality_test

import (
	"bytes"
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

	"go.arpabet.com/obfs/reality"
	"go.arpabet.com/obfs/tlscamo"
)

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

// fallbackServer is a plaintext origin that reads a request and replies body — the
// "real site" probes get reverse-proxied to.
func fallbackServer(t *testing.T, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fallback listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(body))
			}(c)
		}
	}()
	return ln.Addr().String()
}

// tlsUpstream is a real TLS server (its own cert) that echoes a fixed body — the
// "real site" that non-matching-SNI probes get raw-spliced to.
func tlsUpstream(t *testing.T, body string) (addr string, cert tls.Certificate) {
	t.Helper()
	cert, _ = genCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 256)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(body))
			}(c)
		}
	}()
	return ln.Addr().String(), cert
}

func realityServer(t *testing.T, cert tls.Certificate, token []byte, fallback string) net.Listener {
	return realityServerCfg(t, reality.ServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Token:     token,
		Fallback:  fallback,
	})
}

func realityServerCfg(t *testing.T, cfg reality.ServerConfig) net.Listener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rl := reality.Listener(base, cfg)
	t.Cleanup(func() { rl.Close() })
	go func() {
		for {
			c, err := rl.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c) // echo authed tunnels
		}
	}()
	return rl
}

// TestReality_AuthenticatedTunnel: a client with the right token + browser-mimicked
// handshake gets the real tunnel and a round-trip works.
func TestReality_AuthenticatedTunnel(t *testing.T) {
	cert, pool := genCert(t)
	token := []byte("super-secret-tok") // 16 bytes
	rl := realityServer(t, cert, token, fallbackServer(t, "FALLBACK-SITE"))

	dial := reality.Dialer("tcp", rl.Addr().String(), reality.ClientConfig{
		TLS:   tlscamo.Config{ServerName: "localhost", RootCAs: pool},
		Token: token,
	})
	conn, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
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
}

// TestReality_ProbeGetsFallback: an active probe (a normal TLS client that never
// sends the token) is reverse-proxied to the fallback and sees its content.
func TestReality_ProbeGetsFallback(t *testing.T) {
	cert, pool := genCert(t)
	token := []byte("super-secret-tok")
	const body = "FALLBACK-SITE"
	rl := realityServer(t, cert, token, fallbackServer(t, body))

	probe, err := tls.Dial("tcp", rl.Addr().String(), &tls.Config{ServerName: "localhost", RootCAs: pool})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()

	if _, err := probe.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := io.ReadFull(probe, buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != body {
		t.Fatalf("probe got %q, want fallback content %q", buf, body)
	}
}

// TestReality_WrongSNIPassthrough: a probe whose ClientHello SNI does not match
// ServerNames is raw-spliced to the real upstream and terminates TLS against the
// upstream's genuine certificate — not the reality server's.
func TestReality_WrongSNIPassthrough(t *testing.T) {
	cert, _ := genCert(t)
	const body = "REAL-UPSTREAM"
	upstreamAddr, upstreamCert := tlsUpstream(t, body)

	rl := realityServerCfg(t, reality.ServerConfig{
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		Token:       []byte("super-secret-tok"),
		ServerNames: []string{"localhost"},
		Passthrough: upstreamAddr,
	})

	// Probe with a non-matching SNI; verification is skipped (a censor wouldn't care).
	probe, err := tls.Dial("tcp", rl.Addr().String(), &tls.Config{
		ServerName:         "scanner.example",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()

	// The certificate the probe sees must be the upstream's, proving raw passthrough.
	got := probe.ConnectionState().PeerCertificates
	if len(got) == 0 || !bytes.Equal(got[0].Raw, upstreamCert.Leaf.Raw) {
		t.Fatal("probe did not terminate TLS against the real upstream certificate")
	}

	if _, err := probe.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := io.ReadFull(probe, buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != body {
		t.Fatalf("probe got %q, want upstream body %q", buf, body)
	}
}

// TestReality_MatchingSNIAuthenticates: with SNI passthrough enabled, a client whose
// SNI matches still flows through the normal TLS-terminating token path (exercises the
// ClientHello replay into the local TLS server).
func TestReality_MatchingSNIAuthenticates(t *testing.T) {
	cert, pool := genCert(t)
	token := []byte("super-secret-tok")
	upstreamAddr, _ := tlsUpstream(t, "REAL-UPSTREAM")

	rl := realityServerCfg(t, reality.ServerConfig{
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		Token:       token,
		ServerNames: []string{"localhost"},
		Passthrough: upstreamAddr,
	})

	dial := reality.Dialer("tcp", rl.Addr().String(), reality.ClientConfig{
		TLS:   tlscamo.Config{ServerName: "localhost", RootCAs: pool},
		Token: token,
	})
	conn, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
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
}

// TestReality_WrongTokenGetsFallback: a client that completes TLS but sends the
// wrong token is treated as a probe.
func TestReality_WrongTokenGetsFallback(t *testing.T) {
	cert, pool := genCert(t)
	const body = "FALLBACK-SITE"
	rl := realityServer(t, cert, []byte("super-secret-tok"), fallbackServer(t, body))

	probe, err := tls.Dial("tcp", rl.Addr().String(), &tls.Config{ServerName: "localhost", RootCAs: pool})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()

	if _, err := probe.Write([]byte("wrong-token-1234padding")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := io.ReadFull(probe, buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != body {
		t.Fatalf("wrong-token client got %q, want fallback content", buf)
	}
}
