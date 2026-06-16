/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality_test

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

	"go.arpabet.com/obfs/xreality"
)

func selfSignedCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// realSite is a stand-in for the borrowed dest: a real TLS server (its own cert) that
// echoes a fixed body — what unauthenticated probes get spliced to.
func realSite(t *testing.T, body string) (addr string, leafDER []byte) {
	t.Helper()
	cert := selfSignedCert(t, "www.realsite.com")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("realSite listen: %v", err)
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
				buf := make([]byte, 64)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte(body))
			}(c)
		}
	}()
	return ln.Addr().String(), cert.Certificate[0]
}

func startServer(t *testing.T, cfg xreality.ServerConfig) net.Listener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rl := xreality.Listener(base, cfg)
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

// TestTransport_AuthenticatedTunnel: a REALITY client with the right server key and
// shortId gets an end-to-end tunnel and a round-trip works.
func TestTransport_AuthenticatedTunnel(t *testing.T) {
	server, err := xreality.GenerateX25519()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dest, _ := realSite(t, "REAL-SITE")
	shortID := []byte("cohort01")
	rl := startServer(t, xreality.ServerConfig{
		PrivateKey: server,
		ShortIDs:   [][]byte{shortID},
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "www.realsite.com")}},
		Dest:       dest,
		TimeSkew:   time.Minute,
	})

	dial := xreality.Dialer("tcp", rl.Addr().String(), xreality.ClientConfig{
		ServerPublicKey: server.PublicKey().Bytes(),
		ShortID:         shortID,
		ServerName:      "www.realsite.com",
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

// TestTransport_ProbePassthrough: an ordinary TLS client (no REALITY auth) is spliced
// to the real dest and terminates TLS against the dest's genuine certificate.
func TestTransport_ProbePassthrough(t *testing.T) {
	server, _ := xreality.GenerateX25519()
	const body = "REAL-SITE"
	dest, destLeaf := realSite(t, body)
	rl := startServer(t, xreality.ServerConfig{
		PrivateKey: server,
		ShortIDs:   [][]byte{[]byte("cohort01")},
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "www.realsite.com")}},
		Dest:       dest,
		TimeSkew:   time.Minute,
	})

	probe, err := tls.Dial("tcp", rl.Addr().String(), &tls.Config{ServerName: "www.realsite.com", InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()

	if got := probe.ConnectionState().PeerCertificates; len(got) == 0 || !equalBytes(got[0].Raw, destLeaf) {
		t.Fatal("probe did not terminate against the real dest certificate")
	}
	if _, err := probe.Write([]byte("hi")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := io.ReadFull(probe, buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != body {
		t.Fatalf("probe got %q, want dest body %q", buf, body)
	}
}

// TestTransport_WrongKey: a client using the wrong server public key is not
// authenticated (the server passes it through to dest), so the channel-bound server
// auth fails and Client returns an error rather than a bogus tunnel.
func TestTransport_WrongKey(t *testing.T) {
	server, _ := xreality.GenerateX25519()
	wrong, _ := xreality.GenerateX25519()
	dest, _ := realSite(t, "REAL-SITE")
	rl := startServer(t, xreality.ServerConfig{
		PrivateKey: server,
		ShortIDs:   [][]byte{[]byte("cohort01")},
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "www.realsite.com")}},
		Dest:       dest,
		TimeSkew:   time.Minute,
	})

	dial := xreality.Dialer("tcp", rl.Addr().String(), xreality.ClientConfig{
		ServerPublicKey:  wrong.PublicKey().Bytes(),
		ShortID:          []byte("cohort01"),
		ServerName:       "www.realsite.com",
		HandshakeTimeout: 3 * time.Second,
	})
	if conn, err := dial(); err == nil {
		conn.Close()
		t.Fatal("expected channel-auth failure when using the wrong server key")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
