/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: MPL-2.0
 */

package xrayreality_test

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

	reality "github.com/xtls/reality"
	"go.arpabet.com/obfs/xrayreality"
)

const sni = "www.realsite.com"

// waitForDetection blocks until the library's per-Dest post-handshake record-length
// detection (kicked off by NewListener) has finished for all ALPN variants, so the
// server's handshake does not stall waiting for it. The map stores a bool placeholder
// until detection completes and replaces it with a []int.
func waitForDetection(dest string) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, alpn := range []string{"0", "1", "2"} {
			v, ok := reality.GlobalPostHandshakeRecordsLens.Load(dest + " " + sni + " " + alpn)
			if !ok {
				ready = false
				break
			}
			if _, placeholder := v.(bool); placeholder {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func selfSigned(t *testing.T, name string) tls.Certificate {
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

// startDest runs the real borrowed site: a TLS 1.3 server that echoes a fixed body.
func startDest(t *testing.T, body string) (addr string, leafDER []byte) {
	t.Helper()
	cert := selfSigned(t, sni)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dest listen: %v", err)
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
				_, _ = c.Read(make([]byte, 256))
				_, _ = c.Write([]byte(body))
			}(c)
		}
	}()
	return ln.Addr().String(), cert.Certificate[0]
}

func startServer(t *testing.T, dest string) (addr string, pub []byte, shortID []byte) {
	t.Helper()
	priv, pub, err := xrayreality.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	shortID = []byte("xraydemo") // 8 bytes
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := xrayreality.Listener(base, xrayreality.ServerConfig{
		PrivateKey:  priv,
		ShortIDs:    [][]byte{shortID},
		ServerNames: []string{sni},
		Dest:        dest,
		MaxTimeDiff: time.Minute,
	})
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c) // echo authenticated tunnels
		}
	}()
	return ln.Addr().String(), pub, shortID
}

// TestXray_AuthenticatedTunnel: the ported client authenticates against the GENUINE
// xtls/reality server (the exact code real Xray runs) and a full application-data
// round-trip works — i.e. the client is wire-compatible with Xray. The genuine server
// authenticated our ClientHello (X25519 ECDH → HKDF → AES-256-GCM SessionID + shortId)
// and our client verified the server's forged certificate via HMAC-SHA512(authKey,
// ed25519Pub); data then flows over ordinary TLS 1.3 (incl. the library's disguised
// post-handshake dummy NewSessionTicket, which requires the same uTLS build Xray pins).
func TestXray_AuthenticatedTunnel(t *testing.T) {
	dest, _ := startDest(t, "BORROWED-SITE")
	addr, pub, shortID := startServer(t, dest)
	waitForDetection(dest) // let the library's Dest record-length detection populate

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn, err := xrayreality.Client(raw, xrayreality.ClientConfig{
		PublicKey:  pub,
		ShortID:    shortID,
		ServerName: sni,
	})
	if err != nil {
		raw.Close()
		t.Fatalf("REALITY handshake against the genuine xtls/reality server failed: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
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

// TestXray_ProbePassthrough: a plain TLS probe (no REALITY auth) is relayed by the
// genuine server to the borrowed site and sees that site's certificate + content.
func TestXray_ProbePassthrough(t *testing.T) {
	const body = "BORROWED-SITE"
	dest, destLeaf := startDest(t, body)
	addr, _, _ := startServer(t, dest)

	probe, err := tls.Dial("tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()

	if got := probe.ConnectionState().PeerCertificates; len(got) == 0 || !equalBytes(got[0].Raw, destLeaf) {
		t.Fatal("probe did not terminate against the borrowed site's certificate")
	}
	_ = probe.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := probe.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	buf := make([]byte, len(body))
	if _, err := io.ReadFull(probe, buf); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(buf) != body {
		t.Fatalf("probe got %q, want borrowed-site body %q", buf, body)
	}
}

// TestXray_WrongKey: a client with the wrong server public key fails the REALITY HMAC
// verification (it is relayed to the borrowed site, whose certificate the HMAC check
// rejects) rather than returning a bogus tunnel.
func TestXray_WrongKey(t *testing.T) {
	dest, _ := startDest(t, "BORROWED-SITE")
	addr, _, shortID := startServer(t, dest)
	_, wrongPub, err := xrayreality.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if conn, err := xrayreality.Client(raw, xrayreality.ClientConfig{
		PublicKey:        wrongPub,
		ShortID:          shortID,
		ServerName:       sni,
		HandshakeTimeout: 5 * time.Second,
	}); err == nil {
		conn.Close()
		t.Fatal("expected HMAC verification failure with the wrong server key")
	}
	raw.Close()
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
