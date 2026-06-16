/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func mustKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := GenerateX25519()
	if err != nil {
		t.Fatalf("GenerateX25519: %v", err)
	}
	return k
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestAuth_RoundTrip: a client SessionID authenticates at the server, both sides
// derive the same auth key, and the recovered shortId matches.
func TestAuth_RoundTrip(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	cr := randomBytes(t, ClientRandomLen)
	shortID := []byte("cohort01") // 8 bytes

	sid, clientKey, err := ClientSessionID(server.PublicKey().Bytes(), client, cr, shortID)
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}
	if len(sid) != sessionIDLen {
		t.Fatalf("SessionID len = %d, want %d", len(sid), sessionIDLen)
	}

	var got []byte
	serverKey, ok := ServerAuthenticate(server, client.PublicKey().Bytes(), cr, sid,
		func(s []byte) bool { got = s; return true }, time.Minute)
	if !ok {
		t.Fatal("ServerAuthenticate rejected a valid client")
	}
	if !bytes.Equal(clientKey, serverKey) {
		t.Fatal("client and server derived different auth keys")
	}
	want := make([]byte, ShortIDLen)
	copy(want, shortID)
	if !bytes.Equal(got, want) {
		t.Fatalf("recovered shortId = %x, want %x", got, want)
	}
}

// TestAuth_WrongServerKey: a SessionID for one server does not authenticate at
// another (the ECDH secret, hence the auth key, differs).
func TestAuth_WrongServerKey(t *testing.T) {
	server := mustKey(t)
	other := mustKey(t)
	client := mustKey(t)
	cr := randomBytes(t, ClientRandomLen)

	sid, _, err := ClientSessionID(server.PublicKey().Bytes(), client, cr, []byte("x"))
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}
	if _, ok := ServerAuthenticate(other, client.PublicKey().Bytes(), cr, sid, nil, time.Minute); ok {
		t.Fatal("authenticated against the wrong server key")
	}
}

// TestAuth_Tampering: flipping a byte of the SessionID or of the random breaks AEAD
// verification.
func TestAuth_Tampering(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	cr := randomBytes(t, ClientRandomLen)
	sid, _, err := ClientSessionID(server.PublicKey().Bytes(), client, cr, []byte("x"))
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}

	bad := append([]byte(nil), sid...)
	bad[0] ^= 0xff
	if _, ok := ServerAuthenticate(server, client.PublicKey().Bytes(), cr, bad, nil, time.Minute); ok {
		t.Fatal("authenticated a tampered SessionID")
	}

	badCR := append([]byte(nil), cr...)
	badCR[0] ^= 0xff
	if _, ok := ServerAuthenticate(server, client.PublicKey().Bytes(), badCR, sid, nil, time.Minute); ok {
		t.Fatal("authenticated against a tampered client random")
	}
}

// TestAuth_ReplayWindow: a SessionID older than the skew is rejected; a generous skew
// accepts it.
func TestAuth_ReplayWindow(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	cr := randomBytes(t, ClientRandomLen)

	shared, err := client.ECDH(server.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	authKey, err := deriveAuthKey(shared, cr)
	if err != nil {
		t.Fatalf("deriveAuthKey: %v", err)
	}
	sid, err := sealAuth(authKey, cr, []byte("x"), time.Now().Add(-2*time.Second))
	if err != nil {
		t.Fatalf("sealAuth: %v", err)
	}

	cpub := client.PublicKey().Bytes()
	if _, ok := ServerAuthenticate(server, cpub, cr, sid, nil, time.Second); ok {
		t.Fatal("accepted a SessionID outside the replay window")
	}
	if _, ok := ServerAuthenticate(server, cpub, cr, sid, nil, time.Minute); !ok {
		t.Fatal("rejected a SessionID inside a generous window")
	}
}

// TestAuth_ShortIDGate: the accept callback can reject an authenticated-but-unknown
// shortId.
func TestAuth_ShortIDGate(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	cr := randomBytes(t, ClientRandomLen)
	sid, _, err := ClientSessionID(server.PublicKey().Bytes(), client, cr, []byte("nope"))
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}
	if _, ok := ServerAuthenticate(server, client.PublicKey().Bytes(), cr, sid,
		func([]byte) bool { return false }, time.Minute); ok {
		t.Fatal("accepted a rejected shortId")
	}
}

// TestCertHMAC: the certificate-binding HMAC is deterministic, key-dependent, and
// verifiable by recomputation.
func TestCertHMAC(t *testing.T) {
	authKey := randomBytes(t, authKeyLen)
	pub := randomBytes(t, 32)

	h1 := CertHMAC(authKey, pub)
	if len(h1) != 64 { // SHA-512
		t.Fatalf("CertHMAC len = %d, want 64", len(h1))
	}
	if !bytes.Equal(h1, CertHMAC(authKey, pub)) {
		t.Fatal("CertHMAC is not deterministic")
	}
	if bytes.Equal(h1, CertHMAC(randomBytes(t, authKeyLen), pub)) {
		t.Fatal("CertHMAC did not depend on the auth key")
	}
	if bytes.Equal(h1, CertHMAC(authKey, randomBytes(t, 32))) {
		t.Fatal("CertHMAC did not depend on the public key")
	}
}

// TestAuth_BadInputs: the size guards reject malformed inputs.
func TestAuth_BadInputs(t *testing.T) {
	key := randomBytes(t, authKeyLen)
	if _, err := sealAuth(key, randomBytes(t, 31), []byte("x"), time.Now()); err != ErrBadRandom {
		t.Fatalf("short random: got %v, want ErrBadRandom", err)
	}
	if _, err := sealAuth(key, randomBytes(t, ClientRandomLen), randomBytes(t, ShortIDLen+1), time.Now()); err != ErrShortID {
		t.Fatalf("long shortId: got %v, want ErrShortID", err)
	}
	if _, _, err := openAuth(key, randomBytes(t, ClientRandomLen), randomBytes(t, 31)); err != ErrBadSession {
		t.Fatalf("short session: got %v, want ErrBadSession", err)
	}
}

// TestGenerateX25519: keys are 32-byte public values and distinct across calls.
func TestGenerateX25519(t *testing.T) {
	a, b := mustKey(t), mustKey(t)
	if len(a.PublicKey().Bytes()) != 32 {
		t.Fatalf("public key len = %d, want 32", len(a.PublicKey().Bytes()))
	}
	if bytes.Equal(a.PublicKey().Bytes(), b.PublicKey().Bytes()) {
		t.Fatal("two generated keys collided")
	}
}
