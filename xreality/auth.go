/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package xreality implements the security-critical authentication core of a
// REALITY-style transport: the X25519 key agreement, the auth-key derivation, the
// AEAD-authenticated payload smuggled in the TLS ClientHello SessionID, and the
// keyed certificate-binding HMAC. These are pure, deterministic, fully testable
// functions with no dependency outside the standard library.
//
// # Scope
//
// This file is the crypto/auth core — the TLS-independent functions (ECDH, HKDF auth
// key, AEAD SessionID seal/open, cert-binding HMAC). The live transport built on top of
// it lives in client.go (Client/Dialer) and listener.go (Listener):
//
//   - client: mimic a browser ClientHello (uTLS), reuse its X25519 key share as the
//     REALITY ephemeral, inject the sealed SessionID, and verify the server via a
//     post-handshake channel-bound HMAC (see CertHMAC / ExportKeyingMaterial) instead
//     of a CA chain;
//   - server: peek the raw ClientHello, run Authenticate, then terminate TLS for
//     authenticated clients or raw-splice probes to the borrowed site (Dest).
//
// Replacing REALITY's in-handshake forged certificate with a post-handshake
// channel-bound HMAC lets this run on stock crypto/tls + the uTLS public API with no
// forked TLS stack. The trade-off is that it is NOT wire-compatible with Xray REALITY
// (acceptable, since both peers run this package). See REALITY.md at the repository root
// for the full design, the security caveats, and the path to Xray interop.
//
// # Wire self-consistency, not Xray compatibility
//
// Both peers run this package, so the layout is chosen for clarity and is NOT
// byte-compatible with Xray's REALITY (which must interoperate with its own servers).
// The SessionID is the full AES-256-GCM output of a 16-byte payload, exactly filling
// the 32-byte field:
//
//	authKey   = HKDF-SHA256(ikm=ecdhShared, salt=clientRandom, info)         [32B]
//	plaintext = [8B unix seconds][8B shortId]                                [16B]
//	SessionID = AES-256-GCM(authKey, nonce=clientRandom[20:32],
//	                        aad=clientRandom[:20]).Seal(plaintext)           [32B]
//
// The auth key is fresh per handshake (the client uses an ephemeral X25519 key), so
// reusing ClientHello bytes as nonce/salt is safe.
//
// # Use responsibly
//
// Dual-use, like the rest of obfs: do not use to evade authorized monitoring or in
// violation of applicable law.
package xreality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// ClientRandomLen is the size of the TLS ClientHello random the auth derivation
	// binds to. It is fixed by TLS.
	ClientRandomLen = 32
	// ShortIDLen is the fixed width of a client-cohort identifier inside the payload.
	ShortIDLen = 8

	sessionIDLen = 32 // the TLS SessionID field this fills exactly
	authKeyLen   = 32 // AES-256-GCM key from HKDF
	payloadLen   = 16 // [8B time][8B shortId]; GCM adds a 16B tag -> 32B SessionID
	aadLen       = 20 // clientRandom[:20] as AEAD additional data
	nonceLen     = 12 // clientRandom[20:32] as the GCM nonce (AES-GCM standard size)

	hkdfInfo = "go.arpabet.com/obfs/xreality v1 auth"
)

var (
	// ErrBadRandom is returned when the ClientHello random is not ClientRandomLen.
	ErrBadRandom = errors.New("xreality: client random must be 32 bytes")
	// ErrShortID is returned when a shortId exceeds ShortIDLen.
	ErrShortID = errors.New("xreality: shortId exceeds 8 bytes")
	// ErrBadSession is returned when a SessionID is not the expected length.
	ErrBadSession = errors.New("xreality: session id must be 32 bytes")
	// ErrAuth is returned when a SessionID fails AEAD verification.
	ErrAuth = errors.New("xreality: authentication failed")
)

// GenerateX25519 returns a fresh X25519 key pair. The server's pair is long-lived
// (its public key is distributed to clients, the way a REALITY public key is); each
// client generates an ephemeral pair per connection.
func GenerateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// deriveAuthKey turns an ECDH shared secret and the ClientHello random into the
// per-handshake AES-256-GCM auth key via HKDF-SHA256.
func deriveAuthKey(shared, clientRandom []byte) ([]byte, error) {
	if len(clientRandom) != ClientRandomLen {
		return nil, ErrBadRandom
	}
	return hkdf.Key(sha256.New, shared, clientRandom, hkdfInfo, authKeyLen)
}

// aeadFor builds the AES-256-GCM AEAD for an auth key.
func aeadFor(authKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealAuth produces the 32-byte SessionID authenticating (t, shortID) under authKey,
// bound to clientRandom. t is truncated to whole seconds.
func sealAuth(authKey, clientRandom, shortID []byte, t time.Time) ([]byte, error) {
	if len(clientRandom) != ClientRandomLen {
		return nil, ErrBadRandom
	}
	if len(shortID) > ShortIDLen {
		return nil, ErrShortID
	}
	aead, err := aeadFor(authKey)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, payloadLen)
	binary.BigEndian.PutUint64(pt[0:8], uint64(t.Unix()))
	copy(pt[8:16], shortID) // zero-padded to ShortIDLen
	return aead.Seal(nil, clientRandom[aadLen:], pt, clientRandom[:aadLen]), nil
}

// openAuth verifies a SessionID and returns the embedded timestamp and (8-byte,
// zero-padded) shortID.
func openAuth(authKey, clientRandom, sessionID []byte) (time.Time, []byte, error) {
	if len(clientRandom) != ClientRandomLen {
		return time.Time{}, nil, ErrBadRandom
	}
	if len(sessionID) != sessionIDLen {
		return time.Time{}, nil, ErrBadSession
	}
	aead, err := aeadFor(authKey)
	if err != nil {
		return time.Time{}, nil, err
	}
	pt, err := aead.Open(nil, clientRandom[aadLen:], sessionID, clientRandom[:aadLen])
	if err != nil {
		return time.Time{}, nil, ErrAuth
	}
	t := time.Unix(int64(binary.BigEndian.Uint64(pt[0:8])), 0)
	shortID := make([]byte, ShortIDLen)
	copy(shortID, pt[8:16])
	return t, shortID, nil
}

// CertHMAC computes the keyed certificate-binding signature an authenticated REALITY
// server substitutes for the real certificate signature: HMAC-SHA512(authKey,
// ed25519Pub). The client recomputes it to verify the server without a CA chain.
// Compare with hmac.Equal.
func CertHMAC(authKey, ed25519Pub []byte) []byte {
	m := hmac.New(sha512.New, authKey)
	m.Write(ed25519Pub)
	return m.Sum(nil)
}

// ClientSessionID is the client-side entry point: from the server's static public
// key, the client's ephemeral key, the ClientHello random, and a shortId, it derives
// the auth key and the SessionID to embed in the ClientHello. The auth key is kept to
// later verify the server's CertHMAC.
func ClientSessionID(serverPub []byte, clientEphemeral *ecdh.PrivateKey, clientRandom, shortID []byte) (sessionID, authKey []byte, err error) {
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		return nil, nil, err
	}
	shared, err := clientEphemeral.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}
	authKey, err = deriveAuthKey(shared, clientRandom)
	if err != nil {
		return nil, nil, err
	}
	sessionID, err = sealAuth(authKey, clientRandom, shortID, time.Now())
	if err != nil {
		return nil, nil, err
	}
	return sessionID, authKey, nil
}

// ServerAuthenticate is the server-side entry point: from its static private key, the
// client's ephemeral public key (read from the ClientHello key share), the
// ClientHello random, and the SessionID, it reconstructs the auth key and verifies
// the embedded token. accept (if non-nil) gates the recovered shortId, and skew (if
// > 0) bounds the embedded timestamp's distance from now (replay window). On success
// it returns the auth key for forging the certificate HMAC.
//
// It returns ok=false for any failure with no distinguishing error, so a probe and a
// malformed client are handled identically (both get passed through upstream).
func ServerAuthenticate(serverPriv *ecdh.PrivateKey, clientEphemeralPub, clientRandom, sessionID []byte, accept func(shortID []byte) bool, skew time.Duration) (authKey []byte, ok bool) {
	pub, err := ecdh.X25519().NewPublicKey(clientEphemeralPub)
	if err != nil {
		return nil, false
	}
	shared, err := serverPriv.ECDH(pub)
	if err != nil {
		return nil, false
	}
	authKey, err = deriveAuthKey(shared, clientRandom)
	if err != nil {
		return nil, false
	}
	t, shortID, err := openAuth(authKey, clientRandom, sessionID)
	if err != nil {
		return nil, false
	}
	if skew > 0 {
		if d := time.Since(t); d < -skew || d > skew {
			return nil, false
		}
	}
	if accept != nil && !accept(shortID) {
		return nil, false
	}
	return authKey, true
}
