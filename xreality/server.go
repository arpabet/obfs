/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import (
	"crypto/ecdh"
	"time"
)

// Decision is the result of inspecting a peeked ClientHello: whether it carries valid
// REALITY authentication, and (if so) the derived auth key used to forge/verify the
// certificate binding. Info exposes the parsed ClientHello fields regardless.
type Decision struct {
	// Authenticated is true iff the ClientHello carried a valid, in-window auth token
	// for an accepted shortId. A false value means "treat as a probe" — pass the
	// connection through to the borrowed site.
	Authenticated bool

	// AuthKey is the per-handshake key (non-nil only when Authenticated) for the
	// certificate-binding HMAC (see CertHMAC).
	AuthKey []byte

	// Info is the parsed ClientHello (random, session id, SNI, X25519 share).
	Info ClientHelloInfo
}

// Authenticate is the server's REALITY decision pipeline over a single peeked
// ClientHello record: parse it, then (if it structurally could be ours) reconstruct
// the shared secret from the server's static key and the client's X25519 share,
// verify the sealed SessionID, enforce the replay window, and gate the shortId. It
// composes ParseClientHello with ServerAuthenticate.
//
// accept (if non-nil) gates the recovered shortId; skew (if > 0) bounds the embedded
// timestamp's distance from now. A returned error means the bytes were not a parseable
// ClientHello at all; a parseable-but-unauthenticated ClientHello returns
// (Decision{Authenticated: false}, nil) so the caller routes it to passthrough.
//
// This is the security-critical core of a REALITY server. The surrounding plumbing —
// peeking the record off the raw connection, then either terminating TLS with a
// forged certificate (authenticated) or raw-splicing to the borrowed site (probe) —
// is the remaining TLS-integration work; see REALITY.md.
func Authenticate(serverPriv *ecdh.PrivateKey, clientHelloRecord []byte, accept func(shortID []byte) bool, skew time.Duration) (Decision, error) {
	info, err := ParseClientHello(clientHelloRecord)
	if err != nil {
		return Decision{}, err
	}
	d := Decision{Info: info}
	// Must structurally look like one of ours before attempting the (constant-time) AEAD.
	if len(info.X25519) != 32 || len(info.SessionID) != sessionIDLen || len(info.Random) != ClientRandomLen {
		return d, nil
	}
	if authKey, ok := ServerAuthenticate(serverPriv, info.X25519, info.Random, info.SessionID, accept, skew); ok {
		d.Authenticated = true
		d.AuthKey = authKey
	}
	return d, nil
}
