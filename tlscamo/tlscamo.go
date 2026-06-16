/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package tlscamo wraps a connection in a TLS client whose ClientHello mimics a
// real web browser (matching its JA3/JA4 fingerprint), using the uTLS library. A
// censor that fingerprints TLS handshakes then sees an ordinary Chrome/Firefox/…
// client instead of Go's distinctive crypto/tls ClientHello.
//
// It is a separate module so the uTLS dependency stays out of the zero-dependency
// go.arpabet.com/obfs core; it depends on nothing else in the obfs family and
// produces a plain net.Conn, so it composes with value-rpc, gRPC, or net/http.
//
// # Layering
//
// tlscamo must be the OUTERMOST layer (closest to the wire) for the fingerprint to
// be observable — dial TCP, wrap it with tlscamo, and put any obfs traffic shaping
// INSIDE the tunnel (wrap the returned conn), never outside it (which would hide
// the browser handshake inside opaque cells and defeat the point).
//
// # Server side
//
// tlscamo is a client-side concern: the server runs an ordinary crypto/tls server
// (e.g. value-rpc's NewTLSServer). Leave the server's ALPN unset, or include the
// protocols the client offers, so the mimicked ALPN does not break negotiation.
//
// # Encrypted ClientHello (ECH)
//
// Set Config.ECHConfigList (a serialized ECHConfigList, usually from the target's
// DNS HTTPS/SVCB "ech=" record) to encrypt the inner ClientHello, hiding the real
// SNI from a censor that blocks on plaintext server names. ECH needs TLS 1.3 and
// only succeeds if the server negotiates it; see the field doc.
//
// # Caveats
//
// Browser fingerprints drift; pin the utls version and refresh presets over time.
// This provides camouflage and the normal TLS confidentiality/authentication — it
// is not anonymity.
package tlscamo

import (
	"crypto/x509"
	"math/rand"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Preset fingerprints, re-exported so callers need not import utls directly. Each
// "_Auto" preset parrots the current stable version of that browser.
var (
	Chrome     = utls.HelloChrome_Auto
	Firefox    = utls.HelloFirefox_Auto
	Safari     = utls.HelloSafari_Auto
	Edge       = utls.HelloEdge_Auto
	Randomized = utls.HelloRandomized
)

// rollSet is the pool of fingerprints used when Config.Roll is set.
var rollSet = []utls.ClientHelloID{Chrome, Firefox, Safari, Edge}

// Config controls the mimicked TLS client.
type Config struct {
	// ServerName is the SNI and the name verified against the server certificate.
	ServerName string

	// Fingerprint selects the ClientHello to imitate; the zero value uses Chrome.
	// Use the package presets (Chrome, Firefox, …) to avoid importing utls.
	Fingerprint utls.ClientHelloID

	// NextProtos is the offered ALPN list; empty defaults to {"h2","http/1.1"} so
	// the handshake matches what a browser sends.
	NextProtos []string

	// RootCAs verifies the server certificate; nil uses the host's root store.
	RootCAs *x509.CertPool

	// InsecureSkipVerify disables certificate verification (testing only).
	InsecureSkipVerify bool

	// Roll picks a random fingerprint from a pool of common browsers on each call,
	// so repeated connections do not all share one fingerprint.
	Roll bool

	// ECHConfigList, when non-empty, is a serialized TLS ECHConfigList that turns on
	// Encrypted ClientHello: the inner ClientHello — including the real ServerName
	// (SNI) — is encrypted under one of these configs, so a censor keying on
	// plaintext SNI sees only the public outer name. Obtain it out of band, typically
	// from the target's DNS HTTPS/SVCB record ("ech=" value).
	//
	// ECH requires TLS 1.3 and a fingerprint whose ClientHello carries a (GREASE) ECH
	// extension — the default Chrome preset does. The handshake then succeeds ONLY if
	// the server negotiates ECH; if it rejects ECH, Client returns an error (which may
	// carry a retry ECHConfigList). Leave empty to keep the prior plaintext-SNI behavior.
	ECHConfigList []byte
}

// Client performs a uTLS handshake over conn — typically a freshly dialed TCP
// connection — presenting a browser-like ClientHello, and returns the established
// TLS connection. The handshake runs synchronously; set a deadline on conn first
// to bound it. See the package doc for the required layering.
func Client(conn net.Conn, cfg Config) (net.Conn, error) {
	id := cfg.Fingerprint
	if id.Client == "" {
		id = Chrome
	}
	if cfg.Roll {
		id = rollSet[rand.Intn(len(rollSet))]
	}
	alpn := cfg.NextProtos
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}
	uconn := utls.UClient(conn, &utls.Config{
		ServerName:                     cfg.ServerName,
		RootCAs:                        cfg.RootCAs,
		InsecureSkipVerify:             cfg.InsecureSkipVerify,
		NextProtos:                     alpn,
		EncryptedClientHelloConfigList: cfg.ECHConfigList,
	}, id)
	if err := uconn.Handshake(); err != nil {
		return nil, err
	}
	return uconn, nil
}

// Dialer returns a dial function suitable for valuerpc.NewFuncDialer: each call
// dials network/addr and performs the mimicked handshake. When cfg.ServerName is
// empty it is derived from addr's host.
func Dialer(network, addr string, cfg Config) func() (net.Conn, error) {
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	return func() (net.Conn, error) {
		raw, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		conn, err := Client(raw, cfg)
		if err != nil {
			raw.Close()
			return nil, err
		}
		return conn, nil
	}
}
