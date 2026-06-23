/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: MPL-2.0
 *
 * The client handshake below is a focused port of the REALITY client in
 * XTLS/Xray-core (transport/internet/reality/reality.go, © RPRX, MPL-2.0): the
 * SessionID construction, the X25519/HKDF/AES-GCM auth, and the HMAC certificate
 * verification. The optional "spider" web-crawl fallback is omitted, and the peer
 * certificate is read from the standard uTLS VerifyPeerCertificate rawCerts argument
 * instead of Xray's unsafe field access. This file is therefore MPL-2.0, not BUSL-1.1
 * like the obfs core; see LICENSE in this directory.
 */

// Package xrayreality is a wire-compatible REALITY transport: its client interoperates
// with a genuine Xray REALITY server, and its server is a genuine Xray REALITY server
// (github.com/xtls/reality). Unlike go.arpabet.com/obfs/xreality (the dependency-light,
// channel-bound variant that is NOT Xray-compatible), this module reproduces Xray's
// exact on-wire protocol — at the cost of a forked-TLS dependency (xtls/reality, MPL-2.0)
// and this module being MPL-2.0.
//
// Use it only when you must interoperate with real Xray endpoints; otherwise prefer
// obfs/xreality. See REALITY.md at the repository root for the full design.
package xrayreality

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/xerrors"
)

// DefaultFingerprint is the browser ClientHello mimicked when none is set. It must be a
// TLS 1.3 fingerprint that offers an X25519 key share (Chrome does).
var DefaultFingerprint = utls.HelloChrome_Auto

// DefaultClientVersion is embedded in the SessionID; a server with MinClientVer/
// MaxClientVer set compares against it. Override via ClientConfig.Version for a server
// that gates on a specific client version.
var DefaultClientVersion = [3]byte{1, 8, 22}

// DefaultHandshakeTimeout bounds the handshake.
const DefaultHandshakeTimeout = 15 * time.Second

const sessionIDOffset = 39 // fixed location of the 32-byte SessionID inside the ClientHello

var (
	errNoTLS13      = xerrors.New("xrayreality: fingerprint does not offer a TLS 1.3 X25519 key share")
	errBadHello     = xerrors.New("xrayreality: ClientHello too short to carry a SessionID")
	errNotVerified  = xerrors.New("xrayreality: server certificate failed REALITY HMAC verification (MITM or wrong key)")
	errNoServerName = xerrors.New("xrayreality: ServerName is required")
)

// ClientConfig configures the REALITY client. It is wire-compatible with Xray.
type ClientConfig struct {
	// PublicKey is the server's static X25519 public key (32 bytes) — Xray's "public key".
	PublicKey []byte

	// ShortID is the client's short id (<= 8 bytes), matching one the server accepts.
	ShortID []byte

	// ServerName is the borrowed SNI presented in the ClientHello.
	ServerName string

	// Fingerprint selects the mimicked browser ClientHello; zero value uses Chrome.
	Fingerprint utls.ClientHelloID

	// Version is the 3-byte client version embedded in the SessionID; zero uses
	// DefaultClientVersion.
	Version [3]byte

	// HandshakeTimeout bounds the handshake; 0 uses DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// Client performs the REALITY client handshake over conn and returns the verified
// tunnel. It mimics a browser ClientHello (uTLS), reuses that hello's X25519 key share
// as the REALITY ephemeral, seals the authenticated SessionID exactly as Xray does, and
// verifies the server's forged certificate via HMAC-SHA512(authKey, ed25519Pub).
func Client(conn net.Conn, cfg ClientConfig) (net.Conn, error) {
	if cfg.ServerName == "" {
		return nil, errNoServerName
	}
	serverPub, err := ecdh.X25519().NewPublicKey(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	a := &authVerifier{}
	uc := &utls.Config{
		ServerName:             cfg.ServerName,
		InsecureSkipVerify:     true, // the server is verified by the REALITY HMAC below, not a CA chain
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  a.verify,
	}
	id := cfg.Fingerprint
	if id.Client == "" {
		id = DefaultFingerprint
	}
	u := utls.UClient(conn, uc, id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}

	hello := u.HandshakeState.Hello
	if len(hello.Raw) < sessionIDOffset+32 {
		return nil, errBadHello
	}
	ver := cfg.Version
	if ver == ([3]byte{}) {
		ver = DefaultClientVersion
	}

	// Build the SessionID: [3B version][1B reserved][4B unix time][8B shortId], then
	// AEAD-seal it bound to the rest of the ClientHello.
	sid := make([]byte, 32)
	hello.SessionId = sid
	copy(hello.Raw[sessionIDOffset:sessionIDOffset+32], sid) // zero the SessionID region in Raw (the AEAD AAD)
	sid[0], sid[1], sid[2] = ver[0], ver[1], ver[2]
	sid[3] = 0
	binary.BigEndian.PutUint32(sid[4:], uint32(time.Now().Unix()))
	copy(sid[8:], cfg.ShortID)

	ks := u.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		return nil, errNoTLS13
	}
	ecdhe := ks.Ecdhe
	if ecdhe == nil {
		ecdhe = ks.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, errNoTLS13
	}
	authKey, err := ecdhe.ECDH(serverPub)
	if err != nil {
		return nil, err
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		return nil, err
	}
	a.authKey = authKey

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aead.Seal(sid[:0], hello.Random[20:], sid[:16], hello.Raw)
	copy(hello.Raw[sessionIDOffset:sessionIDOffset+32], sid) // write the sealed SessionID back into Raw

	if err := u.Handshake(); err != nil {
		return nil, err
	}
	if !a.verified {
		u.Close()
		return nil, errNotVerified
	}
	_ = conn.SetDeadline(time.Time{})
	return u, nil
}

// authVerifier holds the REALITY auth key across the handshake so VerifyPeerCertificate
// can check the server's forged certificate signature.
type authVerifier struct {
	authKey  []byte
	verified bool
}

// verify implements the REALITY certificate check: the server's certificate carries an
// ed25519 public key, and its signature is HMAC-SHA512(authKey, ed25519Pub) rather than
// a CA signature. Only the genuine server (which derived the same authKey) can produce it.
func (a *authVerifier) verify(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return errNotVerified
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errNotVerified
	}
	h := hmac.New(sha512.New, a.authKey)
	h.Write(pub)
	if hmac.Equal(h.Sum(nil), cert.Signature) {
		a.verified = true
		return nil
	}
	return errNotVerified
}

// Dialer returns a dial function (for valuerpc.NewFuncDialer) that dials network/addr
// and performs the REALITY client handshake.
func Dialer(network, addr string, cfg ClientConfig) func() (net.Conn, error) {
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
