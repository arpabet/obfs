/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import (
	"crypto/hmac"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/xerrors"
)

// DefaultFingerprint is the browser ClientHello mimicked when none is set.
var DefaultFingerprint = utls.HelloChrome_Auto

// DefaultHandshakeTimeout bounds the TLS handshake plus the channel-bound auth.
const DefaultHandshakeTimeout = 15 * time.Second

const (
	ekmLabel  = "EXPORTER-obfs-xreality"
	proofLen  = 64 // HMAC-SHA512
	serverTag = "S"
	clientTag = "C"
)

var ekmContext = []byte("v1")

var (
	errNoX25519   = xerrors.New("xreality: fingerprint has no usable X25519 key share")
	errServerAuth = xerrors.New("xreality: server channel authentication failed")
)

// ClientConfig configures the REALITY client dialer.
type ClientConfig struct {
	// ServerPublicKey is the server's static X25519 public key (32 bytes).
	ServerPublicKey []byte

	// ShortID identifies the client cohort; must be one the server accepts (<= 8 bytes).
	ShortID []byte

	// ServerName is the borrowed SNI presented in the ClientHello.
	ServerName string

	// Fingerprint selects the mimicked browser ClientHello; zero value uses Chrome.
	Fingerprint utls.ClientHelloID

	// NextProtos is the offered ALPN; empty defaults to {"h2","http/1.1"}.
	NextProtos []string

	// HandshakeTimeout bounds the handshake + channel auth; 0 uses DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
}

// Client performs the REALITY client handshake over raw and returns the verified
// tunnel. It mimics a browser ClientHello (uTLS), reuses that hello's X25519 key
// share as the REALITY ephemeral, smuggles the sealed auth token in the SessionID,
// and — because the server presents a forged/self-signed certificate — authenticates
// the server out of band via a channel-bound HMAC keyed by the shared auth key
// instead of a CA chain. A MITM that terminated TLS would derive a different channel
// secret and cannot know the auth key, so the check fails closed.
func Client(raw net.Conn, cfg ClientConfig) (net.Conn, error) {
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))

	id := cfg.Fingerprint
	if id.Client == "" {
		id = DefaultFingerprint
	}
	alpn := cfg.NextProtos
	if len(alpn) == 0 {
		alpn = []string{"h2", "http/1.1"}
	}

	uc := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: true, // server identity is proven by the channel-bound HMAC below
		NextProtos:         alpn,
	}
	u := utls.UClient(raw, uc, id)
	if err := u.BuildHandshakeState(); err != nil {
		return nil, err
	}

	ks := u.HandshakeState.State13.KeyShareKeys
	if ks == nil || ks.Ecdhe == nil {
		return nil, errNoX25519
	}
	ephemeral := ks.Ecdhe
	ephPub := ephemeral.PublicKey().Bytes()
	if !helloHasX25519Share(u.HandshakeState.Hello.KeyShares, ephPub) {
		return nil, errNoX25519
	}

	sid, authKey, err := ClientSessionID(cfg.ServerPublicKey, ephemeral, u.HandshakeState.Hello.Random, cfg.ShortID)
	if err != nil {
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = sid
	if err := u.MarshalClientHello(); err != nil {
		return nil, err
	}
	if err := u.Handshake(); err != nil {
		return nil, err
	}
	// The browser preset's renegotiation_info extension leaves config.Renegotiation
	// non-Never, which disables ExportKeyingMaterial. The handshake (and its sent
	// extension bytes) are done, so clearing it now only re-enables the exporter the
	// channel-bound auth needs — the on-wire fingerprint is unaffected.
	uc.Renegotiation = utls.RenegotiateNever
	if err := clientChannelAuth(u, authKey); err != nil {
		u.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	return u, nil
}

// clientChannelAuth reads and verifies the server's channel-bound proof, then sends
// the client's, binding the shared auth key to this specific TLS channel.
func clientChannelAuth(u *utls.UConn, authKey []byte) error {
	cs := u.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(ekmLabel, ekmContext, 32)
	if err != nil {
		return err
	}
	got := make([]byte, proofLen)
	if _, err := io.ReadFull(u, got); err != nil {
		return err
	}
	if !hmac.Equal(got, proof(authKey, serverTag, ekm)) {
		return errServerAuth
	}
	_, err = u.Write(proof(authKey, clientTag, ekm))
	return err
}

// proof binds the auth key to a channel-keying-material value with a side tag, so the
// client and server proofs differ and neither can be replayed as the other.
func proof(authKey []byte, tag string, ekm []byte) []byte {
	return CertHMAC(authKey, append([]byte(tag), ekm...))
}

func helloHasX25519Share(shares []utls.KeyShare, pub []byte) bool {
	for _, ks := range shares {
		if uint16(ks.Group) == groupX25519 && hmac.Equal(ks.Data, pub) {
			return true
		}
	}
	return false
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
