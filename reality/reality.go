/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package reality provides Trojan-style active-probe defense for a TLS service.
//
// A censor often confirms a suspected proxy by *actively probing* it — connecting
// and seeing whether it behaves like the website it claims to be. reality defeats
// that: the server terminates TLS with a real certificate for the domain it
// fronts, then expects a pre-shared token as the first bytes inside the tunnel.
// Authenticated clients get the tunnel; everyone else — active probes, scanners,
// or a real browser that wanders in — is transparently **reverse-proxied to a real
// fallback site**, so the prober sees a genuine website and learns nothing.
//
// # Scope (Trojan-grade, not full REALITY)
//
// This is the Trojan model: the server presents its OWN certificate for a domain
// you control. It is NOT the full Xray REALITY protocol (which borrows an
// unrelated high-reputation site's certificate and embeds an X25519 key share in
// the ClientHello); that needs TLS-stack surgery and is out of scope here. Trojan
// still gives strong active-probe resistance when paired with a credible fronted
// domain + a plausible fallback.
//
// # Layering and pairing
//
// The client uses go.arpabet.com/obfs/tlscamo so its ClientHello mimics a browser.
// reality is the OUTERMOST layer (wrap raw TCP); put any obfs traffic shaping
// inside the tunnel. Leave the server TLSConfig's ALPN empty (or http/1.1) so an
// unauthenticated probe and the HTTP fallback negotiate the same protocol. The
// Fallback should be a plain HTTP origin you run (e.g. servion's HTTP server).
//
// # value-rpc integration
//
//	server: valuerpc.NewAcceptListener over reality.Listener(base, cfg).Accept
//	client: valuerpc.NewFuncDialer(reality.Dialer(network, addr, cfg))
//
// # Caveats
//
// reality provides camouflage plus standard TLS confidentiality/authentication —
// not anonymity. The Token must be non-empty (>= 16 bytes recommended) and kept
// secret. Dual-use: do not use it to evade authorized monitoring or unlawfully.
package reality

import (
	"crypto/subtle"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"go.arpabet.com/obfs/tlscamo"
)

// DefaultHandshakeTimeout bounds the TLS handshake plus the token read, so a
// stalled prober cannot hold a connection open indefinitely before it is
// classified and proxied.
const DefaultHandshakeTimeout = 15 * time.Second

// ServerConfig configures the probe-defending listener.
type ServerConfig struct {
	// TLSConfig must carry the server certificate for the fronted domain. Leave
	// NextProtos empty (or "http/1.1") so probes and the HTTP fallback agree.
	TLSConfig *tls.Config

	// Token is the pre-shared secret a real client sends as its first bytes inside
	// the tunnel. Must be non-empty; >= 16 random bytes recommended.
	Token []byte

	// Fallback is the "host:port" of a real (plaintext HTTP) site that
	// unauthenticated connections are reverse-proxied to. If empty, such
	// connections are simply closed (weaker camouflage).
	Fallback string

	// HandshakeTimeout bounds the handshake + token read; 0 uses DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration

	// OnError, if set, receives non-fatal fallback/proxy errors (for logging).
	OnError func(error)
}

// ClientConfig configures the dialer.
type ClientConfig struct {
	// TLS controls the mimicked TLS client (fingerprint, ServerName, RootCAs, ALPN).
	TLS tlscamo.Config

	// Token must match the server's.
	Token []byte
}

// Dialer returns a dial function (for valuerpc.NewFuncDialer) that dials
// network/addr, performs a browser-mimicked TLS handshake, sends the token, and
// returns the tunnel.
func Dialer(network, addr string, cfg ClientConfig) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		raw, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		conn, err := tlscamo.Client(raw, cfg.TLS)
		if err != nil {
			raw.Close()
			return nil, err
		}
		if _, err := conn.Write(cfg.Token); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// Listener wraps base so that Accept returns only authenticated tunnels;
// unauthenticated connections are reverse-proxied to Fallback in the background.
func Listener(base net.Listener, cfg ServerConfig) net.Listener {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	l := &listener{
		base:     base,
		cfg:      cfg,
		accepted: make(chan acceptResult),
		done:     make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

type acceptResult struct {
	c   net.Conn
	err error
}

type listener struct {
	base     net.Listener
	cfg      ServerConfig
	accepted chan acceptResult
	done     chan struct{}
	once     sync.Once
}

func (l *listener) acceptLoop() {
	for {
		raw, err := l.base.Accept()
		if err != nil {
			select {
			case l.accepted <- acceptResult{nil, err}:
			case <-l.done:
			}
			return
		}
		go l.handle(raw) // per-conn, so a slow probe never blocks other accepts
	}
}

func (l *listener) handle(raw net.Conn) {
	conn := tls.Server(raw, l.cfg.TLSConfig)
	_ = raw.SetDeadline(time.Now().Add(l.cfg.HandshakeTimeout))
	if err := conn.Handshake(); err != nil {
		raw.Close() // not even valid TLS; nothing to reverse-proxy
		return
	}

	tok := make([]byte, len(l.cfg.Token))
	n, rerr := io.ReadFull(conn, tok)
	_ = raw.SetDeadline(time.Time{}) // clear; the tunnel/proxy manages its own deadlines

	authed := len(l.cfg.Token) > 0 && rerr == nil &&
		subtle.ConstantTimeCompare(tok, l.cfg.Token) == 1
	if authed {
		select {
		case l.accepted <- acceptResult{conn, nil}:
		case <-l.done:
			conn.Close()
		}
		return
	}
	l.reverseProxy(conn, tok[:n])
}

// reverseProxy makes an unauthenticated connection indistinguishable from a real
// reverse proxy to Fallback: it replays the bytes already consumed, then splices
// both directions. The first direction to finish closes both ends.
func (l *listener) reverseProxy(client net.Conn, consumed []byte) {
	defer client.Close()
	if l.cfg.Fallback == "" {
		return
	}
	dst, err := net.Dial("tcp", l.cfg.Fallback)
	if err != nil {
		l.logf(err)
		return
	}
	defer dst.Close()
	if len(consumed) > 0 {
		if _, err := dst.Write(consumed); err != nil {
			l.logf(err)
			return
		}
	}
	var once sync.Once
	closeBoth := func() { once.Do(func() { client.Close(); dst.Close() }) }
	go func() { _, _ = io.Copy(dst, client); closeBoth() }()
	_, _ = io.Copy(client, dst)
	closeBoth()
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case r := <-l.accepted:
		return r.c, r.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.base.Close()
}

func (l *listener) Addr() net.Addr { return l.base.Addr() }

func (l *listener) logf(err error) {
	if l.cfg.OnError != nil && err != nil {
		l.cfg.OnError(err)
	}
}
