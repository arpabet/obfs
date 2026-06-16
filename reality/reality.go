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
// # SNI passthrough (a step toward REALITY)
//
// Set ServerConfig.ServerNames + Passthrough to additionally peek each ClientHello
// and raw-splice any connection whose SNI does not match (or is absent) to a real
// TLS upstream, so probes and IP-range scanners that use a different SNI terminate
// TLS against that upstream's genuine certificate rather than ours. This closes the
// biggest gap versus full REALITY without forging certificates; the full protocol's
// design across obfs/servion/value-rpc is written up in REALITY.md at the repo root.
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
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"go.arpabet.com/obfs/tlscamo"
)

var (
	errNotTLS   = errors.New("reality: not a TLS handshake record")
	errBadHello = errors.New("reality: malformed ClientHello")
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

	// ServerNames, when non-empty, enables SNI-passthrough: the listener peeks each
	// connection's TLS ClientHello and, if its SNI is NOT in this set, splices the raw
	// TCP stream to Passthrough untouched — so a probe or IP-range scanner using a
	// different (or no) SNI completes a genuine TLS handshake with the real upstream
	// and sees that upstream's real certificate, never ours. Connections whose SNI
	// matches proceed to the normal TLS-terminating token check below. This is a step
	// toward REALITY-style probe resistance (see REALITY.md) without TLS-stack surgery.
	ServerNames []string

	// Passthrough is the "host:port" of a real TLS upstream that connections failing
	// the ServerNames check are raw-spliced to. Empty closes such connections. Has no
	// effect unless ServerNames is set.
	Passthrough string

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
	_ = raw.SetDeadline(time.Now().Add(l.cfg.HandshakeTimeout))

	// SNI-passthrough stage: peek the ClientHello and, on a non-matching SNI, hand the
	// raw stream (ClientHello and all) to a real upstream so the prober terminates TLS
	// against that upstream's genuine certificate. A parse failure falls through to the
	// TLS-terminating path below rather than dropping a possibly-legitimate client.
	if len(l.cfg.ServerNames) > 0 {
		sni, prefix, perr := peekClientHelloSNI(raw)
		raw = &prefixConn{Conn: raw, prefix: prefix} // replay the bytes peek consumed
		if perr == nil && !l.serverNameAllowed(sni) {
			l.passthrough(raw)
			return
		}
	}

	conn := tls.Server(raw, l.cfg.TLSConfig)
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

// serverNameAllowed reports whether sni matches one of the configured ServerNames
// (case-insensitively, ignoring a trailing dot). An empty SNI never matches, so
// no-SNI scanners are passed through.
func (l *listener) serverNameAllowed(sni string) bool {
	if sni == "" {
		return false
	}
	sni = strings.TrimSuffix(sni, ".")
	for _, n := range l.cfg.ServerNames {
		if strings.EqualFold(sni, strings.TrimSuffix(n, ".")) {
			return true
		}
	}
	return false
}

// passthrough raw-splices client (its ClientHello already replayed by prefixConn) to
// the real Passthrough upstream, so the peer completes TLS against that upstream's
// genuine certificate. If Passthrough is unset the connection is simply closed.
func (l *listener) passthrough(client net.Conn) {
	defer client.Close()
	if l.cfg.Passthrough == "" {
		return
	}
	_ = client.SetDeadline(time.Time{}) // the splice manages its own lifetime
	dst, err := net.Dial("tcp", l.cfg.Passthrough)
	if err != nil {
		l.logf(err)
		return
	}
	defer dst.Close()
	var once sync.Once
	closeBoth := func() { once.Do(func() { client.Close(); dst.Close() }) }
	go func() { _, _ = io.Copy(dst, client); closeBoth() }()
	_, _ = io.Copy(client, dst)
	closeBoth()
}

// prefixConn replays prefix (the ClientHello bytes consumed while peeking the SNI)
// before reading from the underlying connection, so a downstream TLS server or
// upstream splice sees the original byte stream intact.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// peekClientHelloSNI reads exactly the first TLS record (a ClientHello) from r,
// returning its SNI and every byte consumed (for replay via prefixConn). It never
// reads past the ClientHello, so the live stream is left untouched.
func peekClientHelloSNI(r io.Reader) (string, []byte, error) {
	var buf bytes.Buffer
	sni, err := parseClientHelloSNI(io.TeeReader(r, &buf))
	return sni, buf.Bytes(), err
}

func parseClientHelloSNI(r io.Reader) (string, error) {
	hdr := make([]byte, 5) // TLS record header: type(1) + version(2) + length(2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 0x16 { // handshake
		return "", errNotTLS
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen < 4 || recLen > 1<<14 {
		return "", errBadHello
	}
	body := make([]byte, recLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", err
	}
	return sniFromClientHello(body)
}

// sniFromClientHello walks a ClientHello handshake message to its server_name
// extension. A well-formed ClientHello with no SNI returns ("", nil) -> passthrough.
func sniFromClientHello(b []byte) (string, error) {
	if len(b) < 4 || b[0] != 0x01 { // ClientHello handshake type
		return "", errBadHello
	}
	p := b[4:] // skip handshake header (type + 3-byte length)
	if len(p) < 34 {
		return "", errBadHello
	}
	p = p[34:] // legacy_version(2) + random(32)
	for _, field := range []int{1, 2, 1} {
		// session_id (1-byte len), cipher_suites (2-byte len), compression (1-byte len)
		if len(p) < field {
			return "", errBadHello
		}
		var n int
		if field == 1 {
			n = int(p[0])
		} else {
			n = int(p[0])<<8 | int(p[1])
		}
		p = p[field:]
		if len(p) < n {
			return "", errBadHello
		}
		p = p[n:]
	}
	if len(p) < 2 {
		return "", nil // no extensions -> no SNI
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return "", errBadHello
	}
	p = p[:extLen]
	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		l := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < l {
			return "", errBadHello
		}
		ext := p[:l]
		p = p[l:]
		if extType == 0x0000 { // server_name
			return sniFromExtension(ext)
		}
	}
	return "", nil // no server_name extension
}

func sniFromExtension(ext []byte) (string, error) {
	if len(ext) < 2 {
		return "", errBadHello
	}
	listLen := int(ext[0])<<8 | int(ext[1])
	e := ext[2:]
	if len(e) < listLen {
		return "", errBadHello
	}
	e = e[:listLen]
	for len(e) >= 3 {
		nameType := e[0]
		nl := int(e[1])<<8 | int(e[2])
		e = e[3:]
		if len(e) < nl {
			return "", errBadHello
		}
		if nameType == 0x00 { // host_name
			return string(e[:nl]), nil
		}
		e = e[nl:]
	}
	return "", nil
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
