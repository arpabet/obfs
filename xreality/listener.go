/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"
)

// ServerConfig configures the REALITY listener.
type ServerConfig struct {
	// PrivateKey is the server's static X25519 private key (its public key is given to
	// clients as ClientConfig.ServerPublicKey).
	PrivateKey *ecdh.PrivateKey

	// ShortIDs are the accepted client cohort identifiers (each <= 8 bytes).
	ShortIDs [][]byte

	// TLSConfig carries the certificate presented to authenticated clients. A
	// self-signed certificate for the borrowed ServerName is fine: in TLS 1.3 the
	// certificate is encrypted, and the client verifies the server via the
	// channel-bound HMAC rather than a CA chain.
	TLSConfig *tls.Config

	// Dest is the "host:port" of the real borrowed site that unauthenticated
	// connections (probes, scanners) are raw-spliced to, so they complete a genuine
	// TLS handshake against it and see its real certificate. Empty closes them.
	Dest string

	// TimeSkew bounds the SessionID timestamp's distance from now (replay window);
	// 0 disables the check.
	TimeSkew time.Duration

	// HandshakeTimeout bounds the peek + handshake + channel auth; 0 uses the default.
	HandshakeTimeout time.Duration

	// OnError, if set, receives non-fatal passthrough/auth errors (for logging).
	OnError func(error)
}

func (c ServerConfig) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout <= 0 {
		return DefaultHandshakeTimeout
	}
	return c.HandshakeTimeout
}

// Listener wraps base so Accept returns only authenticated REALITY tunnels;
// unauthenticated connections are raw-spliced to Dest in the background.
func Listener(base net.Listener, cfg ServerConfig) net.Listener {
	l := &listener{base: base, cfg: cfg, accepted: make(chan acceptResult), done: make(chan struct{})}
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
		go l.handle(raw)
	}
}

func (l *listener) handle(raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(l.cfg.handshakeTimeout()))

	record, perr := peekRecord(raw)
	pc := &prefixConn{Conn: raw, prefix: record} // replay the peeked ClientHello downstream
	if perr != nil {
		l.passthrough(pc)
		return
	}
	d, err := Authenticate(l.cfg.PrivateKey, record, l.acceptShortID, l.cfg.TimeSkew)
	if err != nil || !d.Authenticated {
		l.passthrough(pc)
		return
	}

	conn := tls.Server(pc, l.cfg.TLSConfig)
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return
	}
	if err := l.serverChannelAuth(conn, d.AuthKey); err != nil {
		l.logf(err)
		conn.Close()
		return
	}
	_ = raw.SetDeadline(time.Time{})

	select {
	case l.accepted <- acceptResult{conn, nil}:
	case <-l.done:
		conn.Close()
	}
}

// serverChannelAuth sends the server's channel-bound proof and verifies the client's,
// completing mutual authentication bound to this TLS channel.
func (l *listener) serverChannelAuth(conn *tls.Conn, authKey []byte) error {
	cs := conn.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(ekmLabel, ekmContext, 32)
	if err != nil {
		return err
	}
	if _, err := conn.Write(proof(authKey, serverTag, ekm)); err != nil {
		return err
	}
	got := make([]byte, proofLen)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !hmac.Equal(got, proof(authKey, clientTag, ekm)) {
		return errServerAuth
	}
	return nil
}

func (l *listener) acceptShortID(shortID []byte) bool {
	for _, s := range l.cfg.ShortIDs {
		padded := make([]byte, ShortIDLen)
		copy(padded, s)
		if hmac.Equal(padded, shortID) {
			return true
		}
	}
	return false
}

// passthrough raw-splices client (its peeked ClientHello already replayed) to Dest,
// so an unauthenticated peer terminates TLS against the real borrowed site.
func (l *listener) passthrough(client net.Conn) {
	defer client.Close()
	if l.cfg.Dest == "" {
		return
	}
	_ = client.SetDeadline(time.Time{})
	dst, err := net.Dial("tcp", l.cfg.Dest)
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

// prefixConn replays prefix (the peeked ClientHello bytes) before reading from the
// underlying connection.
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

// peekRecord reads exactly one TLS record (the ClientHello) and returns every byte
// consumed, so a prefixConn can replay it whether the connection is terminated
// locally or spliced to Dest. It never reads past the record.
func peekRecord(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	tee := io.TeeReader(r, &buf)
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(tee, hdr); err != nil {
		return buf.Bytes(), err
	}
	if hdr[0] != 0x16 { // handshake
		return buf.Bytes(), ErrNotTLS
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n < 4 || n > 1<<14 {
		return buf.Bytes(), ErrBadHello
	}
	if _, err := io.ReadFull(tee, make([]byte, n)); err != nil {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}
