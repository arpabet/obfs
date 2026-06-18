/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package webrtc carries a connection over a WebRTC data channel, so the traffic
// looks like a WebRTC call (DTLS/SRTP-style over UDP) — the same camouflage Tor's
// Snowflake uses, and expensive for a censor to block wholesale. A detached pion
// data channel is exposed as a net.Conn.
//
// It is a separate module so the heavy pion dependency tree stays out of the
// zero-dependency go.arpabet.com/obfs core, and it produces a net.Conn, so it
// composes with value-rpc, gRPC, or net/http.
//
// # Signaling is pluggable (no broker here)
//
// WebRTC needs an out-of-band exchange of SDP offer/answer before the data channel
// forms. This package does NOT implement that rendezvous — that broker is a
// control-plane concern (servion, or your own). The client provides a Signaler
// (send my offer, get the answer) and the server provides an OfferSource (a stream
// of inbound offers, each with a reply callback). Non-trickle ICE is used: all
// candidates are gathered into a single self-contained SDP, so signaling is one
// request/response.
//
// # value-rpc integration
//
//	client: valuerpc.NewFuncDialer(func(ctx context.Context) (io.ReadWriteCloser, error) {
//	            return webrtc.Dial(ctx, signaler, cfg)
//	        }, writeTimeout)
//	server: valuerpc.NewAcceptListener over webrtc.Listener(offerSource, cfg).Accept
//
// # Caveats
//
// WebRTC carries confidentiality (DTLS) but this is camouflage, not anonymity. NAT
// traversal needs STUN/TURN (Config.ICEServers) off-LAN. The broker is the part a
// censor will attack — make rendezvous resilient (domain fronting, ephemeral
// proxies) at that layer. Dual-use: do not use to evade authorized monitoring.
package webrtc

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/pion/datachannel"
	pion "github.com/pion/webrtc/v4"
)

const defaultConnectTimeout = 20 * time.Second

// ICEServer re-exports pion's type so callers configure STUN/TURN without
// importing pion directly.
type ICEServer = pion.ICEServer

// Config configures the WebRTC transport.
type Config struct {
	// ICEServers lists STUN/TURN servers for NAT traversal. Empty uses only host
	// candidates (fine for LAN/loopback).
	ICEServers []ICEServer

	// ConnectTimeout bounds establishing one connection (handshake + data channel
	// open); 0 uses 20s.
	ConnectTimeout time.Duration
}

// Signaler is the client's out-of-band channel to the broker: it sends the local
// offer SDP and returns the server's answer SDP. obfs/webrtc does not implement it.
type Signaler interface {
	Exchange(ctx context.Context, offerSDP string) (answerSDP string, err error)
}

// OfferSource is the server's stream of inbound offers from the broker. Next blocks
// for the next client offer and returns a reply callback to send the answer back to
// that client; it returns a non-nil error when the source is closed or failed.
type OfferSource interface {
	Next(ctx context.Context) (offerSDP string, reply func(answerSDP string) error, err error)
}

func newAPI() *pion.API {
	se := pion.SettingEngine{}
	se.DetachDataChannels() // expose the data channel as an io.ReadWriteCloser
	return pion.NewAPI(pion.WithSettingEngine(se))
}

// Dial establishes a WebRTC peer connection through sig, opens a data channel, and
// returns it as a net.Conn once open.
func Dial(ctx context.Context, sig Signaler, cfg Config) (net.Conn, error) {
	timeout := cfg.ConnectTimeout
	if timeout <= 0 {
		timeout = defaultConnectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pc, err := newAPI().NewPeerConnection(pion.Configuration{ICEServers: cfg.ICEServers})
	if err != nil {
		return nil, err
	}

	connCh := make(chan net.Conn, 1)
	dc, err := pc.CreateDataChannel("obfs", nil) // ordered + reliable by default
	if err != nil {
		pc.Close()
		return nil, err
	}
	dc.OnOpen(func() {
		raw, derr := dc.Detach()
		if derr != nil {
			pc.Close()
			return
		}
		connCh <- newConn(pc, raw)
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	gathered := pion.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, err
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		pc.Close()
		return nil, ctx.Err()
	}

	offerSDP, err := encodeSDP(pc.LocalDescription())
	if err != nil {
		pc.Close()
		return nil, err
	}
	answerSDP, err := sig.Exchange(ctx, offerSDP)
	if err != nil {
		pc.Close()
		return nil, err
	}
	answer, err := decodeSDP(answerSDP)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetRemoteDescription(answer); err != nil {
		pc.Close()
		return nil, err
	}

	select {
	case c := <-connCh:
		return c, nil
	case <-ctx.Done():
		pc.Close()
		return nil, ctx.Err()
	}
}

// Listener answers offers from src and yields the resulting data-channel
// connections through Accept.
func Listener(src OfferSource, cfg Config) (net.Listener, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = defaultConnectTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{
		src:    src,
		api:    newAPI(),
		cfg:    cfg,
		conns:  make(chan acceptResult),
		ctx:    ctx,
		cancel: cancel,
	}
	go l.acceptLoop()
	return l, nil
}

type acceptResult struct {
	c   net.Conn
	err error
}

type listener struct {
	src    OfferSource
	api    *pion.API
	cfg    Config
	conns  chan acceptResult
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (l *listener) acceptLoop() {
	for {
		offer, reply, err := l.src.Next(l.ctx)
		if err != nil {
			select {
			case l.conns <- acceptResult{nil, err}:
			case <-l.ctx.Done():
			}
			return
		}
		go l.answer(offer, reply)
	}
}

func (l *listener) answer(offerSDP string, reply func(string) error) {
	pc, err := l.api.NewPeerConnection(pion.Configuration{ICEServers: l.cfg.ICEServers})
	if err != nil {
		return
	}

	opened := make(chan net.Conn, 1)
	pc.OnDataChannel(func(dc *pion.DataChannel) {
		dc.OnOpen(func() {
			raw, derr := dc.Detach()
			if derr != nil {
				pc.Close()
				return
			}
			opened <- newConn(pc, raw)
		})
	})

	offer, err := decodeSDP(offerSDP)
	if err != nil {
		pc.Close()
		return
	}
	if err := pc.SetRemoteDescription(offer); err != nil {
		pc.Close()
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		return
	}
	gathered := pion.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		return
	}
	select {
	case <-gathered:
	case <-l.ctx.Done():
		pc.Close()
		return
	}
	answerSDP, err := encodeSDP(pc.LocalDescription())
	if err != nil {
		pc.Close()
		return
	}
	if err := reply(answerSDP); err != nil {
		pc.Close()
		return
	}

	timer := time.NewTimer(l.cfg.ConnectTimeout)
	defer timer.Stop()
	select {
	case c := <-opened:
		select {
		case l.conns <- acceptResult{c, nil}:
		case <-l.ctx.Done():
			c.Close()
		}
	case <-timer.C:
		pc.Close()
	case <-l.ctx.Done():
		pc.Close()
	}
}

func (l *listener) Accept() (net.Conn, error) {
	select {
	case r := <-l.conns:
		return r.c, r.err
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *listener) Close() error {
	l.once.Do(func() { l.cancel() })
	return nil
}

func (l *listener) Addr() net.Addr { return dcAddr{} }

func encodeSDP(sd *pion.SessionDescription) (string, error) {
	b, err := json.Marshal(sd)
	return string(b), err
}

func decodeSDP(s string) (pion.SessionDescription, error) {
	var sd pion.SessionDescription
	err := json.Unmarshal([]byte(s), &sd)
	return sd, err
}

// conn adapts a detached pion data channel (plus its peer connection, for cleanup)
// to net.Conn.
type conn struct {
	pc  *pion.PeerConnection
	raw datachannel.ReadWriteCloser
}

func newConn(pc *pion.PeerConnection, raw datachannel.ReadWriteCloser) *conn {
	return &conn{pc: pc, raw: raw}
}

func (c *conn) Read(p []byte) (int, error)  { return c.raw.Read(p) }
func (c *conn) Write(p []byte) (int, error) { return c.raw.Write(p) }

func (c *conn) Close() error {
	err := c.raw.Close()
	_ = c.pc.Close()
	return err
}

func (c *conn) LocalAddr() net.Addr  { return dcAddr{} }
func (c *conn) RemoteAddr() net.Addr { return dcAddr{} }

func (c *conn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	if d, ok := c.raw.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.raw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

type dcAddr struct{}

func (dcAddr) Network() string { return "webrtc" }
func (dcAddr) String() string  { return "webrtc-datachannel" }
