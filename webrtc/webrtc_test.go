/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package webrtc_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs/webrtc"
)

// memBroker is an in-process rendezvous: it implements both the client Signaler
// and the server OfferSource, bridging one Dial to one Listener without a network
// signaling server. It stands in for a real broker in tests.
type memBroker struct {
	offers chan offerMsg
}

type offerMsg struct {
	sdp   string
	reply chan string
}

func newMemBroker() *memBroker { return &memBroker{offers: make(chan offerMsg)} }

func (b *memBroker) Exchange(ctx context.Context, offer string) (string, error) {
	reply := make(chan string, 1)
	select {
	case b.offers <- offerMsg{sdp: offer, reply: reply}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case ans := <-reply:
		return ans, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (b *memBroker) Next(ctx context.Context) (string, func(string) error, error) {
	select {
	case m := <-b.offers:
		return m.sdp, func(ans string) error { m.reply <- ans; return nil }, nil
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

func startEchoListener(t *testing.T, broker *memBroker) net.Listener {
	t.Helper()
	ln, err := webrtc.Listener(broker, webrtc.Config{})
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln
}

// TestWebRTC_RoundTrip: a Dial and a Listener connect over a real (loopback)
// WebRTC data channel through the in-process broker, and bytes echo back.
func TestWebRTC_RoundTrip(t *testing.T) {
	broker := newMemBroker()
	ln := startEchoListener(t, broker)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := webrtc.Dial(ctx, broker, webrtc.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}

// TestWebRTC_LargerPayload: a multi-KB message survives the data channel intact.
func TestWebRTC_LargerPayload(t *testing.T) {
	broker := newMemBroker()
	ln := startEchoListener(t, broker)
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := webrtc.Dial(ctx, broker, webrtc.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := bytes.Repeat([]byte("vrpc-over-webrtc;"), 256) // ~4 KB
	got := make([]byte, len(want))
	errc := make(chan error, 1)
	go func() {
		_, e := io.ReadFull(conn, got)
		errc <- e
	}()
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch (%d bytes)", len(got))
	}
}

// TestWebRTC_ListenerClose: Accept unblocks with an error after Close.
func TestWebRTC_ListenerClose(t *testing.T) {
	ln, err := webrtc.Listener(newMemBroker(), webrtc.Config{})
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	errc := make(chan error, 1)
	go func() { _, e := ln.Accept(); errc <- e }()
	time.Sleep(20 * time.Millisecond)
	ln.Close()
	select {
	case e := <-errc:
		if e == nil {
			t.Fatal("Accept returned nil error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}
