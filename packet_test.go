/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

var pktKey = []byte("packet-obfuscation-preshared-key")

func udpConn(t *testing.T) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestPacket_RoundTrip: obfuscated datagrams of assorted sizes (including a
// zero-length one) reconstruct exactly through two wrapped PacketConns.
func TestPacket_RoundTrip(t *testing.T) {
	a := obfs.WrapPacket(udpConn(t), obfs.PacketPolicy{Key: pktKey})
	b := obfs.WrapPacket(udpConn(t), obfs.PacketPolicy{Key: pktKey})

	for _, want := range [][]byte{
		{},
		[]byte("x"),
		[]byte("the quick brown fox"),
		bytes.Repeat([]byte("Z"), 1400),
	} {
		if _, err := a.WriteTo(want, b.LocalAddr()); err != nil {
			t.Fatalf("write %d: %v", len(want), err)
		}
		buf := make([]byte, 4096)
		_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := b.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: %v", len(want), err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("round-trip mismatch: got %q want %q", buf[:n], want)
		}
	}
}

// TestPacket_ObfuscatesAndSalts: on the wire the payload is neither plaintext nor
// stable — two identical writes differ (per-datagram salt).
func TestPacket_ObfuscatesAndSalts(t *testing.T) {
	plain := udpConn(t)
	a := obfs.WrapPacket(udpConn(t), obfs.PacketPolicy{Key: pktKey})

	read := func() []byte {
		buf := make([]byte, 256)
		_ = plain.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := plain.ReadFrom(buf)
		if err != nil {
			t.Fatalf("plain read: %v", err)
		}
		return append([]byte(nil), buf[:n]...)
	}

	if _, err := a.WriteTo([]byte("AAAA"), plain.LocalAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}
	w1 := read()
	if len(w1) != 8+2+4 { // salt + length prefix + data, no padding
		t.Fatalf("wire size = %d, want 14", len(w1))
	}
	if bytes.Contains(w1, []byte("AAAA")) {
		t.Fatal("plaintext payload visible on the wire")
	}

	if _, err := a.WriteTo([]byte("AAAA"), plain.LocalAddr()); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	if w2 := read(); bytes.Equal(w1, w2) {
		t.Fatal("identical payloads produced identical wire bytes (salt not applied)")
	}
}

// TestPacket_Padding: a Pad sampler grows the on-wire datagram to its target size.
func TestPacket_Padding(t *testing.T) {
	plain := udpConn(t)
	a := obfs.WrapPacket(udpConn(t), obfs.PacketPolicy{Key: pktKey, Pad: obfs.UniformSize(1200, 1200)})

	if _, err := a.WriteTo([]byte("hi"), plain.LocalAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4096)
	_ = plain.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := plain.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 8+1200 { // salt + padded frame
		t.Fatalf("padded wire size = %d, want %d", n, 8+1200)
	}
}

// TestPacket_Disabled: an empty Key returns the base PacketConn unchanged.
func TestPacket_Disabled(t *testing.T) {
	base := udpConn(t)
	if got := obfs.WrapPacket(base, obfs.PacketPolicy{}); got != base {
		t.Fatal("empty-key WrapPacket must pass the base conn through unchanged")
	}
}

// TestPacket_ShortDatagram: a datagram too short to hold the framing is rejected
// rather than panicking.
func TestPacket_ShortDatagram(t *testing.T) {
	recv := obfs.WrapPacket(udpConn(t), obfs.PacketPolicy{Key: pktKey})
	sender := udpConn(t)

	if _, err := sender.WriteTo([]byte{1, 2, 3}, recv.LocalAddr()); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	_ = recv.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := recv.ReadFrom(buf); err == nil {
		t.Fatal("expected an error reading a too-short datagram")
	}
}
