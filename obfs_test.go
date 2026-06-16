/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

func shapedPipe(p obfs.Policy) (net.Conn, net.Conn) {
	c1, c2 := net.Pipe()
	return obfs.Wrap(c1, p), obfs.Wrap(c2, p)
}

func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); ch <- c }()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	server = <-ch
	if server == nil {
		t.Fatal("accept failed")
	}
	return server, client
}

// captureConn records each underlying Write so tests can inspect on-wire framing.
type captureConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	c.mu.Lock()
	c.writes = append(c.writes, b)
	c.mu.Unlock()
	return len(p), nil
}

func (c *captureConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func (c *captureConn) reset() {
	c.mu.Lock()
	c.writes = nil
	c.mu.Unlock()
}

// TestShaper_RoundTrip: messages of assorted sizes (sub-cell, exactly maxData, and
// spanning many cells) survive the cell framing intact.
func TestShaper_RoundTrip(t *testing.T) {
	a, b := shapedPipe(obfs.Policy{CellSize: 64})
	defer a.Close()
	defer b.Close()

	for _, want := range [][]byte{
		[]byte("hi"),
		bytes.Repeat([]byte("q"), 1),
		bytes.Repeat([]byte("Z"), 62),  // exactly maxData (64 - 2 header)
		bytes.Repeat([]byte("A"), 200), // spans multiple cells
	} {
		errc := make(chan error, 1)
		go func(w []byte) { _, e := a.Write(w); errc <- e }(want)

		got := make([]byte, len(want))
		if _, err := io.ReadFull(b, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("write: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("round-trip mismatch: got %q want %q", got, want)
		}
	}
}

// TestShaper_UniformCellSize: every on-wire write is a whole number of cells,
// regardless of the message length — so no frame's size reveals an operation.
func TestShaper_UniformCellSize(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{CellSize: 100})

	for _, n := range []int{1, 50, 98, 99, 250} {
		cap.reset()
		if _, err := a.Write(bytes.Repeat([]byte("x"), n)); err != nil {
			t.Fatalf("write n=%d: %v", n, err)
		}
		for _, w := range cap.snapshot() {
			if len(w)%100 != 0 {
				t.Fatalf("n=%d: wire write of %d bytes is not a multiple of cell size 100", n, len(w))
			}
		}
	}
}

// TestShaper_CoverTraffic: an idle shaped connection still emits cells.
func TestShaper_CoverTraffic(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{CellSize: 80, CoverEvery: 15 * time.Millisecond})
	defer a.Close()

	time.Sleep(100 * time.Millisecond)
	ws := cap.snapshot()
	if len(ws) == 0 {
		t.Fatal("expected cover cells during idle, got none")
	}
	for _, w := range ws {
		if len(w) != 80 {
			t.Fatalf("cover cell size = %d, want 80", len(w))
		}
	}
}

// TestShaper_Disabled: a zero policy passes writes through unchanged.
func TestShaper_Disabled(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{}) // CellSize 0 -> shaping off

	if _, err := a.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	ws := cap.snapshot()
	if len(ws) != 1 || len(ws[0]) != 5 {
		t.Fatalf("disabled shaper must pass writes through unchanged, got %v", ws)
	}
}

// TestShaper_TCPWithCover: over a real (buffered) socket, cover cells flowing in
// the background are transparently discarded while a real message arrives intact.
func TestShaper_TCPWithCover(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{CellSize: 96, CoverEvery: 10 * time.Millisecond, Jitter: 2 * time.Millisecond})
	b := obfs.Wrap(srv, obfs.Policy{CellSize: 96})
	defer a.Close()
	defer b.Close()

	const msg = "the quick brown fox"
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(b, buf); err != nil {
			got <- "ERR:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	time.Sleep(35 * time.Millisecond) // let some cover cells flow first
	if _, err := a.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case s := <-got:
		if s != msg {
			t.Fatalf("got %q want %q", s, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the real message through cover traffic")
	}
}

func TestFills(t *testing.T) {
	buf := make([]byte, 256)

	obfs.ZeroFill(buf)
	for _, b := range buf {
		if b != 0 {
			t.Fatal("ZeroFill produced a non-zero byte")
		}
	}

	obfs.PrintableFill(buf)
	for _, b := range buf {
		if b < 0x20 || b > 0x7e {
			t.Fatalf("PrintableFill produced non-printable byte %#x", b)
		}
	}

	for i := range buf {
		buf[i] = 0
	}
	obfs.RandomFill(buf)
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("RandomFill left the buffer all zero")
	}
}

func BenchmarkShapedWriteRead(b *testing.B) {
	srv, cli := net.Pipe()
	a := obfs.Wrap(cli, obfs.Policy{CellSize: 512})
	r := obfs.Wrap(srv, obfs.Policy{CellSize: 512})
	defer a.Close()
	defer r.Close()

	msg := bytes.Repeat([]byte("x"), 300)
	buf := make([]byte, len(msg))
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			_, _ = a.Write(msg)
		}
	}()
	for i := 0; i < b.N; i++ {
		if _, err := io.ReadFull(r, buf); err != nil {
			b.Fatal(err)
		}
	}
}
