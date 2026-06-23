/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
	"golang.org/x/xerrors"
)

// failWriteConn is a net.Conn whose Write always fails, to drive the pacer's
// base-write error path.
type failWriteConn struct{ net.Conn }

func (failWriteConn) Write([]byte) (int, error) { return 0, xerrors.New("boom") }

// TestPaced_RoundTrip: a paced sender's cells, released by the background pacer and
// interleaved with cover, reconstruct the original stream at a normal receiver.
func TestPaced_RoundTrip(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		CellSize: 96,
		Paced:    &obfs.PacedConfig{Rate: 2000, Decay: 0.9, MinRate: 200},
	})
	b := obfs.Wrap(srv, obfs.Policy{CellSize: 96})
	defer a.Close()
	defer b.Close()

	for _, want := range [][]byte{
		[]byte("hi"),
		bytes.Repeat([]byte("A"), 500), // spans many cells -> exercises the queue
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
			t.Fatalf("paced round-trip mismatch: got %q want %q", got, want)
		}
	}
}

// TestPaced_Backpressure: with a tiny queue, a large write blocks until the pacer
// drains it, and the data still arrives intact and in order.
func TestPaced_Backpressure(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		CellSize: 64,
		Paced:    &obfs.PacedConfig{Rate: 8000, Queue: 4},
	})
	b := obfs.Wrap(srv, obfs.Policy{CellSize: 64})
	defer a.Close()
	defer b.Close()

	want := bytes.Repeat([]byte("regulator"), 400) // ~3.6 KB, many cells > queue depth
	got := make([]byte, len(want))
	errc := make(chan error, 1)
	go func() { _, e := io.ReadFull(b, got); errc <- e }()
	if _, err := a.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("backpressured payload mismatch")
	}
}

// TestPaced_EmitsCover: an idle paced connection still writes (cover) cells at the
// pacing rate, all of the configured cell size.
func TestPaced_EmitsCover(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{CellSize: 80, Paced: &obfs.PacedConfig{Rate: 200}})
	defer a.Close()

	time.Sleep(100 * time.Millisecond)
	ws := cap.snapshot()
	if len(ws) == 0 {
		t.Fatal("expected cover cells from the idle pacer, got none")
	}
	for _, w := range ws {
		if len(w) != 80 {
			t.Fatalf("paced cell size = %d, want 80", len(w))
		}
	}
}

// TestPaced_NoPadIdle: with NoPad, an idle paced connection writes nothing.
func TestPaced_NoPadIdle(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{CellSize: 80, Paced: &obfs.PacedConfig{Rate: 200, NoPad: true}})
	defer a.Close()

	time.Sleep(60 * time.Millisecond)
	if ws := cap.snapshot(); len(ws) != 0 {
		t.Fatalf("NoPad pacer wrote %d cells while idle, want 0", len(ws))
	}
}

// TestPaced_CloseFlushes: cells accepted by Write but still queued are flushed on
// Close rather than dropped.
func TestPaced_CloseFlushes(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		CellSize: 64,
		Paced:    &obfs.PacedConfig{Rate: 50, MinRate: 50}, // slow: cells linger in the queue
	})
	b := obfs.Wrap(srv, obfs.Policy{CellSize: 64})
	defer b.Close()

	const msg = "flush me on close"
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(b, buf); err != nil {
			got <- "ERR:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	if _, err := a.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	a.Close() // should flush the queued cells before closing the base

	select {
	case s := <-got:
		if s != msg {
			t.Fatalf("got %q want %q", s, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued data was not flushed on Close")
	}
}

// TestPaced_BaseWriteErrorUnblocks: when the base connection's writes fail, a Write
// back-pressured on a full queue must return an error rather than hang forever.
func TestPaced_BaseWriteErrorUnblocks(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	a := obfs.Wrap(failWriteConn{c1}, obfs.Policy{
		CellSize: 64,
		Paced:    &obfs.PacedConfig{Rate: 1000, Queue: 2},
	})
	defer a.Close()

	done := make(chan error, 1)
	go func() { _, err := a.Write(bytes.Repeat([]byte("x"), 4096)); done <- err }() // cells > queue
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error once the base writes fail")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Write hung after the pacer died on a base-write error")
	}
}

// TestPaced_Morph: pacing composes with morpher framing.
func TestPaced_Morph(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		SizeSampler: obfs.UniformSize(40, 120),
		Paced:       &obfs.PacedConfig{Rate: 3000},
	})
	b := obfs.Wrap(srv, obfs.Policy{SizeSampler: obfs.UniformSize(40, 120)})
	defer a.Close()
	defer b.Close()

	want := bytes.Repeat([]byte("paced-morph;"), 100)
	got := make([]byte, len(want))
	errc := make(chan error, 1)
	go func() { _, e := io.ReadFull(b, got); errc <- e }()
	if _, err := a.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("paced morph payload mismatch")
	}
}
