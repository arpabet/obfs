/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

func morphPipe(p obfs.Policy) (net.Conn, net.Conn) {
	c1, c2 := net.Pipe()
	return obfs.Wrap(c1, p), obfs.Wrap(c2, p)
}

// parseMorphCells splits a captured morpher wire buffer into per-cell on-wire sizes
// (2-byte total-length prefix + that many bytes).
func parseMorphCells(t *testing.T, buf []byte) []int {
	t.Helper()
	var sizes []int
	for len(buf) > 0 {
		if len(buf) < 2 {
			t.Fatalf("dangling %d bytes with no cell header", len(buf))
		}
		n := int(binary.BigEndian.Uint16(buf[0:2]))
		wire := 2 + n
		if len(buf) < wire {
			t.Fatalf("short cell: need %d, have %d", wire, len(buf))
		}
		sizes = append(sizes, wire)
		buf = buf[wire:]
	}
	return sizes
}

// TestMorph_RoundTrip: variable-size cells reconstruct the original byte stream
// across sub-cell, multi-cell, and many-cell messages.
func TestMorph_RoundTrip(t *testing.T) {
	a, b := morphPipe(obfs.Policy{SizeSampler: obfs.UniformSize(16, 48)})
	defer a.Close()
	defer b.Close()

	for _, want := range [][]byte{
		[]byte("x"),
		[]byte("hello world"),
		bytes.Repeat([]byte("A"), 500),
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
			t.Fatalf("mismatch: got %q want %q", got, want)
		}
	}
}

// TestMorph_VariableCellSizes: on-wire cells vary in size and stay within the
// sampled range — so no fixed cell size is itself a signature.
func TestMorph_VariableCellSizes(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{SizeSampler: obfs.UniformSize(20, 80)})

	if _, err := a.Write(bytes.Repeat([]byte("x"), 2000)); err != nil {
		t.Fatalf("write: %v", err)
	}
	sizes := parseMorphCells(t, cap.snapshot()[0])
	if len(sizes) < 2 {
		t.Fatalf("expected several cells, got %d", len(sizes))
	}
	distinct := map[int]bool{}
	for _, s := range sizes {
		if s < 20 || s > 80 {
			t.Fatalf("cell wire size %d outside sampled range [20,80]", s)
		}
		distinct[s] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("expected varied cell sizes, all were %d", sizes[0])
	}
}

// TestMorph_SampledSize: an empirical distribution only produces its own sizes.
func TestMorph_SampledSize(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{SizeSampler: obfs.SampledSize(map[int]float64{40: 1, 100: 3})})

	if _, err := a.Write(bytes.Repeat([]byte("y"), 1500)); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, s := range parseMorphCells(t, cap.snapshot()[0]) {
		if s != 40 && s != 100 {
			t.Fatalf("cell size %d not from the sampled set {40,100}", s)
		}
	}
}

// TestMorph_CoverTraffic: idle cover cells are emitted with sampled sizes.
func TestMorph_CoverTraffic(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{
		SizeSampler: obfs.UniformSize(30, 60),
		CoverEvery:  15 * time.Millisecond,
	})
	defer a.Close()

	time.Sleep(100 * time.Millisecond)
	ws := cap.snapshot()
	if len(ws) == 0 {
		t.Fatal("expected cover cells during idle, got none")
	}
	for _, w := range ws {
		for _, s := range parseMorphCells(t, w) {
			if s < 30 || s > 60 {
				t.Fatalf("cover cell size %d outside [30,60]", s)
			}
		}
	}
}

// TestMorph_TCPWithCover: over a real socket, a morphed message survives intact
// through background cover traffic and sampled flush delays.
func TestMorph_TCPWithCover(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		SizeSampler:  obfs.UniformSize(40, 120),
		DelaySampler: obfs.PoissonDelay(time.Millisecond),
		CoverEvery:   10 * time.Millisecond,
	})
	b := obfs.Wrap(srv, obfs.Policy{SizeSampler: obfs.UniformSize(40, 120)})
	defer a.Close()
	defer b.Close()

	const msg = "morphed payload survives cover traffic"
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(b, buf); err != nil {
			got <- "ERR:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	time.Sleep(35 * time.Millisecond)
	if _, err := a.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case s := <-got:
		if s != msg {
			t.Fatalf("got %q want %q", s, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the morphed message")
	}
}

func TestSamplers(t *testing.T) {
	u := obfs.UniformSize(10, 20)
	for i := 0; i < 200; i++ {
		if v := u(); v < 10 || v > 20 {
			t.Fatalf("UniformSize out of range: %d", v)
		}
	}

	s := obfs.SampledSize(map[int]float64{64: 1, 256: 1})
	for i := 0; i < 200; i++ {
		if v := s(); v != 64 && v != 256 {
			t.Fatalf("SampledSize off-distribution: %d", v)
		}
	}

	d := obfs.PoissonDelay(time.Millisecond)
	var sum time.Duration
	const n = 4000
	for i := 0; i < n; i++ {
		v := d()
		if v < 0 {
			t.Fatalf("PoissonDelay negative: %v", v)
		}
		sum += v
	}
	if mean := sum / n; mean < 300*time.Microsecond || mean > 3*time.Millisecond {
		t.Fatalf("PoissonDelay mean %v far from the 1ms target", mean)
	}
}
