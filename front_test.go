/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"io"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

// TestFront_EmitsBudgetedCover: with FRONT enabled, an idle connection emits between
// 1 and MaxCount dummy cells (all valid cells), concentrated near connection start.
func TestFront_EmitsBudgetedCover(t *testing.T) {
	c1, _ := net.Pipe()
	defer c1.Close()
	cap := &captureConn{Conn: c1}
	a := obfs.Wrap(cap, obfs.Policy{
		CellSize: 80,
		Front:    &obfs.FrontConfig{Window: 60 * time.Millisecond, MaxCount: 5},
	})
	defer a.Close()

	time.Sleep(200 * time.Millisecond) // well past the window
	ws := cap.snapshot()
	if len(ws) < 1 || len(ws) > 5 {
		t.Fatalf("FRONT emitted %d cover cells, want within [1,5]", len(ws))
	}
	for _, w := range ws {
		if len(w) != 80 {
			t.Fatalf("cover cell size = %d, want 80", len(w))
		}
	}
}

// TestFront_RoundTrip: FRONT cover cells interleave with a real message over a real
// socket without corrupting it (cover cells are discarded on read).
func TestFront_RoundTrip(t *testing.T) {
	srv, cli := tcpPair(t)
	a := obfs.Wrap(cli, obfs.Policy{
		CellSize: 96,
		Front:    &obfs.FrontConfig{Window: 30 * time.Millisecond, MaxCount: 8},
	})
	b := obfs.Wrap(srv, obfs.Policy{CellSize: 96})
	defer a.Close()
	defer b.Close()

	const msg = "front-padded payload"
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(b, buf); err != nil {
			got <- "ERR:" + err.Error()
			return
		}
		got <- string(buf)
	}()

	time.Sleep(10 * time.Millisecond) // let some FRONT cover flow first
	if _, err := a.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case s := <-got:
		if s != msg {
			t.Fatalf("got %q want %q", s, msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the real message through FRONT cover")
	}
}
