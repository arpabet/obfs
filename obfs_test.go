/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

// The stub must expose the full obfs API and be a pass-through (no shaping).

func TestWrapPassthrough(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	if got := obfs.Wrap(c1, obfs.Policy{CellSize: 512}); got != c1 {
		t.Fatal("stub Wrap must return the base connection unchanged")
	}
	if got := obfs.Wrap(c2, obfs.Policy{}); got != c2 {
		t.Fatal("stub Wrap with zero policy must return the base connection unchanged")
	}
}

func TestListenerPassthrough(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer base.Close()

	if got := obfs.Listener(base, obfs.Policy{CellSize: 256}); got != base {
		t.Fatal("stub Listener must return the base listener unchanged")
	}
}

func TestDialerPassthrough(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	dial := obfs.Dialer(func() (net.Conn, error) { return c1, nil }, obfs.Policy{CellSize: 128})
	got, err := dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if got != c1 {
		t.Fatal("stub Dialer must hand back the base connection unchanged")
	}
}

// The API surface (types, samplers, fills) must exist and be callable.
func TestAPISurface(t *testing.T) {
	_ = obfs.Policy{
		CellSize:     obfs.DefaultCellSize,
		Jitter:       time.Millisecond,
		CoverEvery:   time.Second,
		Fill:         obfs.RandomFill,
		SizeSampler:  obfs.UniformSize(16, 48),
		DelaySampler: obfs.PoissonDelay(time.Millisecond),
	}

	_ = obfs.UniformSize(64, 256)()
	_ = obfs.SampledSize(map[int]float64{40: 1, 100: 3})()
	_ = obfs.PoissonDelay(time.Millisecond)()

	var fills = []obfs.FillFunc{obfs.RandomFill, obfs.ZeroFill, obfs.PrintableFill}
	for _, f := range fills {
		f(make([]byte, 8)) // must not panic
	}
}
