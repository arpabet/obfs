/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package hop_test

import (
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs/hop"
	"golang.org/x/xerrors"
)

// freePort returns a currently-free localhost address. There is a small race
// between closing here and re-binding in MultiListener, acceptable for a test.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	return l.Addr().String()
}

// TestMultiListener_AcceptsOnAllAddrs: a client may connect to any of the bound
// addresses and the fan-in listener accepts it.
func TestMultiListener_AcceptsOnAllAddrs(t *testing.T) {
	a1, a2 := freePort(t), freePort(t)
	ml, err := hop.MultiListener([]string{a1, a2}, nil)
	if err != nil {
		t.Fatalf("MultiListener: %v", err)
	}
	defer ml.Close()

	accepted := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ml.Accept()
			if err != nil {
				return
			}
			c.Close()
			accepted <- struct{}{}
		}
	}()

	for _, a := range []string{a1, a2} {
		c, err := net.Dial("tcp", a)
		if err != nil {
			t.Fatalf("dial %s: %v", a, err)
		}
		c.Close()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for accept on a hopped address")
		}
	}
}

// TestMultiListener_Close: Accept unblocks with an error after Close.
func TestMultiListener_Close(t *testing.T) {
	ml, err := hop.MultiListener([]string{freePort(t)}, nil)
	if err != nil {
		t.Fatalf("MultiListener: %v", err)
	}
	errc := make(chan error, 1)
	go func() { _, e := ml.Accept(); errc <- e }()
	time.Sleep(20 * time.Millisecond)
	if err := ml.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case e := <-errc:
		if e == nil {
			t.Fatal("Accept after Close returned nil error")
		}
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}

// TestDialer_Rotates: over successive time windows the dialer spreads across the
// address set rather than pinning one.
func TestDialer_Rotates(t *testing.T) {
	addrs := []string{"a:1", "b:2", "c:3"}
	seen := map[string]bool{}
	errStop := xerrors.New("stop")
	dial, err := hop.Dialer(addrs, time.Millisecond, func(a string) (net.Conn, error) {
		seen[a] = true
		return nil, errStop
	})
	if err != nil {
		t.Fatalf("Dialer: %v", err)
	}
	for i := 0; i < 30; i++ {
		if _, e := dial(); e != errStop {
			t.Fatalf("dial returned %v, want errStop", e)
		}
		time.Sleep(time.Millisecond)
	}
	if len(seen) < 2 {
		t.Fatalf("expected rotation across addresses, only saw %v", seen)
	}
}

func TestDialer_Validation(t *testing.T) {
	if _, err := hop.Dialer(nil, time.Second, nil); err == nil {
		t.Error("expected error for empty addrs")
	}
	if _, err := hop.Dialer([]string{"a:1"}, 0, nil); err == nil {
		t.Error("expected error for non-positive period")
	}
}
