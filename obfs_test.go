/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"net"
	"testing"
	"time"

	"go.arpabet.com/glue"
	"go.arpabet.com/obfs"
	"go.arpabet.com/servion"
)

func TestNopPassthrough(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	n := obfs.Nop()
	if n.Name() != "nop" {
		t.Fatalf("name = %q, want nop", n.Name())
	}
	out, err := n.Obfuscate(c1)
	if err != nil {
		t.Fatalf("Obfuscate: %v", err)
	}
	if out != c1 {
		t.Fatal("Nop().Obfuscate must return the same connection (pass-through)")
	}
}

// The stub server must satisfy the full servion.Server lifecycle: bind, serve in
// the background (blocking until shutdown), accept a connection, then shut down.
func TestObfsServerLifecycle(t *testing.T) {

	ctx, err := glue.New(
		glue.MapPropertySource{"obfs-server.bind-address": "127.0.0.1:0"},
		servion.ZapLogFactory(true),
		obfs.ObfsServerScanner("obfs-server"),
	)
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	defer ctx.Close()

	list := ctx.Bean(servion.ServerClass, glue.DefaultSearchLevel)
	if len(list) != 1 {
		t.Fatalf("expected exactly 1 servion.Server, got %d", len(list))
	}
	srv := list[0].Object().(servion.Server)

	if err := srv.Bind(); err != nil {
		t.Fatalf("bind: %v", err)
	}
	addr := srv.ListenAddress().String()
	if addr == "" {
		t.Fatal("ListenAddress is empty after Bind")
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()

	// the stub accepts and immediately drops the connection — a successful dial
	// is enough to prove the lifecycle works.
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if err := srv.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}
