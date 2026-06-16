/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"go.arpabet.com/glue"
	"go.arpabet.com/servion"
	"go.uber.org/zap"
)

type implObfsServer struct {
	Log        *zap.Logger     `inject:""`
	Properties glue.Properties `inject:""`
	Obfuscator Obfuscator      `inject:"optional"`

	beanName string

	listener     net.Listener
	alive        atomic.Bool
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

/*
ObfsServer returns a STUB servion.Server. It binds a TCP listener and runs the
standard servion lifecycle (Bind / Serve / Shutdown) so it can be wired into a
servion runtime today, but it performs no real obfuscation: accepted connections
are passed through the (no-op) Obfuscator and dropped. It is registered
automatically by ObfsServerScanner.

Recognized properties (prefixed by beanName):

	<beanName>.bind-address    listen address, e.g. "0.0.0.0:9200"
*/
func ObfsServer(beanName string) servion.Server {
	return &implObfsServer{beanName: beanName, shutdownCh: make(chan struct{})}
}

func (t *implObfsServer) PostConstruct() error {
	t.alive.Store(false)
	return nil
}

func (t *implObfsServer) Bind() (err error) {

	defer servion.PanicToError(&err)

	addr := t.Properties.GetString(fmt.Sprintf("%s.bind-address", t.beanName), "")
	if addr == "" {
		return fmt.Errorf("property '%s.bind-address' not found in server context", t.beanName)
	}

	t.listener, err = net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("can not bind to '%s': %w", addr, err)
	}
	return nil
}

func (t *implObfsServer) Alive() bool {
	return t.alive.Load()
}

func (t *implObfsServer) ListenAddress() net.Addr {
	if t.listener != nil {
		return t.listener.Addr()
	}
	return servion.EmptyAddr
}

func (t *implObfsServer) obfuscator() Obfuscator {
	if t.Obfuscator != nil {
		return t.Obfuscator
	}
	return Nop()
}

func (t *implObfsServer) Serve() (err error) {

	defer servion.PanicToError(&err)

	if t.listener == nil {
		return fmt.Errorf("obfs server '%s' is not bound", t.beanName)
	}

	obf := t.obfuscator()
	addr := t.ListenAddress()
	t.Log.Info("ObfsServerServe",
		zap.String("bean", t.beanName),
		zap.String("addr", addr.String()),
		zap.String("network", addr.Network()),
		zap.String("obfuscator", obf.Name()))

	t.alive.Store(true)
	defer t.alive.Store(false)

	for {
		conn, aerr := t.listener.Accept()
		if aerr != nil {
			select {
			case <-t.shutdownCh:
				return nil
			default:
			}
			if strings.Contains(aerr.Error(), "closed") {
				return nil
			}
			t.Log.Warn("ObfsServerAccept", zap.Error(aerr))
			return aerr
		}

		// STUB: wrap with the (no-op) obfuscator and drop the connection.
		// A real transport would hand the wrapped conn to a backend / RPC mux here.
		if wrapped, werr := obf.Obfuscate(conn); werr == nil {
			conn = wrapped
		}
		_ = conn.Close()
	}
}

func (t *implObfsServer) Shutdown() (err error) {

	t.shutdownOnce.Do(func() {

		addr := t.ListenAddress()
		t.Log.Info("ObfsServerShutdown",
			zap.String("addr", addr.String()),
			zap.String("network", addr.Network()))

		// notify everyone that we are shutting down
		close(t.shutdownCh)

		if t.listener != nil {
			err = t.listener.Close()
		}
	})

	return
}

func (t *implObfsServer) ShutdownCh() <-chan struct{} {
	return t.shutdownCh
}

func (t *implObfsServer) Destroy() error {
	// safe to call twice
	t.Shutdown()
	return nil
}
