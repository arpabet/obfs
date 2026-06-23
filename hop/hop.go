/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package hop adds port/address hopping to a Go transport: clients rotate the
// destination across a set of addresses on a time schedule, while servers listen
// on all of them at once. Rotating the visible IP:port frustrates static
// blocklists and per-endpoint rate analysis, in the spirit of Hysteria's port
// hopping. It depends only on the standard library and is independent of any RPC
// protocol, so it composes with value-rpc, gRPC, or plain net I/O.
package hop

import (
	"net"
	"sync"
	"time"

	"golang.org/x/xerrors"
)

var (
	errNoAddrs   = xerrors.New("hop: no addresses")
	errBadPeriod = xerrors.New("hop: period must be > 0")
)

// Dialer returns a dial function that, on each call, selects the address for the
// current time window (window = floor(now/period), index = window mod len(addrs))
// and dials it with dial. Because the server (see MultiListener) listens on every
// address at once, the client and server need not share the schedule — rotation
// simply spreads connections across endpoints. dial defaults to net.Dial("tcp", …)
// when nil.
func Dialer(addrs []string, period time.Duration, dial func(addr string) (net.Conn, error)) (func() (net.Conn, error), error) {
	if len(addrs) == 0 {
		return nil, errNoAddrs
	}
	if period <= 0 {
		return nil, errBadPeriod
	}
	if dial == nil {
		dial = func(a string) (net.Conn, error) { return net.Dial("tcp", a) }
	}
	cp := append([]string(nil), addrs...)
	return func() (net.Conn, error) {
		w := time.Now().UnixNano() / int64(period)
		idx := int(((w % int64(len(cp))) + int64(len(cp))) % int64(len(cp)))
		return dial(cp[idx])
	}, nil
}

// MultiListener listens on every address in addrs at once and fans their accepted
// connections into a single net.Listener, so a port-hopping client lands wherever
// it connects. listen defaults to net.Listen("tcp", …) when nil. If any address
// fails to bind, those already opened are closed and the error is returned.
func MultiListener(addrs []string, listen func(addr string) (net.Listener, error)) (net.Listener, error) {
	if len(addrs) == 0 {
		return nil, errNoAddrs
	}
	if listen == nil {
		listen = func(a string) (net.Listener, error) { return net.Listen("tcp", a) }
	}
	ml := &multiListener{
		conns: make(chan acceptResult),
		done:  make(chan struct{}),
	}
	for _, a := range addrs {
		l, err := listen(a)
		if err != nil {
			_ = ml.Close()
			return nil, err
		}
		ml.lis = append(ml.lis, l)
	}
	for _, l := range ml.lis {
		ml.wg.Add(1)
		go ml.acceptLoop(l)
	}
	return ml, nil
}

type acceptResult struct {
	c   net.Conn
	err error
}

type multiListener struct {
	lis   []net.Listener
	conns chan acceptResult
	done  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
}

func (m *multiListener) acceptLoop(l net.Listener) {
	defer m.wg.Done()
	for {
		c, err := l.Accept()
		select {
		case m.conns <- acceptResult{c, err}:
			if err != nil {
				return
			}
		case <-m.done:
			if c != nil {
				_ = c.Close()
			}
			return
		}
	}
}

func (m *multiListener) Accept() (net.Conn, error) {
	select {
	case r := <-m.conns:
		return r.c, r.err
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multiListener) Close() error {
	m.once.Do(func() { close(m.done) })
	var firstErr error
	for _, l := range m.lis {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (m *multiListener) Addr() net.Addr {
	if len(m.lis) > 0 {
		return m.lis[0].Addr()
	}
	return nil
}
