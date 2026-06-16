/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

// Package obfs provides carrier-agnostic traffic-shaping middleware for Go byte
// streams. It wraps any net.Conn and re-frames the bytes into fixed-size cells
// with padding, optional timing jitter, and optional cover (chaff) traffic, so a
// network observer cannot fingerprint an application's operations by their packet
// sizes and timing.
//
// It exists because content encryption (TLS) hides *what* you send but not the
// *size and timing* of each message — and per-operation size/timing is often
// enough to identify "which request ran" or "which page loaded". A fixed-cell
// shaper makes every write look identical on the wire, the same idea behind Tor's
// 514-byte cells. obfs is deliberately transport- and protocol-neutral (it depends
// on nothing outside the standard library), so it composes with value-rpc, gRPC,
// plain net/http, or anything else that hands it a net.Conn:
//
//	// Client: shape a base connection, then run any protocol over it.
//	shaped := obfs.Wrap(baseConn, obfs.Policy{CellSize: 512})
//
//	// With value-rpc, hand the shaped conn to the bring-your-own-conn seam:
//	dialer := valuerpc.NewFuncDialer(func() (io.ReadWriteCloser, error) {
//		c, err := net.Dial("tcp", addr)
//		if err != nil {
//			return nil, err
//		}
//		return obfs.Wrap(c, policy), nil
//	}, writeTimeout)
//
// # What obfs is NOT
//
//   - It is NOT encryption or authentication. The shaper does not hide the content
//     of your bytes; run it UNDER TLS (or another vetted secure channel). A shaping
//     layer over plaintext is a privacy illusion.
//   - It is NOT a complete circumvention system. Hiding the rendezvous (which
//     server / IP / SNI) and mimicking a specific protocol's handshake (uTLS,
//     REALITY) are separate concerns tracked in the repository roadmap.
//
// # Use responsibly
//
// Traffic obfuscation is legitimate and important for journalists, NGOs, and
// people living under network censorship — and it is dual-use. Do not use it to
// evade authorized security monitoring or in violation of applicable law. Whether
// running such software is lawful varies by jurisdiction; that is the deployer's
// responsibility.
package obfs

import (
	"net"
	"time"
)

// DefaultCellSize is a reasonable fixed cell size when none is chosen.
const DefaultCellSize = 512

// Policy configures the shaper. The zero Policy disables shaping (Wrap returns the
// base connection unchanged), so shaping can be toggled by configuration.
type Policy struct {
	// CellSize is the exact number of bytes every wire cell occupies. Real
	// messages are split and padded to this size, so no single frame's length
	// reveals an operation. A value <= 2 disables shaping. Typical: 128–1500.
	CellSize int

	// Jitter, if > 0, delays each flush by a random duration in [0, Jitter],
	// decorrelating inter-packet timing from computation time. Costs latency.
	Jitter time.Duration

	// CoverEvery, if > 0, sends a cover (chaff) cell whenever the connection has
	// been idle this long, so "silent vs. busy" and burst shape stop leaking.
	// Costs bandwidth.
	CoverEvery time.Duration

	// Fill generates the padding and cover bytes; nil uses RandomFill. Choose
	// PrintableFill to bias cells toward a high printable-ASCII ratio when the
	// shaped stream rides a cleartext channel and must dodge fully-encrypted-traffic
	// heuristics. (Under TLS the byte distribution is moot.)
	Fill FillFunc

	// SizeSampler, when non-nil, switches the shaper into "morpher" mode: instead
	// of a fixed CellSize, every cell takes a size drawn from SizeSampler, so the
	// on-wire size distribution can be shaped to match a cover protocol rather than
	// being uniform. Morpher mode uses a self-describing wire framing distinct from
	// fixed-cell mode, so BOTH peers must set a SizeSampler; CellSize is then
	// ignored. See UniformSize and SampledSize.
	SizeSampler func() int

	// DelaySampler, when non-nil, draws the delay applied before each flush,
	// overriding Jitter — e.g. PoissonDelay for exponential (less regular) gaps.
	DelaySampler func() time.Duration

	// Front, when non-nil, enables FRONT-style adaptive cover: at connection start a
	// random budget of dummy cells is scheduled at times drawn from a Rayleigh
	// distribution over Front.Window, independent of real traffic. Unlike CoverEvery
	// (constant-rate, only-when-idle chaff), this front-loads non-deterministic
	// padding to blunt website-fingerprinting on the early, most-informative part of
	// a trace. It is applied by the sender, so it need not be symmetric; it composes
	// with CoverEvery. See FrontConfig.
	Front *FrontConfig
}

// FrontConfig parameterizes FRONT-style front-loaded cover padding (Policy.Front).
// The defense (Gong & Wang, "Zero-delay Lightweight Defenses against Website
// Fingerprinting", USENIX Security 2020) injects dummy packets whose timestamps are
// Rayleigh-distributed over a window, concentrating cover where a trace leaks most.
type FrontConfig struct {
	// Window is the time span from connection start over which dummy cells are
	// spread. A non-positive Window disables the defense.
	Window time.Duration

	// MaxCount caps the dummy-cell budget; the actual count is drawn uniformly from
	// [1, MaxCount]. A non-positive MaxCount disables the defense.
	MaxCount int
}

// Wrap returns base shaped according to p, as a net.Conn. The returned connection
// re-frames all I/O into cells; the peer must be Wrapped with a matching policy
// (same CellSize in fixed mode, or also a SizeSampler in morpher mode). With the
// zero policy (CellSize <= 2 and no SizeSampler) base is returned unchanged.
//
// The shaper adds no encryption: compose it under TLS. Apply it symmetrically.
func Wrap(base net.Conn, p Policy) net.Conn {
	return newShapedConn(base, p)
}

// Dialer wraps a base dial function so every connection it returns is shaped per
// p. It is the client-side convenience for any stack that dials a net.Conn; for
// value-rpc, pass the result through valuerpc.NewFuncDialer.
func Dialer(dial func() (net.Conn, error), p Policy) func() (net.Conn, error) {
	return func() (net.Conn, error) {
		c, err := dial()
		if err != nil {
			return nil, err
		}
		return Wrap(c, p), nil
	}
}

// Listener wraps a base net.Listener so every accepted connection is shaped per p.
func Listener(base net.Listener, p Policy) net.Listener {
	return &shapedListener{Listener: base, policy: p}
}

type shapedListener struct {
	net.Listener
	policy Policy
}

func (l *shapedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Wrap(c, l.policy), nil
}
