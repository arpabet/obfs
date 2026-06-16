/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import "math/rand"

// FillFunc generates padding and cover bytes, filling all of p. It controls the
// byte-distribution ("entropy / printability") profile of the shaped stream.
type FillFunc func(p []byte)

// RandomFill fills p with pseudo-random bytes (high entropy). It is the default.
// The bytes are not cryptographically secret — padding need not be — so a fast
// PRNG is used; confidentiality must come from running the shaper under TLS.
func RandomFill(p []byte) {
	for i := 0; i < len(p); {
		v := rand.Uint64()
		for j := 0; j < 8 && i < len(p); j++ {
			p[i] = byte(v)
			v >>= 8
			i++
		}
	}
}

// ZeroFill fills p with zero bytes — cheapest, but a long run of zeros is itself a
// recognizable pattern. Useful mainly for tests.
func ZeroFill(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

// PrintableFill fills p with random printable ASCII (0x20–0x7e), raising each
// cell's printable-byte ratio. Use it when the shaped stream must ride a cleartext
// channel and stay clear of fully-encrypted-traffic heuristics that block flows
// with too few printable bytes or too high entropy. Under TLS this is unnecessary.
func PrintableFill(p []byte) {
	const lo, hi = 0x20, 0x7e
	for i := range p {
		p[i] = byte(lo + rand.Intn(hi-lo+1))
	}
}
