/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

// FillFunc generates padding and cover bytes, filling all of p. It controls the
// byte-distribution ("entropy / printability") profile of the shaped stream.
type FillFunc func(p []byte)

// RandomFill fills p with pseudo-random bytes (high entropy). It is the default.
// The bytes are not cryptographically secret — padding need not be — so a fast
// PRNG is used; confidentiality must come from running the shaper under TLS.
//
// STUB: this build performs no fill.
func RandomFill(p []byte) {}

// ZeroFill fills p with zero bytes — cheapest, but a long run of zeros is itself a
// recognizable pattern. Useful mainly for tests.
//
// STUB: this build performs no fill.
func ZeroFill(p []byte) {}

// PrintableFill fills p with random printable ASCII (0x20–0x7e), raising each
// cell's printable-byte ratio. Use it when the shaped stream must ride a cleartext
// channel and stay clear of fully-encrypted-traffic heuristics that block flows
// with too few printable bytes or too high entropy. Under TLS this is unnecessary.
//
// STUB: this build performs no fill.
func PrintableFill(p []byte) {}
