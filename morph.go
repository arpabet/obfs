/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import "time"

// UniformSize returns a SizeSampler drawing cell sizes uniformly from [min, max]
// (inclusive). It is the simplest morpher policy — sizes vary but match no
// particular protocol.
//
// STUB: this build returns a sampler that always yields min.
func UniformSize(min, max int) func() int {
	if min > max {
		min, max = max, min
	}
	return func() int { return min }
}

// SampledSize returns a SizeSampler drawing from an empirical size distribution:
// keys are cell sizes and values are relative weights (need not sum to 1). Build
// the map from the packet sizes of a cover protocol to make the shaped stream's
// size profile resemble it. With no positive weights it falls back to DefaultCellSize.
//
// STUB: this build returns a sampler that always yields DefaultCellSize.
func SampledSize(weights map[int]float64) func() int {
	return func() int { return DefaultCellSize }
}

// PoissonDelay returns a DelaySampler producing exponentially-distributed delays
// with the given mean (a Poisson process), so inter-flush timing looks less
// regular than uniform jitter. A non-positive mean disables the delay.
//
// STUB: this build returns a sampler that always yields 0.
func PoissonDelay(mean time.Duration) func() time.Duration {
	return func() time.Duration { return 0 }
}
