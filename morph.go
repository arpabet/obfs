/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import (
	"encoding/binary"
	"io"
	"math"
	"math/rand"
	"sort"
	"time"
)

// Morpher framing (used when Policy.SizeSampler != nil). Unlike fixed-cell mode,
// each cell is variable-sized and self-describing on the wire:
//
//	[2B totalLen N][N bytes: [2B realLen R][R data bytes][N-2-R padding]]
//
// so the receiver can read variable-size cells and the size distribution can be
// shaped toward a cover protocol. Both peers must use morpher mode.
const (
	morphOverhead = 4     // 2-byte total length + 2-byte real length
	maxMorphCell  = 65535 // cap so the total-length field (cell size minus 2) fits a uint16
)

// writeMorph splits p into sampled-size cells and flushes them in one underlying
// write, after an optional sampled (or jitter) delay.
func (c *shapedConn) writeMorph(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	var buf []byte
	remaining := p
	for len(remaining) > 0 {
		s := c.sizeSampler()
		if s < morphOverhead+1 { // guarantee >= 1 byte of data capacity -> forward progress
			s = morphOverhead + 1
		}
		if s > maxMorphCell {
			s = maxMorphCell
		}
		r := s - morphOverhead // capacity
		if r > len(remaining) {
			r = len(remaining)
		}
		cell := make([]byte, s)
		binary.BigEndian.PutUint16(cell[0:2], uint16(s-2)) // total length following this field
		binary.BigEndian.PutUint16(cell[2:4], uint16(r))   // real data length
		copy(cell[4:4+r], remaining[:r])
		c.fill(cell[4+r:])
		buf = append(buf, cell...)
		remaining = remaining[r:]
	}
	c.applyDelay()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.base.Write(buf); err != nil {
		return 0, err
	}
	c.lastWrite = time.Now()
	return len(p), nil
}

// readMorph reads one variable-size cell at a time, skipping cover cells, and
// reconstructs the original byte stream.
func (c *shapedConn) readMorph(p []byte) (int, error) {
	for len(c.pending) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(c.base, hdr[:]); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(hdr[:])) // bytes following: 2 (realLen) + data + pad
		if n < 2 {
			return 0, errCorruptCell
		}
		if cap(c.rbuf) < n {
			c.rbuf = make([]byte, n)
		} else {
			c.rbuf = c.rbuf[:n]
		}
		if _, err := io.ReadFull(c.base, c.rbuf); err != nil {
			return 0, err
		}
		r := int(binary.BigEndian.Uint16(c.rbuf[0:2]))
		if r > n-2 {
			return 0, errCorruptCell
		}
		c.pending = c.rbuf[2 : 2+r] // r == 0 (cover) -> empty -> loop
	}
	k := copy(p, c.pending)
	c.pending = c.pending[k:]
	return k, nil
}

// morphCoverCell builds a zero-data cover cell of a sampled size.
func (c *shapedConn) morphCoverCell() []byte {
	s := c.sizeSampler()
	if s < morphOverhead {
		s = morphOverhead
	}
	if s > maxMorphCell {
		s = maxMorphCell
	}
	cell := make([]byte, s)
	binary.BigEndian.PutUint16(cell[0:2], uint16(s-2)) // realLen stays 0 -> cover
	c.fill(cell[4:])
	return cell
}

// UniformSize returns a SizeSampler drawing cell sizes uniformly from [min, max]
// (inclusive). It is the simplest morpher policy — sizes vary but match no
// particular protocol.
func UniformSize(min, max int) func() int {
	if min > max {
		min, max = max, min
	}
	span := max - min + 1
	return func() int {
		if span <= 1 {
			return min
		}
		return min + rand.Intn(span)
	}
}

// SampledSize returns a SizeSampler drawing from an empirical size distribution:
// keys are cell sizes and values are relative weights (need not sum to 1). Build
// the map from the packet sizes of a cover protocol to make the shaped stream's
// size profile resemble it. With no positive weights it falls back to DefaultCellSize.
func SampledSize(weights map[int]float64) func() int {
	sizes := make([]int, 0, len(weights))
	for s := range weights {
		sizes = append(sizes, s)
	}
	sort.Ints(sizes) // deterministic cumulative table

	type bucket struct {
		size int
		cum  float64
	}
	var table []bucket
	var total float64
	for _, s := range sizes {
		if w := weights[s]; w > 0 {
			total += w
			table = append(table, bucket{s, total})
		}
	}
	if len(table) == 0 {
		return func() int { return DefaultCellSize }
	}
	return func() int {
		x := rand.Float64() * total
		for _, b := range table {
			if x < b.cum {
				return b.size
			}
		}
		return table[len(table)-1].size
	}
}

// PoissonDelay returns a DelaySampler producing exponentially-distributed delays
// with the given mean (a Poisson process), so inter-flush timing looks less
// regular than uniform jitter. A non-positive mean disables the delay.
func PoissonDelay(mean time.Duration) func() time.Duration {
	return func() time.Duration {
		if mean <= 0 {
			return 0
		}
		u := rand.Float64()
		if u <= 0 {
			u = math.SmallestNonzeroFloat64
		}
		return time.Duration(-float64(mean) * math.Log(u))
	}
}
