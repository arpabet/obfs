/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

const hdrSize = 2 // uint16 real-data length prefix inside each cell

var errCorruptCell = errors.New("obfs: corrupt cell (data length exceeds cell size)")

// shapedConn is a net.Conn that re-frames I/O into fixed-size cells. Each cell is
// [2-byte big-endian real length n][n data bytes][padding], so every cell is
// exactly CellSize bytes on the wire regardless of payload. A length of 0 marks a
// cover (chaff) cell, discarded on read.
type shapedConn struct {
	base     net.Conn
	cellSize int
	maxData  int
	fill     FillFunc
	jitter   time.Duration

	// morpher mode (SizeSampler != nil): variable, self-describing cell sizes.
	morph        bool
	sizeSampler  func() int
	delaySampler func() time.Duration

	writeMu   sync.Mutex
	lastWrite time.Time

	// read side — single reader, no lock; pending points into the read buffer until
	// drained. cell is the fixed-mode buffer; rbuf grows per cell in morpher mode.
	cell    []byte
	rbuf    []byte
	pending []byte

	closeOnce sync.Once
	closeErr  error
	done      chan struct{}
	wg        sync.WaitGroup
}

func newShapedConn(base net.Conn, p Policy) net.Conn {
	morph := p.SizeSampler != nil
	if !morph && p.CellSize <= hdrSize {
		return base // shaping disabled
	}
	fill := p.Fill
	if fill == nil {
		fill = RandomFill
	}
	c := &shapedConn{
		base:         base,
		cellSize:     p.CellSize,
		maxData:      p.CellSize - hdrSize, // fixed mode only
		fill:         fill,
		jitter:       p.Jitter,
		morph:        morph,
		sizeSampler:  p.SizeSampler,
		delaySampler: p.DelaySampler,
		lastWrite:    time.Now(),
		done:         make(chan struct{}),
	}
	if !morph {
		c.cell = make([]byte, p.CellSize)
	}
	if p.CoverEvery > 0 {
		c.wg.Add(1)
		go c.coverLoop(p.CoverEvery)
	}
	if p.Front != nil && p.Front.Window > 0 && p.Front.MaxCount > 0 {
		c.wg.Add(1)
		go c.frontLoop(*p.Front)
	}
	return c
}

// Write splits p into fixed-size cells (padding the last one) and flushes them in
// a single underlying write, after an optional jitter delay.
func (c *shapedConn) Write(p []byte) (int, error) {
	if c.morph {
		return c.writeMorph(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	nCells := (len(p) + c.maxData - 1) / c.maxData
	buf := make([]byte, nCells*c.cellSize)
	src := p
	for off := 0; off < len(buf); off += c.cellSize {
		cell := buf[off : off+c.cellSize]
		m := len(src)
		if m > c.maxData {
			m = c.maxData
		}
		binary.BigEndian.PutUint16(cell[:hdrSize], uint16(m))
		copy(cell[hdrSize:hdrSize+m], src[:m])
		c.fill(cell[hdrSize+m:])
		src = src[m:]
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

// Read returns the real bytes from the next data cell, transparently skipping
// cover cells. It reconstructs the original byte stream regardless of how Write
// split it into cells.
func (c *shapedConn) Read(p []byte) (int, error) {
	if c.morph {
		return c.readMorph(p)
	}
	for len(c.pending) == 0 {
		if _, err := io.ReadFull(c.base, c.cell); err != nil {
			return 0, err
		}
		n := int(binary.BigEndian.Uint16(c.cell[:hdrSize]))
		if n > c.maxData {
			return 0, errCorruptCell
		}
		c.pending = c.cell[hdrSize : hdrSize+n] // n == 0 (cover) -> empty -> loop
	}
	k := copy(p, c.pending)
	c.pending = c.pending[k:]
	return k, nil
}

// applyDelay sleeps before a flush: a sampled delay in morpher mode (when set),
// otherwise uniform jitter in [0, Jitter].
func (c *shapedConn) applyDelay() {
	if c.delaySampler != nil {
		if d := c.delaySampler(); d > 0 {
			time.Sleep(d)
		}
		return
	}
	c.applyJitter()
}

func (c *shapedConn) applyJitter() {
	if c.jitter > 0 {
		time.Sleep(time.Duration(rand.Int63n(int64(c.jitter) + 1)))
	}
}

// coverLoop emits a cover cell whenever the connection has been idle for interval,
// so an observer cannot tell a busy connection from an idle one.
func (c *shapedConn) coverLoop(interval time.Duration) {
	defer c.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			c.writeMu.Lock()
			if time.Since(c.lastWrite) >= interval {
				if _, err := c.base.Write(c.coverCell()); err == nil {
					c.lastWrite = time.Now()
				}
			}
			c.writeMu.Unlock()
		}
	}
}

// frontLoop implements the FRONT defense: it draws a dummy-cell budget uniformly
// from [1, MaxCount] and a Rayleigh scale from the window, samples one send time per
// dummy cell, and emits cover cells at those (sorted) times. It runs once, near the
// start of the connection, then exits — front-loading non-deterministic padding.
func (c *shapedConn) frontLoop(cfg FrontConfig) {
	defer c.wg.Done()

	n := 1 + rand.Intn(cfg.MaxCount)
	// Rayleigh scale as a random fraction of the window, so the padding mass lands
	// at a non-deterministic point inside it rather than always early or always late.
	sigma := float64(cfg.Window) * (0.3 + 0.4*rand.Float64())

	times := make([]time.Duration, n)
	for i := range times {
		u := rand.Float64()
		if u <= 0 {
			u = math.SmallestNonzeroFloat64
		}
		t := time.Duration(sigma * math.Sqrt(-2*math.Log(u))) // Rayleigh sample
		if t > cfg.Window {
			t = cfg.Window
		}
		times[i] = t
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })

	start := time.Now()
	for _, t := range times {
		timer := time.NewTimer(t - time.Since(start)) // a non-positive delay fires at once
		select {
		case <-c.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		c.writeMu.Lock()
		if _, err := c.base.Write(c.coverCell()); err == nil {
			c.lastWrite = time.Now()
		}
		c.writeMu.Unlock()
	}
}

// coverCell builds a single cover (zero-data) cell in the active framing mode.
func (c *shapedConn) coverCell() []byte {
	if c.morph {
		return c.morphCoverCell()
	}
	cell := make([]byte, c.cellSize) // real-length header stays 0 -> cover
	c.fill(cell[hdrSize:])
	return cell
}

func (c *shapedConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.wg.Wait()
		c.closeErr = c.base.Close()
	})
	return c.closeErr
}

func (c *shapedConn) LocalAddr() net.Addr                { return c.base.LocalAddr() }
func (c *shapedConn) RemoteAddr() net.Addr               { return c.base.RemoteAddr() }
func (c *shapedConn) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *shapedConn) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *shapedConn) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }
