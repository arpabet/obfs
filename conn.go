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
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/xerrors"
)

const hdrSize = 2 // uint16 real-data length prefix inside each cell

var errCorruptCell = xerrors.New("obfs: corrupt cell (data length exceeds cell size)")

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

	// paced mode (Paced != nil): a background pacer releases cells at a regularized,
	// decaying rate; Write enqueues framed cells into sendQ instead of writing them.
	paced     bool
	pace      PacedConfig
	sendQ     chan []byte
	paceDead  chan struct{} // closed when the pacer stops on a base-write error
	paceMu    sync.Mutex
	paceStart time.Time // surge clock; reset when a burst starts on a drained queue
	paceErrV  error     // sticky base-write error surfaced by later Write calls

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
	if p.Paced != nil && p.Paced.Rate > 0 {
		c.paced = true
		c.pace = p.Paced.withDefaults()
		c.sendQ = make(chan []byte, c.pace.Queue)
		c.paceDead = make(chan struct{})
		c.paceStart = time.Now()
	}
	// The pacer supersedes idle/front cover: it already emits cover when the queue is
	// empty, and direct writes from those loops would bypass the regularized schedule.
	if !c.paced {
		if p.CoverEvery > 0 {
			c.wg.Add(1)
			go c.coverLoop(p.CoverEvery)
		}
		if p.Front != nil && p.Front.Window > 0 && p.Front.MaxCount > 0 {
			c.wg.Add(1)
			go c.frontLoop(*p.Front)
		}
	} else {
		c.wg.Add(1)
		go c.pacingLoop()
	}
	return c
}

// Write splits p into fixed-size cells (padding the last one) and flushes them in
// a single underlying write, after an optional jitter delay.
func (c *shapedConn) Write(p []byte) (int, error) {
	if c.paced {
		return c.writePaced(p)
	}
	if c.morph {
		return c.writeMorph(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	buf, _ := c.fixedCells(p)
	c.applyDelay()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if _, err := c.base.Write(buf); err != nil {
		return 0, err
	}
	c.lastWrite = time.Now()
	return len(p), nil
}

// fixedCells frames p into fixed-size cells laid out back-to-back in one buffer; the
// returned cell slices alias that buffer, so callers may either write buf in a single
// flush (non-paced) or enqueue the per-cell slices (paced) without extra allocation.
func (c *shapedConn) fixedCells(p []byte) ([]byte, [][]byte) {
	nCells := (len(p) + c.maxData - 1) / c.maxData
	buf := make([]byte, nCells*c.cellSize)
	cells := make([][]byte, nCells)
	src := p
	for i := 0; i < nCells; i++ {
		cell := buf[i*c.cellSize : (i+1)*c.cellSize]
		m := len(src)
		if m > c.maxData {
			m = c.maxData
		}
		binary.BigEndian.PutUint16(cell[:hdrSize], uint16(m))
		copy(cell[hdrSize:hdrSize+m], src[:m])
		c.fill(cell[hdrSize+m:])
		cells[i] = cell
		src = src[m:]
	}
	return buf, cells
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

// writePaced frames p and hands the cells to the pacer instead of writing them now,
// applying back-pressure when the queue is full (throttling the application to the
// regularized rate). A base-write error seen by the pacer is reported here.
func (c *shapedConn) writePaced(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := c.pacedErr(); err != nil {
		return 0, err
	}
	var cells [][]byte
	if c.morph {
		cells = c.morphCells(p)
	} else {
		_, cells = c.fixedCells(p)
	}
	if len(c.sendQ) == 0 { // a fresh burst on a drained queue restarts the surge clock
		c.resetSurge()
	}
	for _, cell := range cells {
		select {
		case c.sendQ <- cell:
		case <-c.paceDead: // pacer died on a base-write error; don't block forever
			if err := c.pacedErr(); err != nil {
				return 0, err
			}
			return 0, net.ErrClosed
		case <-c.done:
			return 0, net.ErrClosed
		}
	}
	return len(p), nil
}

// pacingLoop is the RegulaTor-style sender: it wakes on the current (decaying) rate
// interval and releases one queued cell, or a cover cell when the queue is empty, so
// the on-wire schedule is regular and independent of how the application bursts.
func (c *shapedConn) pacingLoop() {
	defer c.wg.Done()
	for {
		timer := time.NewTimer(c.currentInterval())
		select {
		case <-c.done:
			timer.Stop()
			return
		case <-timer.C:
		}
		var cell []byte
		select {
		case cell = <-c.sendQ:
		default:
			if c.pace.NoPad {
				continue // hold the rate clock but send nothing while idle
			}
			cell = c.coverCell()
		}
		c.writeMu.Lock()
		_, err := c.base.Write(cell)
		if err == nil {
			c.lastWrite = time.Now()
		}
		c.writeMu.Unlock()
		if err != nil {
			c.setPaceErr(err)
			close(c.paceDead) // unblock any Write waiting on back-pressure
			return
		}
	}
}

// currentInterval converts the decayed send rate into an inter-cell delay. The rate
// is Rate*Decay^elapsed (since the last surge), floored at MinRate.
func (c *shapedConn) currentInterval() time.Duration {
	elapsed := time.Since(c.surgeStart()).Seconds()
	rate := c.pace.Rate
	if c.pace.Decay < 1 {
		rate = c.pace.Rate * math.Pow(c.pace.Decay, elapsed)
	}
	if rate < c.pace.MinRate {
		rate = c.pace.MinRate
	}
	return time.Duration(float64(time.Second) / rate)
}

func (c *shapedConn) resetSurge() {
	c.paceMu.Lock()
	c.paceStart = time.Now()
	c.paceMu.Unlock()
}

func (c *shapedConn) surgeStart() time.Time {
	c.paceMu.Lock()
	defer c.paceMu.Unlock()
	return c.paceStart
}

func (c *shapedConn) setPaceErr(err error) {
	c.paceMu.Lock()
	if c.paceErrV == nil {
		c.paceErrV = err
	}
	c.paceMu.Unlock()
}

func (c *shapedConn) pacedErr() error {
	c.paceMu.Lock()
	defer c.paceMu.Unlock()
	return c.paceErrV
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
		c.wg.Wait() // pacer/cover loops have stopped; sendQ now has no concurrent reader
		if c.paced {
			c.flushQueue() // best-effort: write cells already accepted by Write
		}
		c.closeErr = c.base.Close()
	})
	return c.closeErr
}

// flushQueue drains any cells still queued at Close and writes them, so data the
// application already handed to a successful Write is not silently dropped. Cells a
// concurrent in-flight Write had not yet enqueued (it observes c.done) are lost.
func (c *shapedConn) flushQueue() {
	for {
		select {
		case cell := <-c.sendQ:
			if _, err := c.base.Write(cell); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (c *shapedConn) LocalAddr() net.Addr                { return c.base.LocalAddr() }
func (c *shapedConn) RemoteAddr() net.Addr               { return c.base.RemoteAddr() }
func (c *shapedConn) SetDeadline(t time.Time) error      { return c.base.SetDeadline(t) }
func (c *shapedConn) SetReadDeadline(t time.Time) error  { return c.base.SetReadDeadline(t) }
func (c *shapedConn) SetWriteDeadline(t time.Time) error { return c.base.SetWriteDeadline(t) }
