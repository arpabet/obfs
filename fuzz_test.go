/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs_test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"go.arpabet.com/obfs"
)

// readerConn is a minimal net.Conn whose Read drains a fixed byte slice (then
// reports io.EOF) and whose Write is discarded. It feeds attacker-controlled wire
// bytes into a shaped conn's reader so the cell parsers can be fuzzed in isolation.
type readerConn struct {
	r *bytes.Reader
}

func (c *readerConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *readerConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *readerConn) Close() error                       { return nil }
func (c *readerConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *readerConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *readerConn) SetDeadline(t time.Time) error      { return nil }
func (c *readerConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *readerConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "fuzz" }
func (dummyAddr) String() string  { return "fuzz" }

// drain reads from r until any error, asserting only that it terminates (no panic,
// no hang) on arbitrary input. The reader is single-use, so a bounded source must
// always reach io.EOF / ErrUnexpectedEOF.
func drain(t *testing.T, r net.Conn) {
	t.Helper()
	buf := make([]byte, 37) // odd size to exercise partial pending drains
	for i := 0; i < 1<<20; i++ {
		if _, err := r.Read(buf); err != nil {
			return
		}
	}
	t.Fatal("reader did not terminate on bounded input")
}

// FuzzShapedRead feeds arbitrary bytes to the fixed-cell reader. The 2-byte real
// length header is untrusted; the parser must reject n > maxData rather than panic.
func FuzzShapedRead(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})                   // a cover cell
	f.Add([]byte{0x00, 0x02, 'h', 'i'})         // a valid 1-cell payload (CellSize 4)
	f.Add([]byte{0xff, 0xff, 0x01, 0x02})       // length far exceeds the cell
	f.Add(bytes.Repeat([]byte{0x00, 0x01}, 64)) // many tiny cells

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := obfs.Wrap(&readerConn{r: bytes.NewReader(data)}, obfs.Policy{CellSize: 4})
		drain(t, conn)
	})
}

// FuzzMorphRead feeds arbitrary bytes to the morpher reader, whose self-describing
// total-length and real-length fields are both untrusted.
func FuzzMorphRead(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x02, 0x00, 0x00})           // a zero-data (cover) cell
	f.Add([]byte{0x00, 0x04, 0x00, 0x02, 'h', 'i'}) // a valid 2-byte payload cell
	f.Add([]byte{0x00, 0x02, 0xff, 0xff})           // realLen exceeds the cell body
	f.Add([]byte{0xff, 0xff})                       // total length with no body

	f.Fuzz(func(t *testing.T, data []byte) {
		conn := obfs.Wrap(&readerConn{r: bytes.NewReader(data)}, obfs.Policy{
			SizeSampler: obfs.UniformSize(8, 32), // any sampler -> morpher read path
		})
		drain(t, conn)
	})
}
