/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// Datagram obfuscation (Salamander-style, after Hysteria2). Each datagram is
// wrapped as
//
//	[8B random salt][AES-256-CTR( [2B realLen][realData][padding] )]
//
// The PSK is hashed to an AES-256 key; the per-datagram salt seeds the CTR IV, so
// two identical payloads encrypt to different bytes and a passive observer sees only
// pseudo-random datagrams — defeating DPI that fingerprints the carried protocol
// (e.g. a QUIC long-header). The optional length-prefix + padding lets each datagram
// be grown to a sampled size so packet *lengths* stop leaking, the datagram analogue
// of the stream morpher.
const (
	saltSize    = 8
	pktHdrSize  = 2 // big-endian real-data length inside the encrypted frame
	pktOverhead = saltSize + pktHdrSize
	maxDatagram = 65535
	maxPktData  = maxDatagram - pktOverhead
)

var (
	errShortPacket = errors.New("obfs: datagram too short to be an obfs frame")
	errPacketLen   = errors.New("obfs: corrupt datagram (real length exceeds frame)")
	errPacketBig   = errors.New("obfs: datagram payload too large to frame")
)

// PacketPolicy configures datagram obfuscation. The zero PacketPolicy (empty Key)
// disables it, so WrapPacket returns the base PacketConn unchanged and obfuscation
// can be toggled by configuration.
type PacketPolicy struct {
	// Key is the pre-shared secret keying the per-datagram obfuscation; both peers
	// must use the same Key. An empty Key disables obfuscation (pass-through).
	Key []byte

	// Pad, when non-nil, is a target-size sampler (the same shape as Policy.SizeSampler,
	// e.g. UniformSize or SampledSize): each datagram is grown with padding to at
	// least the sampled on-wire size, so packet lengths match a cover distribution.
	// Sizes at or below the real frame add no padding. nil sends no padding.
	Pad func() int

	// Fill generates padding bytes; nil uses RandomFill. Padding rides inside the
	// encrypted frame, so the choice is cosmetic unless the carrier is cleartext.
	Fill FillFunc
}

// WrapPacket returns base with per-datagram obfuscation per p, as a net.PacketConn.
// The peer must wrap with the same Key (and, for length matching, a comparable Pad).
// With an empty Key, base is returned unchanged.
//
// This obfuscates and encrypts the payload but provides NO integrity/authentication
// (it is unauthenticated AES-CTR) — it is camouflage, not a secure channel. Run a
// real tunnel (e.g. QUIC's own TLS) inside it; for QUIC, hand the wrapped PacketConn
// to the transport. Apply it symmetrically.
func WrapPacket(base net.PacketConn, p PacketPolicy) net.PacketConn {
	if len(p.Key) == 0 {
		return base
	}
	sum := sha256.Sum256(p.Key)
	block, _ := aes.NewCipher(sum[:]) // 32-byte key: AES-256; err is impossible here
	fill := p.Fill
	if fill == nil {
		fill = RandomFill
	}
	c := &obfsPacketConn{PacketConn: base, block: block, pad: p.Pad, fill: fill}
	c.readPool.New = func() any { b := make([]byte, maxDatagram); return &b }
	return c
}

type obfsPacketConn struct {
	net.PacketConn
	block    cipher.Block
	pad      func() int
	fill     FillFunc
	readPool sync.Pool
}

// stream returns a fresh CTR keystream for one datagram, seeded by its salt. A new
// stream per datagram keeps WriteTo/ReadFrom safe for concurrent use (cipher.Block
// is read-only and shared; cipher.Stream is not, so it is never shared).
func (c *obfsPacketConn) stream(salt []byte) cipher.Stream {
	var iv [aes.BlockSize]byte
	copy(iv[:], salt) // remaining bytes stay zero
	return cipher.NewCTR(c.block, iv[:])
}

func (c *obfsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > maxPktData {
		return 0, errPacketBig
	}
	frameLen := pktHdrSize + len(p)
	if c.pad != nil {
		if s := c.pad(); s > frameLen {
			if s > maxDatagram {
				s = maxDatagram
			}
			frameLen = s
		}
	}
	out := make([]byte, saltSize+frameLen)
	salt := out[:saltSize]
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	frame := out[saltSize:]
	binary.BigEndian.PutUint16(frame[:pktHdrSize], uint16(len(p)))
	copy(frame[pktHdrSize:], p)
	c.fill(frame[pktHdrSize+len(p):])
	c.stream(salt).XORKeyStream(frame, frame)

	if _, err := c.PacketConn.WriteTo(out, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *obfsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufp := c.readPool.Get().(*[]byte)
	defer c.readPool.Put(bufp)
	buf := *bufp

	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, addr, err
	}
	if n < pktOverhead {
		return 0, addr, errShortPacket
	}
	salt, frame := buf[:saltSize], buf[saltSize:n]
	c.stream(salt).XORKeyStream(frame, frame)

	realLen := int(binary.BigEndian.Uint16(frame[:pktHdrSize]))
	if realLen > len(frame)-pktHdrSize {
		return 0, addr, errPacketLen
	}
	k := copy(p, frame[pktHdrSize:pktHdrSize+realLen]) // excess (p too small) is dropped, UDP-style
	return k, addr, nil
}
