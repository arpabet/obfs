/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import "golang.org/x/xerrors"

const (
	extServerName uint16 = 0x0000
	extKeyShare   uint16 = 0x0033
	groupX25519   uint16 = 0x001d
)

var (
	// ErrNotTLS is returned when a record is not a TLS handshake record.
	ErrNotTLS = xerrors.New("xreality: not a TLS handshake record")
	// ErrBadHello is returned when a ClientHello cannot be parsed.
	ErrBadHello = xerrors.New("xreality: malformed ClientHello")
)

// ClientHelloInfo holds the REALITY-relevant fields a server reads out of a peeked
// ClientHello before deciding whether to terminate TLS or pass the connection through.
type ClientHelloInfo struct {
	Random     []byte // the 32-byte ClientHello random (HKDF salt / AEAD nonce+AAD)
	SessionID  []byte // the legacy_session_id (carries the sealed auth token, if ours)
	ServerName string // the SNI, if present
	X25519     []byte // the client's X25519 key_share (its ephemeral public key), if present
}

// ParseClientHello parses a single TLS record containing a ClientHello and returns
// its REALITY-relevant fields. It is strict and fully bounds-checked: any structural
// problem yields ErrBadHello rather than a panic. The record must contain the whole
// ClientHello (a server peeks exactly one record). Missing optional fields (no SNI,
// no X25519 key share) are reported as zero values, not errors — the caller decides.
func ParseClientHello(record []byte) (ClientHelloInfo, error) {
	var info ClientHelloInfo
	if len(record) < 5 || record[0] != 0x16 { // handshake record
		return info, ErrNotTLS
	}
	recLen := int(record[3])<<8 | int(record[4])
	if recLen < 4 || 5+recLen > len(record) {
		return info, ErrBadHello
	}
	b := record[5 : 5+recLen]
	if b[0] != 0x01 { // ClientHello handshake type
		return info, ErrBadHello
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	body := b[4:]
	if hsLen > len(body) {
		return info, ErrBadHello
	}
	p := body[:hsLen]

	if len(p) < 34 { // legacy_version(2) + random(32)
		return info, ErrBadHello
	}
	info.Random = clone(p[2:34])
	p = p[34:]

	sid, p, ok := take8(p) // session_id
	if !ok {
		return info, ErrBadHello
	}
	info.SessionID = clone(sid)

	if _, p2, ok := take16(p); ok { // cipher_suites
		p = p2
	} else {
		return info, ErrBadHello
	}
	if _, p2, ok := take8(p); ok { // compression_methods
		p = p2
	} else {
		return info, ErrBadHello
	}

	if len(p) < 2 { // no extensions block
		return info, nil
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return info, ErrBadHello
	}
	ext := p[:extLen]
	for len(ext) >= 4 {
		etype := uint16(ext[0])<<8 | uint16(ext[1])
		l := int(ext[2])<<8 | int(ext[3])
		ext = ext[4:]
		if len(ext) < l {
			return info, ErrBadHello
		}
		body := ext[:l]
		ext = ext[l:]
		switch etype {
		case extServerName:
			info.ServerName = parseSNI(body)
		case extKeyShare:
			info.X25519 = parseKeyShareX25519(body)
		}
	}
	return info, nil
}

// parseSNI returns the first host_name in a server_name extension, or "".
func parseSNI(ext []byte) string {
	list, _, ok := take16(ext) // ServerNameList
	if !ok {
		return ""
	}
	for len(list) >= 3 {
		nameType := list[0]
		nl := int(list[1])<<8 | int(list[2])
		list = list[3:]
		if len(list) < nl {
			return ""
		}
		if nameType == 0x00 { // host_name
			return string(list[:nl])
		}
		list = list[nl:]
	}
	return ""
}

// parseKeyShareX25519 returns the 32-byte X25519 share from a key_share extension, or
// nil. It skips GREASE and other groups (e.g. post-quantum hybrids) to find group 0x001d.
func parseKeyShareX25519(ext []byte) []byte {
	shares, _, ok := take16(ext) // client_shares
	if !ok {
		return nil
	}
	for len(shares) >= 4 {
		group := uint16(shares[0])<<8 | uint16(shares[1])
		dl := int(shares[2])<<8 | int(shares[3])
		shares = shares[4:]
		if len(shares) < dl {
			return nil
		}
		data := shares[:dl]
		shares = shares[dl:]
		if group == groupX25519 && len(data) == 32 {
			return clone(data)
		}
	}
	return nil
}

// take8 splits off a 1-byte-length-prefixed field; take16 a 2-byte-length-prefixed one.
func take8(p []byte) (field, rest []byte, ok bool) {
	if len(p) < 1 {
		return nil, p, false
	}
	n := int(p[0])
	if len(p) < 1+n {
		return nil, p, false
	}
	return p[1 : 1+n], p[1+n:], true
}

func take16(p []byte) (field, rest []byte, ok bool) {
	if len(p) < 2 {
		return nil, p, false
	}
	n := int(p[0])<<8 | int(p[1])
	if len(p) < 2+n {
		return nil, p, false
	}
	return p[2 : 2+n], p[2+n:], true
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }
