/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package xreality

import (
	"bytes"
	"testing"
	"time"
)

type share struct {
	group uint16
	data  []byte
}

func u16(b *bytes.Buffer, v int) { b.WriteByte(byte(v >> 8)); b.WriteByte(byte(v)) }

// buildClientHello assembles a minimal but structurally valid TLS 1.3 ClientHello
// record, for exercising the parser and the server decision pipeline without uTLS.
func buildClientHello(random, sessionID []byte, serverName string, shares []share) []byte {
	var exts bytes.Buffer
	if serverName != "" {
		var entry bytes.Buffer
		entry.WriteByte(0x00) // host_name
		u16(&entry, len(serverName))
		entry.WriteString(serverName)
		u16(&exts, int(extServerName))
		u16(&exts, entry.Len()+2)
		u16(&exts, entry.Len())
		exts.Write(entry.Bytes())
	}
	if shares != nil {
		var list bytes.Buffer
		for _, s := range shares {
			u16(&list, int(s.group))
			u16(&list, len(s.data))
			list.Write(s.data)
		}
		u16(&exts, int(extKeyShare))
		u16(&exts, list.Len()+2)
		u16(&exts, list.Len())
		exts.Write(list.Bytes())
	}

	var body bytes.Buffer
	body.WriteByte(0x03)
	body.WriteByte(0x03) // legacy_version
	body.Write(random)
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	u16(&body, 2)
	body.WriteByte(0x13)
	body.WriteByte(0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body.WriteByte(1)
	body.WriteByte(0x00) // compression: null
	u16(&body, exts.Len())
	body.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	hs.WriteByte(byte(body.Len() >> 16))
	hs.WriteByte(byte(body.Len() >> 8))
	hs.WriteByte(byte(body.Len()))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.WriteByte(0x03)
	rec.WriteByte(0x03)
	u16(&rec, hs.Len())
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// TestParse_Fields: the parser recovers random, session id, SNI, and the X25519 share,
// skipping a GREASE key-share group to find group 0x001d.
func TestParse_Fields(t *testing.T) {
	random := randomBytes(t, ClientRandomLen)
	sid := randomBytes(t, sessionIDLen)
	x := randomBytes(t, 32)
	rec := buildClientHello(random, sid, "www.example.com", []share{
		{0x0a0a, randomBytes(t, 16)}, // GREASE-ish, skipped
		{groupX25519, x},
	})

	info, err := ParseClientHello(rec)
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if !bytes.Equal(info.Random, random) {
		t.Fatal("random mismatch")
	}
	if !bytes.Equal(info.SessionID, sid) {
		t.Fatal("session id mismatch")
	}
	if info.ServerName != "www.example.com" {
		t.Fatalf("SNI = %q", info.ServerName)
	}
	if !bytes.Equal(info.X25519, x) {
		t.Fatal("X25519 share mismatch")
	}
}

// TestParse_Optional: a ClientHello with neither SNI nor key share parses with those
// fields empty (not an error).
func TestParse_Optional(t *testing.T) {
	info, err := ParseClientHello(buildClientHello(randomBytes(t, ClientRandomLen), nil, "", nil))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if info.ServerName != "" || info.X25519 != nil {
		t.Fatalf("expected empty SNI/keyshare, got %q / %x", info.ServerName, info.X25519)
	}
}

// TestParse_Errors: non-TLS and truncated records are rejected without panicking.
func TestParse_Errors(t *testing.T) {
	if _, err := ParseClientHello([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0x00}); err != ErrNotTLS {
		t.Fatalf("non-handshake: got %v, want ErrNotTLS", err)
	}
	full := buildClientHello(randomBytes(t, ClientRandomLen), randomBytes(t, 8), "a", []share{{groupX25519, randomBytes(t, 32)}})
	for _, n := range []int{6, 12, 40, len(full) - 1} {
		if _, err := ParseClientHello(full[:n]); err == nil {
			t.Fatalf("truncated to %d bytes parsed without error", n)
		}
	}
}

// TestAuthenticate_Valid: a ClientHello built from ClientSessionID authenticates at
// the matching server, yielding the auth key and parsed SNI.
func TestAuthenticate_Valid(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	random := randomBytes(t, ClientRandomLen)

	sid, clientKey, err := ClientSessionID(server.PublicKey().Bytes(), client, random, []byte("cohort01"))
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}
	rec := buildClientHello(random, sid, "www.realsite.com", []share{{groupX25519, client.PublicKey().Bytes()}})

	d, err := Authenticate(server, rec, func([]byte) bool { return true }, time.Minute)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !d.Authenticated {
		t.Fatal("valid REALITY ClientHello was not authenticated")
	}
	if !bytes.Equal(d.AuthKey, clientKey) {
		t.Fatal("server auth key != client auth key")
	}
	if d.Info.ServerName != "www.realsite.com" {
		t.Fatalf("SNI = %q", d.Info.ServerName)
	}
}

// TestAuthenticate_Probe: an ordinary ClientHello (random session id, unrelated key
// share) is not authenticated and yields no error — the caller passes it through.
func TestAuthenticate_Probe(t *testing.T) {
	server := mustKey(t)
	rec := buildClientHello(
		randomBytes(t, ClientRandomLen),
		randomBytes(t, sessionIDLen),
		"www.realsite.com",
		[]share{{groupX25519, mustKey(t).PublicKey().Bytes()}},
	)
	d, err := Authenticate(server, rec, func([]byte) bool { return true }, time.Minute)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if d.Authenticated {
		t.Fatal("a probe ClientHello was wrongly authenticated")
	}
}

// TestAuthenticate_WrongShortID: an authenticated token whose shortId is not accepted
// is treated as a probe.
func TestAuthenticate_WrongShortID(t *testing.T) {
	server := mustKey(t)
	client := mustKey(t)
	random := randomBytes(t, ClientRandomLen)
	sid, _, err := ClientSessionID(server.PublicKey().Bytes(), client, random, []byte("cohortAA"))
	if err != nil {
		t.Fatalf("ClientSessionID: %v", err)
	}
	rec := buildClientHello(random, sid, "x", []share{{groupX25519, client.PublicKey().Bytes()}})

	d, err := Authenticate(server, rec, func(s []byte) bool { return bytes.Equal(s, []byte("cohortBB")) }, time.Minute)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if d.Authenticated {
		t.Fatal("unaccepted shortId was authenticated")
	}
}
