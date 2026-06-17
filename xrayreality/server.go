/*
 * Copyright (c) 2026 Karagatan LLC.
 * SPDX-License-Identifier: MPL-2.0
 *
 * The server is the genuine REALITY server from github.com/xtls/reality (© RPRX,
 * MPL-2.0); this file only maps configuration and key generation onto it. MPL-2.0; see
 * LICENSE in this directory.
 */

package xrayreality

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"time"

	reality "github.com/xtls/reality"
)

// ServerConfig configures the REALITY listener.
type ServerConfig struct {
	// PrivateKey is the server's static X25519 private key (32 bytes); its public key
	// is distributed to clients as ClientConfig.PublicKey.
	PrivateKey []byte

	// ShortIDs are the accepted client short ids (each <= 8 bytes; padded to 8).
	ShortIDs [][]byte

	// ServerNames are the borrowed SNIs the server accepts (others are passed through).
	ServerNames []string

	// Dest is the "host:port" of the real borrowed site. The server connects to it to
	// mirror its handshake and to which it passes unauthenticated connections through.
	// It must speak TLS 1.3.
	Dest string

	// MaxTimeDiff bounds the SessionID timestamp's distance from now (replay window);
	// 0 disables the check.
	MaxTimeDiff time.Duration

	// MinClientVer / MaxClientVer, if set (3 bytes each), gate the client version
	// embedded in the SessionID.
	MinClientVer []byte
	MaxClientVer []byte

	// Show enables the underlying library's verbose REALITY handshake logging (debug).
	Show bool
}

// Listener wraps base in a genuine REALITY server: Accept returns only authenticated
// tunnels, and unauthenticated connections are transparently relayed to Dest (so an
// active probe completes TLS against the real borrowed site). It is wire-compatible
// with Xray clients.
func Listener(base net.Listener, cfg ServerConfig) net.Listener {
	shortIDs := make(map[[8]byte]bool, len(cfg.ShortIDs))
	for _, s := range cfg.ShortIDs {
		var id [8]byte
		copy(id[:], s)
		shortIDs[id] = true
	}
	names := make(map[string]bool, len(cfg.ServerNames))
	for _, n := range cfg.ServerNames {
		names[n] = true
	}
	return reality.NewListener(base, &reality.Config{
		DialContext: (&net.Dialer{}).DialContext, // used to reach Dest; required (nil panics)
		Show:        cfg.Show,
		Type:        "tcp",
		// REALITY emits its own dummy NewSessionTicket (disguised as application data) to
		// mirror Dest. A full standard session ticket would not survive that disguising
		// and breaks the client's first read, so suppress the standard one.
		SessionTicketsDisabled: true,
		Dest:                   cfg.Dest,
		ServerNames:            names,
		PrivateKey:             cfg.PrivateKey,
		ShortIds:               shortIDs,
		MaxTimeDiff:            cfg.MaxTimeDiff,
		MinClientVer:           cfg.MinClientVer,
		MaxClientVer:           cfg.MaxClientVer,
	})
}

// GenerateKeyPair returns a new X25519 (privateKey, publicKey) pair in the raw 32-byte
// form REALITY uses: the private key feeds ServerConfig.PrivateKey, the public key
// feeds ClientConfig.PublicKey.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}
