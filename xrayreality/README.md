# obfs/xrayreality

**Wire-compatible** Xray REALITY transport. Its client interoperates with a genuine
Xray REALITY server, and its server *is* a genuine Xray REALITY server
([github.com/xtls/reality](https://github.com/XTLS/REALITY)).

```
go get go.arpabet.com/obfs/xrayreality
```

> **License: MPL-2.0** (not BUSL-1.1 like the rest of `obfs`). This module depends on
> and ports MPL-2.0 code from `xtls/reality` and Xray-core; see [LICENSE](LICENSE).

## When to use this vs. `obfs/xreality`

| | `obfs/xreality` | `obfs/xrayreality` (this) |
|---|---|---|
| Xray interop | ❌ no | ✅ yes |
| TLS stack | stock `crypto/tls` + uTLS | forked TLS (`xtls/reality`) |
| Server auth | post-handshake channel-bound HMAC | in-handshake forged certificate |
| Dependencies | uTLS only | uTLS + `xtls/reality` (heavier) |
| License | BUSL-1.1 | MPL-2.0 |

Use **`obfs/xreality`** unless you specifically need to talk to real Xray endpoints.

## Use

```go
import "go.arpabet.com/obfs/xrayreality"

// keys (server keeps priv; clients get pub) — or use Xray's own x25519 keys
priv, pub, _ := xrayreality.GenerateKeyPair()

// Server: authenticated tunnels come out of Accept; probes are relayed to Dest.
ln := xrayreality.Listener(baseTCP, xrayreality.ServerConfig{
    PrivateKey:  priv,
    ShortIDs:    [][]byte{shortID},        // <= 8 bytes each
    ServerNames: []string{"www.realsite.com"},
    Dest:        "www.realsite.com:443",   // the real borrowed site (must speak TLS 1.3)
    MaxTimeDiff: 90 * time.Second,
})

// Client:
dial := xrayreality.Dialer("tcp", serverAddr, xrayreality.ClientConfig{
    PublicKey:  pub,
    ShortID:    shortID,
    ServerName: "www.realsite.com",
    // Fingerprint defaults to Chrome
})
conn, err := dial()
```

It returns a `net.Conn` / a `net.Listener`, so it drops into value-rpc's
bring-your-own-connection seam exactly like the other obfs transports.

## How it works

This reproduces Xray's exact on-wire protocol:

- **Client** (`client.go`, a focused port of Xray-core's `reality.UClient`): a uTLS
  browser ClientHello whose X25519 key share is reused as the REALITY ephemeral; the
  32-byte SessionID is `[3B version][1B reserved][4B unix time][8B shortId]`,
  AES-256-GCM-sealed under `HKDF-SHA256(ECDH(serverPub, ephemeral), salt=random[:20],
  "REALITY")` with `nonce=random[20:]`, `AAD=ClientHello`. The server's forged
  certificate is verified by `HMAC-SHA512(authKey, ed25519Pub) == cert.Signature`.
- **Server** (`server.go`): the genuine `xtls/reality` listener — it authenticates the
  ClientHello, terminates TLS with a forged certificate for authenticated clients, and
  transparently relays everyone else (probes, scanners) to `Dest`, the real borrowed
  site, so probing reveals only that site.

## Testing & caveats

`xrayreality_test.go` verifies, end-to-end against the **genuine** `xtls/reality` server
(the exact code real Xray runs):

- `TestXray_AuthenticatedTunnel` — the ported client authenticates, verifies the server's
  forged certificate, and a full **application-data round-trip** succeeds.
- `TestXray_ProbePassthrough` — a plain TLS probe is relayed to `Dest` and sees that
  site's certificate.
- `TestXray_WrongKey` — a wrong server key fails the HMAC verification.

Two things are load-bearing for interop and are handled here: the client pins the **same
uTLS build Xray uses** (a post-v1.8.2 commit — released v1.8.2 mis-parses the server's
disguised post-handshake record), and the server sets `SessionTicketsDisabled` so it emits
only REALITY's dummy (disguised) NewSessionTicket rather than a full one. As with all of
`obfs`, run a traffic shaper **inside** the tunnel (REALITY only hides the handshake) and
use responsibly. See [REALITY.md](../REALITY.md) for the full design.
