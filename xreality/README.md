# obfs/xreality

A **REALITY-style transport** that needs **no forked TLS stack**. A browser-mimicked
(uTLS) TLS handshake to a *borrowed* real site, with authentication smuggled in the
ClientHello so the server decides — *before* terminating TLS — whether to serve the
tunnel or splice the connection through to the real site. Server identity is proven by a
**post-handshake channel-bound HMAC** instead of a forged certificate, so it runs on
stock `crypto/tls` + the uTLS public API.

```
go get go.arpabet.com/obfs/xreality
```

> Depends on [`refraction-networking/utls`](https://github.com/refraction-networking/utls).
> **Not** wire-compatible with Xray — for that use [`obfs/xrayreality`](../xrayreality).
> See the comparison and full design in [REALITY.md](../REALITY.md).

## Use

```go
import "go.arpabet.com/obfs/xreality"

priv, _ := xreality.GenerateX25519() // server static key; clients get priv.PublicKey().Bytes()

// Server: authenticated tunnels come out of Accept; probes are raw-spliced to Dest.
ln := xreality.Listener(baseTCP, xreality.ServerConfig{
    PrivateKey: priv,
    ShortIDs:   [][]byte{shortID},                // <= 8 bytes each
    TLSConfig:  &tls.Config{Certificates: certs}, // self-signed for the borrowed SNI is fine
    Dest:       "www.realsite.com:443",           // real borrowed site for probe passthrough
    TimeSkew:   90 * time.Second,                 // replay window
})

// Client:
dial := xreality.Dialer("tcp", serverAddr, xreality.ClientConfig{
    ServerPublicKey: priv.PublicKey().Bytes(),
    ShortID:         shortID,
    ServerName:      "www.realsite.com",
    // Fingerprint defaults to Chrome
})
conn, err := dial()
```

`Client`/`Listener` return a `net.Conn` / `net.Listener`, so this drops into value-rpc's
bring-your-own-connection seam like the other obfs transports. A runnable end-to-end demo
(with traffic shaping inside the tunnel) lives in
[`servion/vrpc/examples/xreality`](https://go.arpabet.com/servion).

## How it works

- **SessionID** = `AES-256-GCM([8B time][8B shortId])` exactly filling the 32-byte field,
  keyed by `HKDF-SHA256(ECDH(serverPub, ClientHello X25519 share), salt=random, info)`.
- The server peeks the ClientHello (`ParseClientHello` + `Authenticate`), routing
  authenticated clients to a TLS terminator and probes to a raw splice to `Dest`.
- After the handshake, both sides exchange `HMAC(authKey, tag‖ExportKeyingMaterial())` —
  a channel-bound proof that defeats a MITM, replacing REALITY's in-handshake forged
  certificate (so no TLS fork is needed). It is invisible to a censor (inside TLS 1.3).

The auth core (`GenerateX25519`, `ClientSessionID`, `ServerAuthenticate`, `CertHMAC`) and
the server decision pipeline (`ParseClientHello`, `Authenticate`) are exported for reuse.

## Caveats

- REALITY only hides the **handshake** — run an `obfs` traffic shaper *inside* the tunnel
  to also defend the post-handshake traffic shape (see [REALITY.md §8](../REALITY.md)).
- Pick `Dest` carefully (TLS 1.3, high-reputation, not co-located with you); enforce
  `TimeSkew`. Camouflage, not anonymity. **Dual-use**; see the [root README](../README.md).
