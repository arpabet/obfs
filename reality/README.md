# obfs/reality

**Trojan-style active-probe defense.** The server terminates TLS with a real certificate
for the domain it fronts and expects a pre-shared token as the first bytes inside the
tunnel. Authenticated clients get the tunnel; everyone else — active probes, scanners, a
stray browser — is transparently **reverse-proxied to a real fallback site**, so probing
the server just reveals a genuine website. A separate module; the client reuses
[`obfs/tlscamo`](../tlscamo) for the browser fingerprint.

```
go get go.arpabet.com/obfs/reality
```

> Depends on `obfs/tlscamo` (→ uTLS).

## Use

```go
import "go.arpabet.com/obfs/reality"

// Server: only authenticated tunnels come out of Accept; probes go to Fallback.
rl := reality.Listener(baseTCP, reality.ServerConfig{
    TLSConfig: tlsConf,          // real cert for the fronted domain; leave ALPN empty
    Token:     token,            // pre-shared, >= 16 random bytes
    Fallback:  "127.0.0.1:8080", // a real HTTP origin probes are reverse-proxied to
})

// Client:
dial := reality.Dialer("tcp", addr, reality.ClientConfig{
    TLS:   tlscamo.Config{ServerName: "example.com", Fingerprint: tlscamo.Chrome},
    Token: token,
})
```

### SNI passthrough (toward REALITY)

Add `ServerNames` + `Passthrough` to peek each ClientHello and raw-splice any connection
whose SNI does **not** match to a real TLS upstream — so wrong-SNI scanners terminate TLS
against that upstream's genuine certificate, not yours:

```go
reality.ServerConfig{
    TLSConfig:   tlsConf, Token: token,
    ServerNames: []string{"example.com"},
    Passthrough: "real-upstream:443",
}
```

## Scope & caveats

- This is **Trojan-grade** (the server presents its *own* certificate), not full Xray
  REALITY (which borrows an unrelated site's cert). For the full protocol see
  [`obfs/xreality`](../xreality) (channel-bound, no TLS fork) and
  [`obfs/xrayreality`](../xrayreality) (Xray-wire-compatible), and the design in
  [REALITY.md](../REALITY.md).
- Provides camouflage plus standard TLS confidentiality/authentication — not anonymity.
  The `Token` must be kept secret. **Dual-use**; see the [root README](../README.md).

See the [obfs overview](../README.md) for layering with hop and traffic shaping.
