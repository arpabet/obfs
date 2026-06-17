# fullstack example — hop + tlscamo + shaping

Composes three `obfs` layers in one process over a plain echo service:

```
client:  hop.Dialer ─▶ tlscamo.Client (outermost) ─▶ obfs.Wrap (shaping, inside)
server:  hop.MultiListener ─▶ crypto/tls server    ─▶ obfs.Wrap (shaping, inside)
```

```bash
GOWORK=off go run .
```

Output:

```
hopped 3 addresses, browser-mimicked TLS, shaped into 512-byte cells:
  echo -> "hello through hop + tlscamo + shaping"
```

## What it shows

- **`obfs/hop`** — the server listens on three addresses; the client rotates across them.
- **`obfs/tlscamo`** — the client's TLS handshake mimics Chrome (the server is an
  ordinary `crypto/tls` server).
- **`obfs` shaping** — both ends `obfs.Wrap` the tunnel with the same `Policy` (fixed
  512-byte cells + FRONT padding), *inside* the encrypted tunnel.

The layering rule: the fingerprint-bearing TLS layer is **outermost** (what a censor
sees on the wire), traffic shaping goes **inside** the tunnel, and every layer is applied
**symmetrically** on both peers.

## Notes

It's a separate module so the uTLS dependency (via `tlscamo`) never enters the
zero-dependency `obfs` core; `GOWORK=off` builds it against its `replace` directives. In
production, split client and server, use a real certificate, and add only the layers your
threat model needs. See the [obfs overview](../../README.md) and
[REALITY.md](../../REALITY.md).
