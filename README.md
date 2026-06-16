# obfs

Carrier-agnostic **traffic-shaping middleware** for Go byte streams. `obfs` wraps
any `net.Conn` and re-frames the bytes into fixed-size cells with padding, optional
timing jitter, and optional cover (chaff) traffic, so a network observer cannot
fingerprint your application's operations by their **packet sizes and timing**.

The **core depends on nothing outside the standard library**; heavier techniques
(uTLS, pion) live in optional submodules that isolate their own dependencies.
Everything composes with [value-rpc](https://go.arpabet.com/value-rpc), gRPC, plain
`net/http`, or anything else that hands it a `net.Conn`.

> **Responsible use.** Traffic obfuscation is legitimate and important for
> people living under network censorship — and it is
> **dual-use**. Do not use it to evade authorized security monitoring or in
> violation of applicable law. Whether running such software is lawful varies by
> jurisdiction; that is the deployer's responsibility.

## Why

Content encryption (TLS) hides **what** you send, but not the **size and timing**
of each message — and per-operation size/timing is often enough to tell *which*
request ran or *which* page loaded, even inside a TLS tunnel. The modern lesson
from censorship research (2023→2025) is also that "look like uniformly random
bytes" *lost* — fully-encrypted-traffic detectors now block exactly that. So the
goal is to **stop leaking operation structure** and to **control the byte
distribution**, not to maximize randomness.

`obfs` makes every write look identical on the wire (fixed cells, the same idea as
Tor's 514-byte cells), pads idle periods with cover traffic, and lets you choose
the padding byte profile.

## Threat model — what each piece defends against

A censor escalates across three largely independent problems; the obfs pieces are
composable layers, each targeting a different one. None is sufficient alone —
combine the layers that match your adversary.

| Censor move | What it keys on | obfs answer |
|---|---|---|
| **Passive DPI / flow analysis** | packet sizes, timing, entropy; TLS JA3/JA4 | core shaper + **morpher** (size/timing distribution) + **FRONT**/**RegulaTor pacing** (burst defense), **tlscamo** (browser TLS fingerprint), **WrapPacket** (UDP/QUIC datagram obfuscation) |
| **Active probing** | connecting to the server and checking it behaves like its cover story | **reality** — unauthenticated probes are reverse-proxied to a real fallback site |
| **Endpoint blocking** | a static server IP / port / SNI | **hop** (rotate ports), **webrtc** (peer-to-peer data channel reached via a broker) |

## What's here

| Package | What it does | Deps |
|---------|--------------|------|
| `obfs` | fixed-cell shaper (`Wrap`), length padding, timing jitter, cover traffic, pluggable `Fill` (random / printable / zero), **distribution-matching morpher** (`SizeSampler`/`DelaySampler`), **FRONT adaptive padding** (`Front`), and **datagram obfuscation** for UDP/QUIC (`WrapPacket`) | stdlib only |
| `obfs/hop` | port/address hopping — client rotates destinations on a time schedule, server listens on all of them | stdlib only |
| `obfs/tlscamo` | **uTLS ClientHello mimicry** — TLS client whose JA3/JA4 matches a real browser, with ALPN, fingerprint rotation, and optional **Encrypted ClientHello (ECH)** to hide the SNI (separate module) | `refraction-networking/utls` |
| `obfs/reality` | **Trojan-style active-probe defense** — token-authenticated TLS tunnel; unauthenticated probes are reverse-proxied to a real fallback site, plus optional **SNI-passthrough** (wrong-SNI scanners get raw-spliced to a real upstream's genuine cert) (separate module) | `obfs/tlscamo` (→ utls) |
| `obfs/webrtc` | **Snowflake-style WebRTC data channel** — carry a `net.Conn` over a WebRTC data channel (looks like a call); pluggable signaling, no built-in broker (separate module) | `pion/webrtc` |

## Install

```
go get go.arpabet.com/obfs
```

## Use

### Shape a connection

```go
import "go.arpabet.com/obfs"

shaped := obfs.Wrap(baseConn, obfs.Policy{
    CellSize:   512,                    // every wire frame is exactly 512 bytes
    Jitter:     2 * time.Millisecond,   // decorrelate timing (costs latency)
    CoverEvery: 50 * time.Millisecond,  // chaff when idle (costs bandwidth)
    Fill:       obfs.RandomFill,        // or obfs.PrintableFill under cleartext
})
// run any protocol over `shaped`; the peer must Wrap with the same CellSize.
```

### Distribution-matching morpher

Fixed cells make every frame *identical*; the morpher instead makes the size
distribution *match a cover protocol*, which can blend better than a single uniform
size. Set a `SizeSampler` (this switches on a self-describing wire framing, so
**both peers must set one**):

```go
shaped := obfs.Wrap(baseConn, obfs.Policy{
    // sizes drawn to resemble a cover protocol's packets instead of a fixed cell
    SizeSampler:  obfs.SampledSize(map[int]float64{1300: 6, 600: 2, 120: 1}),
    DelaySampler: obfs.PoissonDelay(3 * time.Millisecond), // less-regular timing
    CoverEvery:   50 * time.Millisecond,
})
// obfs.UniformSize(min, max) is the simplest sampler when you have no profile.
```

### FRONT adaptive padding

`CoverEvery` is constant-rate chaff sent only while idle. `Front` instead front-loads
a randomized burst of dummy cells at the start of the connection — where a trace
leaks the most to website-fingerprinting — at Rayleigh-distributed times. It is
sender-side and composes with the rest of the policy:

```go
shaped := obfs.Wrap(baseConn, obfs.Policy{
    CellSize: 512,
    Front:    &obfs.FrontConfig{Window: 2 * time.Second, MaxCount: 30}, // up to 30 dummy cells
})
```

### RegulaTor-style send pacing

FRONT adds traffic-*independent* padding; it does not reshape your own bursts. `Paced`
does: a background pacer releases cells at a controlled rate that decays over time
(like a real page load), queueing real data and filling idle slots with cover, so the
*burst pattern* — the strongest fingerprinting signal — stops leaking. `Write`
back-pressures to the rate. It supersedes `CoverEvery`/`Front` (the pacer owns all
writes) and trades latency/bandwidth for unlinkability:

```go
shaped := obfs.Wrap(baseConn, obfs.Policy{
    CellSize: 512,
    Paced:    &obfs.PacedConfig{Rate: 1000, Decay: 0.94, MinRate: 50}, // cells/sec, decaying
})
```

### Datagram obfuscation (UDP / QUIC)

For datagram carriers, `WrapPacket` obfuscates each UDP datagram (Salamander-style:
per-packet salt + AES-256-CTR under a PSK), so a censor sees pseudo-random packets
instead of, say, a QUIC long-header. An optional `Pad` sampler shapes packet
*lengths* too. Wrap the UDP socket and hand it to a QUIC transport:

```go
udp, _ := net.ListenPacket("udp", ":0")
pc := obfs.WrapPacket(udp, obfs.PacketPolicy{
    Key: psk,                          // same on both peers
    Pad: obfs.UniformSize(1200, 1400), // optional length shaping
})
// give pc to your QUIC transport (e.g. value-rpc/quic); QUIC's TLS rides inside.
```

It is obfuscation, not a secure channel (unauthenticated AES-CTR — no integrity);
keep a real tunnel (QUIC's own TLS) inside it.

### With value-rpc (bring-your-own-connection seam)

```go
// Client
dialer := valuerpc.NewFuncDialer(func() (io.ReadWriteCloser, error) {
    base, err := net.Dial("tcp", addr) // ideally a TLS conn — see caveats
    if err != nil {
        return nil, err
    }
    return obfs.Wrap(base, policy), nil
}, valueclient.DefaultTimeout)
cli := valueclient.NewClientWithDialer(dialer)

// Server
base, _ := net.Listen("tcp", addr)
shaped := obfs.Listener(base, policy)
lis := valuerpc.NewAcceptListener(
    func() (io.ReadWriteCloser, error) { return shaped.Accept() },
    base.Addr(), base.Close, valueserver.DefaultTimeout)
srv, _ := valueserver.NewServerWithListener(lis, logger)
```

### TLS fingerprint mimicry (`obfs/tlscamo`)

Make the TLS handshake look like a real browser (so a censor fingerprinting JA3/JA4
sees Chrome, not Go). It is a **separate module** (`go.arpabet.com/obfs/tlscamo`,
dep: uTLS) and must be the **outermost** layer — wrap the raw TCP conn, and put any
`obfs` shaping *inside* the tunnel. The server stays a standard `crypto/tls` server.

```go
import "go.arpabet.com/obfs/tlscamo"

dialer := valuerpc.NewFuncDialer(func() (io.ReadWriteCloser, error) {
    raw, err := net.Dial("tcp", addr)
    if err != nil {
        return nil, err
    }
    // browser-like ClientHello (outermost); shape inside with obfs.Wrap(conn, …) if desired
    return tlscamo.Client(raw, tlscamo.Config{ServerName: "example.com", Fingerprint: tlscamo.Chrome})
}, valueclient.DefaultTimeout)
```

To also hide the **SNI** from a censor that blocks on plaintext server names, set
`ECHConfigList` (Encrypted ClientHello). Fetch the serialized config from the
target's DNS HTTPS/SVCB `ech=` record; ECH needs TLS 1.3 and only succeeds if the
server negotiates it:

```go
tlscamo.Config{ServerName: "example.com", Fingerprint: tlscamo.Chrome, ECHConfigList: echList}
```

### Active-probe defense (`obfs/reality`)

Trojan-style: the server terminates TLS with a real cert for the domain it fronts
and expects a pre-shared token as the first bytes; authenticated clients get the
tunnel, while active probes (and stray browsers) are transparently
**reverse-proxied to a real fallback site** — so probing the server just shows a
genuine website. The client reuses `tlscamo` for the browser fingerprint.

```go
import "go.arpabet.com/obfs/reality"

// Server: only authenticated tunnels come out of Accept; probes go to Fallback.
rl := reality.Listener(baseTCP, reality.ServerConfig{
    TLSConfig: tlsConf,            // real cert for the fronted domain; leave ALPN empty
    Token:     token,              // pre-shared, >= 16 random bytes
    Fallback:  "127.0.0.1:8080",   // a real HTTP origin (e.g. servion's HTTP server)
})

// Client:
dial := reality.Dialer("tcp", addr, reality.ClientConfig{
    TLS:   tlscamo.Config{ServerName: "example.com", Fingerprint: tlscamo.Chrome},
    Token: token,
})
```

This is Trojan-grade (server presents its own cert) — not the full Xray REALITY
(which borrows an unrelated site's cert); see the package doc. With **servion**,
point `Fallback` at the HTTP server servion already runs, so the decoy is real.

Set `ServerNames` + `Passthrough` to additionally peek each ClientHello and
raw-splice any connection whose SNI doesn't match to a real TLS upstream, so
IP-range scanners using the wrong SNI see that upstream's genuine certificate, not
yours. The full REALITY protocol — and how it would be built across obfs, servion,
and value-rpc — is designed in [REALITY.md](REALITY.md).

### REALITY auth core (`obfs/xreality`)

The full REALITY transport's hard part is TLS-stack surgery, which isn't responsibly
one-shottable. But its security-critical, TLS-independent core is — so `obfs/xreality`
implements and fully tests exactly that piece, de-risking the rest of Phase 1.

A separate, **stdlib-only, zero-dependency** module:

- `GenerateX25519()` — X25519 keypairs (`crypto/ecdh`).
- `ClientSessionID(serverPub, clientEphemeral, clientRandom, shortID)` — ECDH →
  HKDF-SHA256 auth key → AES-256-GCM-sealed 32-byte SessionID (the auth token smuggled
  in the ClientHello), bound to the ClientHello random as AAD/nonce.
- `ServerAuthenticate(serverPriv, clientPub, clientRandom, sessionID, accept, skew)` —
  reconstructs the auth key, AEAD-verifies, enforces the replay window, gates the
  shortId, and returns the key for the cert binding. Returns a bare `ok bool` so a
  probe and a malformed client are indistinguishable.
- `CertHMAC(authKey, ed25519Pub)` — the HMAC-SHA512 cert-binding signature (TLS 1.3
  encrypts the cert, so only authenticated clients ever see/verify it).
- `ParseClientHello(record)` + `Authenticate(...)` — the server **decision pipeline**:
  a strict, bounds-checked ClientHello parser (random / session id / SNI / X25519 share)
  composed with `ServerAuthenticate` to classify a peeked ClientHello as authenticated
  (→ terminate) or a probe (→ pass through).

Deliberately **not** wire-compatible with Xray (both peers are ours), so the layout is
clean: `SessionID = AES-256-GCM(plaintext=[8B time][8B shortId])` exactly filling the
32-byte field. The crypto core and the server decision pipeline are done; what remains
is the live TLS plumbing (uTLS ClientHello injection + a forged-certificate TLS path),
which needs a vendored/forked TLS stack — see [REALITY.md](REALITY.md).

### WebRTC data channel (`obfs/webrtc`)

Carry the connection over a WebRTC data channel so it looks like a call (the
Snowflake idea). It's a **separate module** (`go.arpabet.com/obfs/webrtc`, dep:
pion) and **does not include a broker** — you provide the signaling (SDP exchange):
a `Signaler` on the client and an `OfferSource` on the server. That rendezvous is a
control-plane concern (servion, an HTTP broker, domain fronting, …).

```go
import "go.arpabet.com/obfs/webrtc"

// Client (signaler talks to your broker; non-trickle ICE → one offer/answer exchange)
conn, err := webrtc.Dial(ctx, signaler, webrtc.Config{
    ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
})

// Server: Accept yields a net.Conn per answered offer from the source
ln, _ := webrtc.Listener(offerSource, webrtc.Config{})
```

### Port hopping

```go
import "go.arpabet.com/obfs/hop"

// Server: listen on every candidate port at once.
lis, _ := hop.MultiListener([]string{":4001", ":4002", ":4003"}, nil)

// Client: rotate destination by time window.
dial, _ := hop.Dialer([]string{"host:4001", "host:4002", "host:4003"},
    30*time.Second, nil)
conn, _ := dial()
```

## Composing the layers

The pieces are `net.Conn` middleware, so they stack. Order matters: the
fingerprint-bearing TLS/WebRTC layer must be **outermost** (it is what the censor
sees on the wire), and traffic shaping goes **inside** the encrypted tunnel.

```
  value-rpc / gRPC / HTTP             your protocol (innermost)
        │
  obfs shaping (cells / morpher /     hide per-operation size & timing,
        │        cover)               INSIDE the encrypted tunnel
  TLS + tlscamo   (or reality)        confidentiality + browser-like handshake;
        │                             the OUTERMOST visible layer
  TCP  /  obfs/hop  /  obfs/webrtc    reachability & rendezvous
        │
     the network
```

Wiring that whole stack into value-rpc's bring-your-own-connection seam:

```go
hopDial, _ := hop.Dialer(addrs, 30*time.Second, nil)
dialer := valuerpc.NewFuncDialer(func() (io.ReadWriteCloser, error) {
    base, err := hopDial() // reachability / rendezvous
    if err != nil {
        return nil, err
    }
    tlsConn, err := tlscamo.Client(base, tlscamo.Config{ServerName: "example.com"})
    if err != nil { // outermost, browser-like TLS handshake
        base.Close()
        return nil, err
    }
    return obfs.Wrap(tlsConn, policy), nil // shaping inside the tunnel
}, valueclient.DefaultTimeout)
```

Rules of thumb: apply every layer **symmetrically** on both peers; always keep a
real **TLS** layer (`tlscamo` or `reality`) — obfs shaping is not encryption; and
add only the layers your threat model needs, since each costs latency, bandwidth,
or dependencies.

## Caveats

- **Not encryption.** The shaper does not hide your content. **Run it under TLS**
  (or another vetted secure channel); a shaping layer over plaintext is a privacy
  illusion.
- **Symmetric.** Both peers must `Wrap` with matching framing — the same `CellSize`
  in fixed mode, or both setting a `SizeSampler` in morpher mode.
- **It is an arms race.** Today's cover is tomorrow's signature. Keep policies
  tunable and disposable; track the upstream pluggable-transport ecosystem.
- **Real cost.** Fixed cells, jitter, and chaff trade bandwidth and latency for
  unlinkability. Keep them opt-in and sized to the workload.
- **Pin your dependencies.** Browser TLS fingerprints and the pion API drift; pin
  the `utls`/`pion` versions and refresh `tlscamo` presets so a stale fingerprint
  doesn't itself become the signature.

## Status

The planned techniques are all implemented, each dependency-bearing one as a
**separate sub-module** so importing the zero-dep core never pulls it in (the same
discipline `value-rpc/quic` uses for `quic-go`):

- ✅ `obfs` core — fixed-cell shaper + **distribution-matching morpher** (`SizeSampler`/`DelaySampler`), **FRONT adaptive padding** + **RegulaTor-style pacing** (`Paced`), cover traffic, fills, and **datagram obfuscation** (`WrapPacket`) for UDP/QUIC — zero deps.
- ✅ `obfs/hop` — port/address hopping — zero deps.
- ✅ `obfs/tlscamo` — uTLS ClientHello mimicry + ALPN + fingerprint rotation + optional ECH (SNI encryption).
- ✅ `obfs/reality` — Trojan-style active-probe defense (token auth + fallback + optional SNI-passthrough). Full REALITY design: [REALITY.md](REALITY.md).
- 🚧 `obfs/xreality` — REALITY **auth crypto core** (X25519/HKDF/AEAD SessionID + cert-binding HMAC) **and server decision pipeline** (`ParseClientHello` + `Authenticate`), stdlib only; the live TLS plumbing is still open — see [REALITY.md](REALITY.md).
- ✅ `obfs/webrtc` — Snowflake-style WebRTC data-channel transport.

Composition (the layers stack; apply from the wire inward): port hopping →
WebRTC/TLS-mimicry (outermost, visible) → traffic shaping (inside the tunnel) →
your protocol. The rendezvous/broker and per-carrier DI wiring live above obfs (in
servion or your app), not here.

See [value-rpc TRANSPORTS.md §10–§11](https://go.arpabet.com/value-rpc) for the
threat model and the layering rationale (value-rpc seam vs. `obfs` vs. higher-level
orchestration).

## References

The designs follow established censorship-circumvention work:

- **uTLS** — TLS ClientHello fingerprint mimicry: <https://github.com/refraction-networking/utls>
- **pion/webrtc** — WebRTC data channels in Go: <https://github.com/pion/webrtc>
- **Tor Snowflake** — WebRTC-proxy pluggable transport: <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake>
- **Trojan / Xray REALITY** — probe-resistant fronting & fallback: <https://xtls.github.io/en/config/features/fallback.html>

## License

BUSL-1.1 — see [LICENSE](LICENSE).
