# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/). The repository is a multi-module
workspace: the zero-dependency core (`go.arpabet.com/obfs`, including `obfs/hop`)
and the dependency-bearing submodules (`obfs/tlscamo`, `obfs/reality`,
`obfs/webrtc`) are versioned and tagged independently — entries below note which
module a change applies to.

## [Unreleased]

## [0.2.0] — 2026-06-16

Coordinated release. Per-module tags: **`v0.2.0`** (core + `hop`),
**`tlscamo/v0.2.0`**, **`reality/v0.2.0`**, and the new **`xreality/v0.1.0`** and
**`xrayreality/v0.1.0`**; `webrtc` stays at `v0.1.0` (unchanged). The
distribution-matching morpher (`SizeSampler`/`DelaySampler`), committed after the
`v0.1.0` tag, also ships in core `v0.2.0`.

### Added

- **Datagram obfuscation** (`obfs.WrapPacket`, `PacketPolicy`) in the zero-dep core
  — a Salamander-style (Hysteria2) `net.PacketConn` wrapper that encrypts each
  datagram under a PSK with a per-datagram salt (AES-256-CTR over
  `[8B salt][2B len][data][pad]`), so a passive observer sees only pseudo-random
  packets. An optional `Pad` size sampler grows datagrams to a cover distribution
  (the datagram analogue of the stream morpher). Pairs with a QUIC transport: wrap
  the UDP `PacketConn` and hand it to the transport. Obfuscation only — no integrity.
- **FRONT adaptive padding** (`Policy.Front`, `FrontConfig`) in the core stream
  shaper — front-loads a randomized budget of dummy cells at Rayleigh-distributed
  times over a window, blunting website-fingerprinting on the early part of a trace
  (Gong & Wang, USENIX Security 2020). Sender-side, composes with `CoverEvery`.
- **RegulaTor-style send pacing** (`Policy.Paced`, `PacedConfig`) in the core stream
  shaper — a background pacer releases cells at a controlled, decaying rate instead
  of when `Write` is called, smoothing traffic *bursts* (the part FRONT and the
  morpher leave untouched) into a shape-independent schedule; queued real cells are
  paced out, idle slots are filled with cover, and `Write` back-pressures to the rate
  (Holland & Hopper, PETS 2022). Supersedes `CoverEvery`/`Front`; `Close` flushes the
  queue.
- **`obfs/xreality`** (new submodule) — the REALITY authentication crypto core
  (stdlib only): X25519 ECDH, HKDF-SHA256 auth-key derivation, AES-256-GCM SessionID
  seal/open bound to the ClientHello random, replay-window check, and the
  certificate-binding HMAC (`ClientSessionID`, `ServerAuthenticate`, `CertHMAC`). This
  is REALITY.md Phase 1a — the TLS-independent, security-critical part.
  Phase 1b-i adds the server **decision pipeline**: `ParseClientHello` (a strict,
  bounds-checked extractor of the random / session id / SNI / X25519 key share) and
  `Authenticate` (parse → ECDH → AEAD verify → replay window → shortId gate → route).
  Phase 1b-ii adds the **live transport** (`Client` / `Dialer` / `Listener`): the
  client mimics a browser ClientHello (uTLS), reuses its X25519 key share as the REALITY
  ephemeral, and injects the sealed SessionID; the server peeks the ClientHello, routes
  authenticated clients to a TLS terminator and probes to a raw splice to `Dest` (the
  real borrowed site). Server identity is proven by a **post-handshake channel-bound
  HMAC** over TLS exporter keying material — which replaces REALITY's in-handshake
  forged certificate, so it runs on stock `crypto/tls` + uTLS with **no TLS fork**. Not
  wire-compatible with Xray (both peers are ours); adds a uTLS dependency.
- **`obfs/xrayreality`** (new **MPL-2.0** submodule) — a **wire-compatible** Xray REALITY
  transport. The server is the genuine `github.com/xtls/reality` listener; the client is a
  focused port of Xray-core's `reality.UClient` (uTLS ClientHello with the X25519 key share
  reused as the REALITY ephemeral, the AES-256-GCM-sealed SessionID, and HMAC-SHA512 forged-
  certificate verification). It is MPL-2.0 (not BUSL) because it depends on / ports MPL code.
  Use `obfs/xreality` unless you must interoperate with real Xray endpoints. Tests verify a
  full application-data round-trip against the genuine server (plus probe passthrough and
  wrong-key rejection). Two interop details are handled: the client pins the same uTLS build
  Xray uses (released v1.8.2 mis-parses the server's disguised post-handshake record), and the
  server sets `SessionTicketsDisabled` so it emits only REALITY's dummy (disguised) ticket.
- **SNI-passthrough** in `obfs/reality` (`ServerConfig.ServerNames` + `Passthrough`)
  — the listener peeks each ClientHello and raw-splices any connection whose SNI does
  not match to a real TLS upstream, so probes/IP-range scanners using the wrong (or
  no) SNI terminate TLS against that upstream's genuine certificate instead of the
  server's. A step toward REALITY-style probe resistance without TLS-stack surgery.
- **REALITY.md** design doc — how full Xray REALITY would be implemented across
  `obfs` (protocol), `servion` (control plane), and `value-rpc` (unchanged).
- **LICENSE** file (BUSL-1.1, Change License MPL 2.0) at the repository root,
  matching the rest of the `go.arpabet.com` family. All source headers already
  declared `SPDX-License-Identifier: BUSL-1.1`; the file was previously missing.
- **Encrypted ClientHello (ECH)** in `obfs/tlscamo`. `tlscamo.Config` gains an
  `ECHConfigList` field; when set, the mimicked TLS handshake encrypts the inner
  ClientHello (including the real SNI) under the provided ECH config, closing the
  plaintext-SNI blocking vector while keeping the browser-like outer fingerprint.
- **Fuzz tests** for the untrusted cell parsers — `FuzzShapedRead` (fixed-cell
  mode) and `FuzzMorphRead` (morpher mode) drive arbitrary bytes through the
  readers and assert they never panic or hang.

## [0.1.0] — 2026-06-15

Initial public release. Tagged per module: `v0.1.0` (core + `hop`),
`tlscamo/v0.1.0`, `reality/v0.1.0`/`reality/v0.1.1`, `webrtc/v0.1.0`.

### Added

- **`obfs` core** (zero dependencies) — fixed-cell traffic shaper (`Wrap`,
  `Dialer`, `Listener`) with length padding, timing jitter, and idle cover
  (chaff) traffic; pluggable `Fill` (`RandomFill`, `PrintableFill`, `ZeroFill`);
  and a distribution-matching **morpher** (`SizeSampler`/`DelaySampler`,
  `UniformSize`, `SampledSize`, `PoissonDelay`).
- **`obfs/hop`** (zero dependencies) — port/address hopping: `Dialer` rotates the
  destination by time window, `MultiListener` listens on every candidate at once.
- **`obfs/tlscamo`** — uTLS ClientHello mimicry (Chrome/Firefox/Safari/Edge/
  randomized), ALPN control, and per-connection fingerprint rolling.
- **`obfs/reality`** — Trojan-style active-probe defense: token-authenticated TLS
  tunnel; unauthenticated connections are transparently reverse-proxied to a real
  fallback site.
- **`obfs/webrtc`** — Snowflake-style WebRTC data-channel transport with pluggable
  signaling (`Signaler`/`OfferSource`); no built-in broker.

[Unreleased]: https://github.com/arpabet/obfs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/arpabet/obfs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/arpabet/obfs/releases/tag/v0.1.0
