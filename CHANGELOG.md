# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/). The repository is a multi-module
workspace: the zero-dependency core (`go.arpabet.com/obfs`, including `obfs/hop`)
and the dependency-bearing submodules (`obfs/tlscamo`, `obfs/reality`,
`obfs/webrtc`) are versioned and tagged independently — entries below note which
module a change applies to.

## [Unreleased]

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

[Unreleased]: https://github.com/arpabet/obfs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/arpabet/obfs/releases/tag/v0.1.0
