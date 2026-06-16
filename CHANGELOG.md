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
