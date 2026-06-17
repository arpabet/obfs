# Releasing obfs

`obfs` is a **multi-module** repository: the zero-dependency core and each
dependency-bearing submodule are versioned and tagged **independently**, so importing the
core never pulls in uTLS/pion/forked-TLS. This guide covers the tag scheme, the order, and
the pre-release checklist.

## Modules and tags

| Module | Path | Deps | License | Latest tag | Next |
|---|---|---|---|---|---|
| core (+ `hop`) | `go.arpabet.com/obfs` | stdlib only | BUSL-1.1 | `v0.1.0` | **`v0.2.0`** (morpher, FRONT, RegulaTor pacing, `WrapPacket`, fuzz) |
| tlscamo | `go.arpabet.com/obfs/tlscamo` | uTLS | BUSL-1.1 | `tlscamo/v0.1.0` | **`tlscamo/v0.2.0`** (ECH) |
| reality | `go.arpabet.com/obfs/reality` | tlscamo→uTLS | BUSL-1.1 | `reality/v0.1.1` | **`reality/v0.2.0`** (SNI-passthrough) |
| webrtc | `go.arpabet.com/obfs/webrtc` | pion | BUSL-1.1 | `webrtc/v0.1.0` | unchanged |
| xreality | `go.arpabet.com/obfs/xreality` | uTLS | BUSL-1.1 | — | **`xreality/v0.1.0`** (new) |
| xrayreality | `go.arpabet.com/obfs/xrayreality` | xtls/reality, uTLS | **MPL-2.0** | — | **`xrayreality/v0.1.0`** (new) |

Submodule tags are prefixed with the submodule path (e.g. `tlscamo/v0.2.0`) — that is how
Go resolves versions for a module in a subdirectory.

## Cross-module dependencies (tag order matters)

- `reality` requires `tlscamo` by version. **Tag `tlscamo` first**, then bump the require
  in `reality/go.mod`, run `go mod tidy`, verify `reality/go.sum` has the new tlscamo zip
  hash (a missing hash has broken a release before), then tag `reality`.
- `xreality`, `xrayreality`, `webrtc`, and the core are independent of each other.
- `xrayreality` is **MPL-2.0** (it depends on / ports MPL code: `xtls/reality` and
  Xray-core). It carries its own `LICENSE`; this does not affect the BUSL-1.1 of the rest
  (obfs's BUSL Change License is already MPL-2.0, so there is no conflict).

## Before tagging — drop the local `replace`s

These are resolved from the working tree during development and **must be removed (and the
requires pinned to the new tags)** before release; otherwise consumers can't build:

- `obfs/examples/fullstack/go.mod` — `replace go.arpabet.com/obfs`, `…/tlscamo`.
- In the companion **servion** repo: `servion/vrpc/go.mod` and
  `servion/vrpc/examples/{reality,xreality}/go.mod`.

## Checklist (run per module, from its directory)

```bash
gofmt -l .                 # must be empty
go vet ./...
go test -race -cover ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go mod tidy                # commit any go.mod/go.sum changes
```

Then for the core also smoke-run the fuzz targets and examples:

```bash
go test -run='^$' -fuzz=FuzzShapedRead -fuzztime=15s .
go test -run=Example .
( cd examples/fullstack && GOWORK=off go run . )
```

CI (`.github/workflows/build.yaml`) runs build/vet/race-test + govulncheck per module
across Go 1.25/1.26, plus the fuzz smoke and benchmarks.

## Tagging

```bash
# core
git tag v0.2.0 && git push origin v0.2.0
# submodules (tlscamo before reality)
git tag tlscamo/v0.2.0    && git push origin tlscamo/v0.2.0
git tag reality/v0.2.0    && git push origin reality/v0.2.0
git tag xreality/v0.1.0   && git push origin xreality/v0.1.0
git tag xrayreality/v0.1.0 && git push origin xrayreality/v0.1.0
```

Update [CHANGELOG.md](CHANGELOG.md): move the `[Unreleased]` items under the new version
headings with the date, and add the compare links.

## Note on the module proxy

`go.arpabet.com/*` modules are kept off Google's public proxy/checksum DB
(`GOPRIVATE=go.arpabet.com/*`, set in CI), so they are fetched directly from source.
Consumers behind the default proxy may need the same `GOPRIVATE` (or a vanity-import
server that serves `go-import` meta tags for `go.arpabet.com/obfs`).
