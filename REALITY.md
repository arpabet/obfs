# obfs — Full REALITY transport (design / research)

Date: 2026-06-16. Companion to [README.md](README.md) and to value-rpc's
[TRANSPORTS.md](https://go.arpabet.com/value-rpc) §10–§11.

Goal: implement the **full Xray REALITY** protocol — borrowed-certificate,
active-probe-proof TLS camouflage — across the three libraries, **without changing
value-rpc**, with the protocol itself living in `obfs` and all keys/config/rotation
in `servion`. This document is the implementation plan; no REALITY code exists yet.
The shipping `obfs/reality` package today is **Trojan-grade** (server presents its
*own* certificate + token auth + HTTP fallback), which is a different, weaker model.

## TL;DR

- **Feasible, and the layering already fits.** REALITY produces a `net.Conn`, so it
  drops into value-rpc's bring-your-own-connection seam exactly like the current
  Trojan `reality` — **value-rpc needs zero changes**.
- **The protocol lives in `obfs`** as a new submodule (`obfs/xreality`), beside
  `tlscamo` (which it reuses for the browser ClientHello) and the rest of the
  shaping toolbox.
- **`servion` owns the control plane**: the X25519 server keypair, the shortId set,
  the borrowed-SNI `dest`, key rotation, and the DI/lifecycle wiring (a `Transport`
  bean in `servion/vrpc`).
- **The hard part — modifying the TLS 1.3 handshake on both ends — turned out to be
  avoidable for our use case.** Because both peers are ours, `obfs/xreality` reuses the
  uTLS browser hello's X25519 key share + injects the sealed SessionID on the client,
  and proves server identity with a **post-handshake channel-bound HMAC** instead of a
  forged certificate — so it runs on stock `crypto/tls` + the uTLS public API, no fork.
  The one scenario that still needs the fork is **wire-compatibility with real Xray
  servers**, for which vendoring Xray's MPL-2.0 TLS code is the path (no license
  conflict — obfs's BUSL Change License is already MPL-2.0).
- **REALITY only fixes the handshake.** Real-world GFW testing still blocked it via
  *post-handshake traffic shape*. That is exactly what the rest of `obfs`
  (morpher / FRONT / RegulaTor pacer) defends — run them **inside** the tunnel. This
  synergy is the strongest reason to put REALITY in `obfs`.

## 1. What REALITY actually does (verified mechanics)

Confirmed from source-level analysis (see References). The design defeats *active
probing*: a censor that suspects a proxy connects to it and checks whether it behaves
like the site it claims to be. REALITY makes that check pass against a **real,
unrelated** high-reputation site whose name it borrows.

1. **Client auth is smuggled in the ClientHello `SessionID` (32 bytes).** The client
   generates its normal X25519 keyshare, computes `ECDH(client_priv, server_pub)` →
   `shared`, then
   `AuthKey = HKDF-SHA256(ikm=shared, salt=clientHello.random[:20], info="REALITY")`.
   The SessionID is packed as `[3B version][1B pad][4B unix-time][24B shortId]` and
   **AEAD-encrypted in place** (AES-GCM or ChaCha20-Poly1305) with
   `nonce = clientHello.random[20:]` and `AAD = the whole ClientHello`. On the wire it
   is an ordinary TLS 1.3 ClientHello to the borrowed SNI (browser JA3/JA4 via uTLS).

2. **Server distinguishes auth vs probe by peeking the raw ClientHello — before any
   TLS termination.** It extracts the client keyshare, computes
   `ECDH(server_priv, client_pub)` → the same `shared`, derives the same `AuthKey`,
   and tries to AEAD-decrypt the SessionID. Success **and** valid version + timestamp
   window + known shortId ⇒ authenticated; anything else ⇒ probe.

3. **Probe → raw TCP passthrough to the real site.** Unauthenticated bytes are
   `io.Copy`'d verbatim to `dest` (the borrowed real site). The prober completes a
   genuine TLS handshake with the **real** site and sees its **real** certificate
   chain. This is strictly stronger than Trojan (which presents *its own* cert).

4. **Authenticated → forged certificate only the client can verify.** The server
   terminates TLS itself, presenting a self-signed ed25519 certificate for the
   borrowed SNI but **replacing the certificate signature with
   `HMAC-SHA512(AuthKey, ed25519_pubkey)`**. Because **TLS 1.3 encrypts the
   Certificate message**, a passive censor never sees the forged cert. The client
   recomputes the same HMAC and accepts the connection iff it matches; otherwise it
   aborts.

5. **uTLS** provides the client's low-level handshake access (build handshake state,
   reach the ephemeral keys, inject the SessionID) plus the browser fingerprint.
   `obfs/tlscamo` already wraps uTLS and is the dependency seam.

## 2. Responsibility split

Matches value-rpc TRANSPORTS.md §10.6: `obfs` = primitives, `servion` = assembly +
control plane, `value-rpc` = the RPC layer over a carrier-agnostic seam.

| Concern | Library | What it owns |
|---|---|---|
| **Protocol primitive** | **`obfs/xreality`** (new submodule) | ClientHello SessionID injection; server ClientHello peek + ECDH; AEAD auth; HMAC certificate forge/verify; raw passthrough to `dest`. Exposes a `net.Conn` (client) and a `net.Listener` (server). |
| **Assembly + control plane** | **`servion`** (`servion/vrpc` `Transport` bean) | X25519 server keypair, shortId set, borrowed-SNI `dest`, timestamp/replay window policy, key rotation, choice/validation of the borrowed site, DI + lifecycle. |
| **RPC over the tunnel** | **`value-rpc`** | **Nothing.** REALITY yields an `io.ReadWriteCloser`; it uses the existing `NewFuncDialer` / `NewAcceptListener` seam unchanged. |

Dependency arrows (unchanged from today): `servion/vrpc` → `obfs/xreality` →
`obfs/tlscamo` → uTLS. value-rpc sits at the bottom, oblivious to the carrier.

## 3. Where the coupling is — and why value-rpc is untouched

The seam already exists and is exactly the shape REALITY needs
(`value-rpc/valuerpc/transport_conn.go`):

```go
func NewFuncDialer(connect func() (io.ReadWriteCloser, error), writeTimeout time.Duration) Dialer
func NewAcceptListener(accept func() (io.ReadWriteCloser, error), addr net.Addr, stop func() error, writeTimeout time.Duration) Listener
```

A `net.Conn` is an `io.ReadWriteCloser`, so the REALITY dialer/listener feed these
directly — the same way `servion/vrpc/obfs.go` already wires the Trojan `reality`
package today. No value-rpc change is needed for REALITY, ever.

## 4. Proposed `obfs/xreality` API

A new submodule (heavy, TLS-forking deps stay out of the zero-dep core), mirroring
the existing `reality` package shape so it is a near drop-in:

```go
package xreality // as implemented

// Server: only authenticated tunnels come out of Accept; probes are spliced to Dest.
ln := xreality.Listener(baseTCP, xreality.ServerConfig{
    PrivateKey: x25519Priv,                          // *ecdh.PrivateKey; servion owns + rotates
    ShortIDs:   [][]byte{shortID},                   // accepted client tags (<= 8 bytes)
    TLSConfig:  &tls.Config{Certificates: certs},    // self-signed cert for the borrowed SNI is fine
    Dest:       "www.realsite.com:443",              // borrowed real site for probe passthrough
    TimeSkew:   90 * time.Second,                    // replay window on the embedded timestamp
})

// Client: dials, performs the REALITY handshake, returns the channel-verified tunnel.
dial := xreality.Dialer("tcp", serverAddr, xreality.ClientConfig{
    ServerPublicKey: x25519Priv.PublicKey().Bytes(), // server's static X25519 public key
    ShortID:         shortID,
    ServerName:      "www.realsite.com",
    // Fingerprint defaults to Chrome (utls.ClientHelloID)
})
```

`servion/vrpc` wraps these in a `Transport` bean exactly as its current doc-comment
example wraps Trojan `reality` (`servion/vrpc/obfs.go`): swap `reality.*` for
`xreality.*` and add beans for the keypair, shortIds, and `dest`.

## 5. The hard part: TLS-stack surgery — and how `obfs/xreality` avoids it

Stock `crypto/tls` cannot (a) hand you control of the ClientHello SessionID and
ephemeral keys, nor (b) forge a CertificateVerify signature. Options, with what was
actually built:

0. **Implemented: channel-bound auth on stock TLS + uTLS (no fork).** Problem (a) is
   solved by uTLS's public API — `BuildHandshakeState` exposes the keyshare ephemeral
   and lets us inject the SessionID before `MarshalClientHello`. Problem (b) is sidestepped
   entirely: instead of forging the certificate, the server proves identity *after* the
   handshake with `HMAC(authKey, tag‖ExportKeyingMaterial())`, which the client verifies.
   This is what `obfs/xreality` ships. It is **not Xray-wire-compatible** (acceptable —
   both peers are ours) and is the lowest-risk, dependency-light path.
1. **Vendor Xray's `reality` TLS code into a submodule as MPL-2.0 (for Xray interop).**
   Needed only if you must interoperate with real Xray servers/clients. Xray-core is
   **MPL-2.0**; MPL is *file-level* copyleft, so those files live in a separate module
   beside our BUSL-1.1 core as long as they keep their MPL headers — and obfs's BUSL
   **Change License is already MPL-2.0**, so there is no conflict. Reuses audited code
   instead of re-deriving it; the submodule's own `LICENSE` documents the mixed licensing.
2. **Fork a minimal TLS 1.3 handshake.** Server via a trimmed `crypto/tls` copy patched
   at the CertificateVerify step. This is what Xray maintains — a standing burden to
   track Go's TLS changes. Only worth it to avoid the MPL dependency while keeping Xray
   compatibility.
3. **Phase 0 (shipped earlier): SNI-passthrough in `obfs/reality`.** Peek the ClientHello
   and splice wrong-SNI probes to a real upstream — a cheap Trojan hardening, no auth/no
   forgery, complementary to the above.

## 6. Security caveats (must ship in the package doc)

- **No formal proof; non-standard crypto.** Client→server auth is an AEAD-sealed token
  in the SessionID; server→client auth is a channel-bound HMAC over TLS exporter keying
  material (not a CA signature). Security rests on X25519 + AEAD + HKDF + the TLS
  exporter, not a formally proven protocol composition. The replay window and the
  exporter binding are load-bearing — review them before relying on this.
- **REALITY only fixes the handshake.** Real-world GFW testing (Iran; Xray #2778 /
  #3269) still blocked REALITY flows over time via **post-handshake traffic-shape**
  distinguishers. Mitigation lives in this same module: run the **shaper / morpher /
  FRONT / RegulaTor pacer inside** the REALITY tunnel. Handshake camouflage and
  traffic-shape camouflage are independent layers; REALITY is only the former.
- **Replay.** The server must enforce the embedded timestamp window (`TimeSkew`) and
  may keep a short-lived seen-cache, or a captured ClientHello can be replayed.
- **`dest` selection is load-bearing.** It must speak TLS 1.3, be high-reputation,
  not be co-located with or correlated to your server, and not itself be blocked.
- **Dual-use.** As with the rest of `obfs`: do not use to evade authorized monitoring
  or in violation of applicable law.

## 7. Phased plan

| Phase | Where | Deliverable | New deps | Status |
|---|---|---|---|---|
| **0** | `obfs/reality` | SNI-passthrough fallback (probes spliced to a real upstream). Closes the main Trojan gap. | none | **done** |
| **1a** | `obfs/xreality` | REALITY **auth/crypto core** (X25519 ECDH, HKDF auth key, AEAD SessionID seal/open, replay window, cert-binding HMAC) — stdlib only, fully unit-tested. | none | **done** |
| **1b-i** | `obfs/xreality` | Server **decision pipeline**: `ParseClientHello` (random/session-id/SNI/X25519 share, fully bounds-checked) + `Authenticate` (parse → ECDH → AEAD verify → replay window → shortId gate → route). Pure, stdlib-only, fully tested. | none | **done** |
| **1b-ii** | `obfs/xreality` | Live **TLS plumbing**: `Client` (uTLS browser hello, reuses the hello's X25519 key share as the REALITY ephemeral, injects the sealed SessionID) + `Listener` (raw-peek → `Authenticate` → terminate *or* raw-splice to `Dest`). Server identity is proven by a **post-handshake channel-bound HMAC** (TLS exporter keying material), which replaces REALITY's in-handshake forged certificate — so **no TLS fork is needed**. | uTLS | **done (no-fork variant)** |
| **2** | `servion/vrpc/examples/xreality` | A `Transport` bean over `obfs/xreality` (server `Listener` + client `Dialer`), as its own module so uTLS stays out of `servion/vrpc`; runnable end-to-end demo (authenticated tunnel + probe→borrowed-site passthrough). | uTLS (in the example module only) | **done** |
| **3** | docs | The "REALITY + inner obfs shaping" recipe (handshake **and** traffic-shape defense together). | none | open |

Phases 1a, 1b-i, and 1b-ii (`obfs/xreality`) are implemented and tested: the auth core
(`ClientSessionID` / `ServerAuthenticate` / `CertHMAC`), the server decision pipeline
(`ParseClientHello` / `Authenticate`), and the live transport (`Client` / `Dialer` /
`Listener`).

The live transport avoids the TLS fork via a design adjustment that the "both peers are
ours" freedom allows. An experiment confirmed uTLS's public API is enough on the client:
after `BuildHandshakeState`, the browser hello's standalone X25519 key share
(`State13.KeyShareKeys.Ecdhe`, matching the on-wire group `0x001d` share) is reused as
the REALITY ephemeral, the sealed SessionID is injected, and `MarshalClientHello` +
`Handshake` complete a real handshake against a stock `crypto/tls` server. The only
gap — proving server identity without a CA-valid certificate — is filled **after** the
handshake by a **channel-bound HMAC**: both sides export TLS keying material
(`ExportKeyingMaterial`) and exchange `HMAC(authKey, tag‖ekm)`. Only the real server
knows `authKey` (derived from its static key + the client ephemeral), and the binding to
the exporter defeats a MITM that re-terminates TLS. This replaces REALITY's in-handshake
forged `CertificateVerify` (which would need a forked TLS stack) with an equivalent,
TLS-1.3-encrypted, censor-invisible check. (One uTLS quirk: the browser preset's
`renegotiation_info` extension disables the exporter; the flag is cleared post-handshake,
leaving the on-wire fingerprint untouched.)

The trade-off: this is **not wire-compatible with Xray REALITY** (it never was meant to
be — see below). For Xray interop specifically, the vendored/forked TLS path in §5 would
still be required.

value-rpc is untouched in every phase.

## References

- REALITY source-code analysis — <https://objshadow.pages.dev/en/posts/how-reality-works/>
- REALITY Protocol, XTLS/Xray-core (DeepWiki) — <https://deepwiki.com/XTLS/Xray-core/4.1-reality-protocol>
- REALITY Protocol deep dive (DeepWiki) — <https://deepwiki.com/XTLS/Xray-examples/3.3-reality-protocol-deep-dive>
- Blocking of REALITY in Iran (test results) — <https://github.com/XTLS/Xray-core/issues/2778>
- VLESS / REALITY / censorship-bypass overview — <https://plisio.net/cybersecurity/vless-protocol>
- uTLS — <https://github.com/refraction-networking/utls>
