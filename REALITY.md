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
- **The one genuinely hard part is unavoidable and dominates the work:** REALITY
  modifies the TLS 1.3 handshake on *both* ends, which stock `crypto/tls` cannot do.
  This is "TLS-stack surgery," not glue. The pragmatic path is to vendor Xray's
  audited REALITY TLS code as a separate **MPL-2.0** submodule (no license conflict —
  obfs's BUSL Change License is already MPL-2.0).
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
package xreality

// Server: only authenticated tunnels come out of Accept; probes are spliced to Dest.
ln := xreality.Listener(baseTCP, xreality.ServerConfig{
    PrivateKey:  x25519Priv,             // servion owns + rotates
    ShortIDs:    [][]byte{shortID},      // accepted client tags
    ServerNames: []string{"www.realsite.com"},
    Dest:        "www.realsite.com:443", // borrowed SNI + passthrough target
    TimeSkew:    90 * time.Second,       // replay window on the embedded timestamp
})

// Client: dials, performs the REALITY handshake, returns the verified tunnel.
dial := xreality.Dialer("tcp", serverAddr, xreality.ClientConfig{
    PublicKey:   x25519Pub,
    ShortID:     shortID,
    ServerName:  "www.realsite.com",
    Fingerprint: tlscamo.Chrome,         // reuses obfs/tlscamo
})
```

`servion/vrpc` wraps these in a `Transport` bean exactly as its current doc-comment
example wraps Trojan `reality` (`servion/vrpc/obfs.go`): swap `reality.*` for
`xreality.*` and add beans for the keypair, shortIds, and `dest`.

## 5. The hard part: TLS-stack surgery (the real cost)

Stock `crypto/tls` cannot (a) hand you control of the ClientHello SessionID and
ephemeral keys, nor (b) forge a CertificateVerify signature. Three options, ranked:

1. **Vendor Xray's `reality` TLS code into `obfs/xreality` as an MPL-2.0 submodule
   (recommended).** Xray-core is **MPL-2.0**; MPL is *file-level* copyleft, so those
   files live in a separate module beside our BUSL-1.1 core as long as they keep
   their MPL headers — and obfs's BUSL **Change License is already MPL-2.0**, so there
   is no conflict. Reuses audited, security-critical crypto instead of re-deriving it.
   Lowest risk, fastest, honest about provenance. The submodule's own `LICENSE`
   (MPL-2.0) documents the mixed licensing.
2. **Fork a minimal TLS 1.3 handshake.** Client via uTLS's exposed handshake state;
   server via a trimmed `crypto/tls` copy patched at the Certificate /
   CertificateVerify step. This is what Xray maintains — a standing burden to track
   Go's TLS changes. Only worth it to avoid the MPL dependency.
3. **Phase 0 (cheap, no surgery): SNI-passthrough in the existing `obfs/reality`.**
   Peek the ClientHello and *splice probes to a real upstream* (raw TCP) instead of
   reverse-proxying decrypted bytes to an HTTP origin. Probers then get a real
   third-party certificate — closing the biggest Trojan gap — with a few hundred
   lines and **no new dependencies and no cert forgery**. Not byte-identical to
   REALITY's authenticated path, but a large, safe increment shippable now.

## 6. Security caveats (must ship in the package doc)

- **No formal proof; non-standard crypto.** The certificate "signature" is an HMAC,
  not a CA signature; security rests on X25519 + AEAD + HKDF primitives, not a proven
  protocol composition.
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
| **1b-ii** | `obfs/xreality` | Live **TLS plumbing**: client SessionID injection + keyshare-ephemeral reuse + HMAC cert verify via uTLS; server raw-peek → `Authenticate` → forged-cert termination *or* raw passthrough. Needs uTLS handshake-state control (its keyshare-private API is in flux) and a forged-cert TLS path → Option 1 (vendor Xray MPL TLS). | uTLS (+ vendored MPL TLS) | open |
| **2** | `servion/vrpc` | `RealityTransport` bean + keypair / shortId / `dest` config + rotation in servion's control plane. | none beyond 1b | open |
| **3** | docs | The "REALITY + inner obfs shaping" recipe (handshake **and** traffic-shape defense together). | none | open |

Phases 1a + 1b-i (`obfs/xreality`) are the security-critical, TLS-independent parts and
are implemented and tested now: the auth core (`ClientSessionID` / `ServerAuthenticate`
/ `CertHMAC`) plus the server decision pipeline (`ParseClientHello` / `Authenticate`).
What remains (1b-ii) is the live TLS plumbing — the part that needs uTLS handshake-state
control and a forged-certificate TLS path, i.e. the vendored/forked TLS stack. The
`Authenticate` function is exactly the seam that plumbing calls after peeking the raw
ClientHello.

value-rpc is untouched in every phase.

## References

- REALITY source-code analysis — <https://objshadow.pages.dev/en/posts/how-reality-works/>
- REALITY Protocol, XTLS/Xray-core (DeepWiki) — <https://deepwiki.com/XTLS/Xray-core/4.1-reality-protocol>
- REALITY Protocol deep dive (DeepWiki) — <https://deepwiki.com/XTLS/Xray-examples/3.3-reality-protocol-deep-dive>
- Blocking of REALITY in Iran (test results) — <https://github.com/XTLS/Xray-core/issues/2778>
- VLESS / REALITY / censorship-bypass overview — <https://plisio.net/cybersecurity/vless-protocol>
- uTLS — <https://github.com/refraction-networking/utls>
