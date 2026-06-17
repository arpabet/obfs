# obfs/tlscamo

**uTLS ClientHello mimicry**: a TLS client whose handshake matches a real browser's
JA3/JA4 fingerprint, so a censor that fingerprints TLS sees an ordinary Chrome/Firefox/…
client instead of Go's distinctive `crypto/tls` ClientHello. Optionally encrypts the
SNI with **ECH**. A separate module so the uTLS dependency stays out of the
zero-dependency [`obfs`](../README.md) core.

```
go get go.arpabet.com/obfs/tlscamo
```

> Depends on [`refraction-networking/utls`](https://github.com/refraction-networking/utls).

## Use

```go
import "go.arpabet.com/obfs/tlscamo"

dial := tlscamo.Dialer("tcp", "example.com:443", tlscamo.Config{
    ServerName:  "example.com",
    Fingerprint: tlscamo.Chrome, // Chrome/Firefox/Safari/Edge/Randomized
    Roll:        true,           // pick a random fingerprint per connection
})
conn, err := dial() // a net.Conn; run any protocol over it
```

Or wrap an already-dialed conn (must be the **outermost** layer, closest to the wire):

```go
raw, _ := net.Dial("tcp", addr)
conn, err := tlscamo.Client(raw, tlscamo.Config{ServerName: "example.com"})
```

### Hide the SNI with ECH

```go
tlscamo.Config{ServerName: "example.com", ECHConfigList: echList} // from the DNS HTTPS/SVCB "ech=" record
```

ECH needs TLS 1.3 and succeeds only if the server negotiates it.

## Layering & caveats

- **Outermost layer.** Put any `obfs` traffic shaping *inside* the tunnel (wrap the
  returned conn), never outside it.
- **Server side is unchanged** — run an ordinary `crypto/tls` server; leave its ALPN
  unset or include the protocols the client offers.
- Browser fingerprints drift — **pin the uTLS version** and refresh presets over time,
  so a stale fingerprint doesn't itself become the signature.
- This is camouflage plus normal TLS confidentiality/authentication — not anonymity.

See the [obfs overview](../README.md) for composition with hop, shaping, and reality.
