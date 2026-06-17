# obfs/webrtc

**Snowflake-style WebRTC data channel.** Carry a `net.Conn` over a WebRTC data channel,
so the traffic looks like a call (DTLS/SRTP-style over UDP) — the same camouflage Tor's
Snowflake uses, and expensive for a censor to block wholesale. A separate module so the
heavy [`pion`](https://github.com/pion/webrtc) dependency tree stays out of the
zero-dependency [`obfs`](../README.md) core.

```
go get go.arpabet.com/obfs/webrtc
```

> Depends on `pion/webrtc`.

## Signaling is pluggable (no broker here)

WebRTC needs an out-of-band SDP offer/answer exchange before the data channel forms.
This package does **not** implement that rendezvous — that broker is a control-plane
concern (servion, an HTTP broker, domain fronting, …). The client provides a `Signaler`
(send my offer, get the answer); the server provides an `OfferSource` (a stream of
inbound offers, each with a reply callback). Non-trickle ICE is used, so signaling is one
request/response.

## Use

```go
import "go.arpabet.com/obfs/webrtc"

// Client (signaler talks to your broker):
conn, err := webrtc.Dial(ctx, signaler, webrtc.Config{
    ICEServers: []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}},
})

// Server: Accept yields a net.Conn per answered offer from the source.
ln, err := webrtc.Listener(offerSource, webrtc.Config{})
```

## Caveats

- WebRTC carries confidentiality (DTLS), but this is **camouflage, not anonymity**.
- NAT traversal needs STUN/TURN (`Config.ICEServers`) off-LAN.
- The **broker is the part a censor attacks** — make rendezvous resilient (domain
  fronting, ephemeral proxies) at that layer.
- **Dual-use**; see the [root README](../README.md).

See the [obfs overview](../README.md) for how WebRTC composes with traffic shaping inside
the tunnel.
