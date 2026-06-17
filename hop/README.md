# obfs/hop

Port/address **hopping** for Go transports: the client rotates its destination across
a set of addresses on a time schedule, while the server listens on all of them at once.
Rotating the visible IP:port frustrates static blocklists and per-endpoint rate
analysis (in the spirit of Hysteria's port hopping). Part of the zero-dependency
[`obfs`](../README.md) core — stdlib only — so it composes with value-rpc, gRPC, or
plain net I/O.

```
go get go.arpabet.com/obfs
```

## Use

```go
import "go.arpabet.com/obfs/hop"

// Server: listen on every candidate address at once; accepted conns fan into one Listener.
lis, err := hop.MultiListener([]string{":4001", ":4002", ":4003"}, nil)

// Client: rotate the destination by time window (window = floor(now/period)).
dial, err := hop.Dialer(
    []string{"host:4001", "host:4002", "host:4003"},
    30*time.Second, // rotation period
    nil,            // custom dial func; nil = net.Dial("tcp", …)
)
conn, err := dial()
```

The client and server need not share the schedule — the server accepts on all
addresses, so rotation simply spreads connections across endpoints. Pass a custom
`dial`/`listen` func (3rd arg) to hop over TLS, QUIC, or any other carrier.

## Notes

- Hopping changes **reachability**, not content — run it under TLS and, if you need it,
  with `obfs` traffic shaping inside the tunnel.
- It is **dual-use**; see the [root README](../README.md) for responsible-use guidance.

See the [obfs overview](../README.md) for how hop composes with the other layers.
