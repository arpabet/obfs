# obfs examples

Runnable, self-contained demos. Each is its **own Go module** (so heavy dependencies like
uTLS never enter the zero-dependency `obfs` core) and is run with `GOWORK=off`.

| Example | Shows |
|---------|-------|
| [`fullstack`](fullstack) | Composing **hop + tlscamo + traffic shaping** over an echo service — the canonical layering. |

For inline, copy-pasteable snippets see the Go [example functions](https://pkg.go.dev/go.arpabet.com/obfs#pkg-examples)
(`ExampleWrap`, `ExampleWrap_morpher`, `ExampleWrapPacket`) and each module's README.

REALITY-style transports have runnable, servion-wired demos (value-rpc over the tunnel,
with shaping inside) in **`servion/vrpc/examples/`**:

- `servion/vrpc/examples/reality` — Trojan-style active-probe defense.
- `servion/vrpc/examples/xreality` — REALITY-style transport + inner obfs shaping.

```bash
cd examples/fullstack && GOWORK=off go run .
```
