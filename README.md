# obfs

A **stub** censorship-resistant obfuscation transport for
[servion](https://go.arpabet.com/servion).

It does **no real obfuscation yet**. Its purpose is to lock down the integration
surface that servion expects — so a servion application can already wire it in,
and the real shaping / protocol-mimicry logic can be filled in later without
changing the public API.

```bash
go get go.arpabet.com/obfs
```

## What it provides

It mirrors servion's other transport modules (`grpc`, `vrpc`):

| Type | Role |
|------|------|
| `obfs.ObfsServerScanner(name, …)` | `glue.Scanner` for `servion.RunCommand` (like `HttpServerScanner`) |
| `obfs.ObfsServer(name)` | a stub `servion.Server` — binds a TCP listener, runs the full Bind/Serve/Shutdown lifecycle, but passes accepted connections through the no-op `Obfuscator` and drops them |
| `obfs.Obfuscator` | the pluggable obfuscation seam (`Obfuscate(net.Conn) (net.Conn, error)`) — where real length/timing/entropy shaping and protocol mimicry will live |
| `obfs.Nop()` | a pass-through `Obfuscator` (the current default) |

## Usage

```go
import (
	"go.arpabet.com/cligo"
	"go.arpabet.com/glue"
	"go.arpabet.com/servion"
	"go.arpabet.com/obfs"
)

func main() {
	properties := glue.MapPropertySource{
		"obfs-server.bind-address": "0.0.0.0:9200",
	}
	beans := []interface{}{
		properties,
		servion.RunCommand(obfs.ObfsServerScanner("obfs-server")),
		servion.ZapLogFactory(true),
	}
	cligo.Main(cligo.Beans(beans...))
}
```

The server is picked up by servion's standard runtime exactly like an HTTP or
gRPC server (`ServionStarted {Servers: 1}`), so the wiring is real even though
the transport is a placeholder.

## Status

Stub / placeholder. The `Obfuscator` interface and the server lifecycle are the
stable contract; real implementations (HTTPS/REALITY mimicry, QUIC, traffic
shaping, …) plug in behind `Obfuscator` and the server `Serve` loop. See the
servion research notes for the planned designs.

## License

Business Source License 1.1 (BUSL-1.1) — Copyright (c) 2026 Karagatan LLC.
