# gohttp-scaffold

Shared HTTP scaffolding for the Red Potato Labs Go services: a standard middleware chain, JSON helpers, health and build endpoints, an environment helper and a run loop with graceful shutdown. Error reporting goes through [beacon-client](https://github.com/redpotatolabs/beacon-client) when a client is configured and is a no-op otherwise.

## Install

```sh
go get github.com/redpotatolabs/gohttp-scaffold@latest
```

## Use

```go
import scaffold "github.com/redpotatolabs/gohttp-scaffold"

mux := http.NewServeMux()
scaffold.RegisterBuildRoutes(mux, scaffold.BuildInfo{BuildID: buildID})

srv := scaffold.New()
srv.SetBeacon(beaconClient) // optional

handler := srv.Wrap(mux, nil) // security headers, rate limit, panic recovery
err := srv.Run(ctx, scaffold.RunConfig{Addr: ":8080", Handler: handler})
```

## What ships

| Symbol | Purpose |
| --- | --- |
| `Server`, `New`, `Server.SetBeacon`, `Server.Report` | holds the optional beacon client and reports errors through it |
| `Server.Wrap(h, *WrapOptions)` | applies the default middleware stack in a fixed order |
| `SecurityHeaders`, `ContentSecurityPolicy` | standard response headers |
| `RateLimiter(rps, burst)` | per-client token bucket, keyed by the real client IP behind Cloudflare or a proxy |
| `RecoverPanics` | turns handler panics into 500 responses and reports them |
| `ReadJSON`, `WriteJSON`, `DefaultMaxJSONBytes` | size-limited JSON decoding and encoding |
| `RegisterBuildRoutes`, `BuildInfo` | `GET /healthz` and `GET /__build_id` |
| `EnvOrDefault` | environment variable with a fallback |
| `Server.Run`, `RunConfig` | `http.Server` with standard timeouts and graceful shutdown on context cancel |

## License

MIT, see [LICENSE](LICENSE).
