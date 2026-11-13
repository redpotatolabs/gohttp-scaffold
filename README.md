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

### Subpackages

| Package | Purpose |
| --- | --- |
| `changelog` | append-only `changes.jsonl`: who (Discord ID and name) did what to which target, synced on every write |
| `share` | public read-only links: 128-bit tokens in `shares.json`, create, list and revoke handlers for editors, and a public handler that serves whatever the app's resolver returns for the link's target. Create and revoke go to the change log. |

Mount the share handlers yourself, with the manage routes behind your edit-role check and the public one open:

```go
h := &share.Handlers{Store: shares, Resolve: resolveRevision, Identify: auth.Actor}
mux.Handle("POST /api/shares", requireEdit(http.HandlerFunc(h.Create)))
mux.Handle("GET /api/shares", requireEdit(http.HandlerFunc(h.List)))
mux.Handle("DELETE /api/shares/{token}", requireEdit(http.HandlerFunc(h.Revoke)))
mux.HandleFunc("GET /api/s/{token}", h.Public)
```

## License

MIT, see [LICENSE](LICENSE).
