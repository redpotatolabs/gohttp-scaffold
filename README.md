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
| `SecurityHeaders`, `ContentSecurityPolicy`, `ContentSecurityPolicyWith` | standard response headers. The policy lets Cloudflare's Web Analytics beacon load (`AnalyticsScript`) and report (`AnalyticsReport`); `ContentSecurityPolicyWith(origins...)` adds connect-src origins such as a Sentry ingest host, in the one connect-src directive |
| `RateLimiter(rps, burst)` | per-client token bucket, keyed by the real client IP behind Cloudflare or a proxy |
| `RecoverPanics` | turns handler panics into 500 responses and reports them |
| `ReadJSON`, `WriteJSON`, `DefaultMaxJSONBytes` | size-limited JSON decoding and encoding |
| `RegisterBuildRoutes`, `BuildInfo` | `GET /healthz` and `GET /__build_id` |
| `EnvOrDefault` | environment variable with a fallback |
| `Server.Run`, `RunConfig` | `http.Server` with standard timeouts and graceful shutdown on context cancel |

### Subpackages

| Package | Purpose |
| --- | --- |
| `auth` | Discord sign-in the way the schedule does it: sessions in `sessions.json` with an ID-only cookie and a CSRF token, `/auth/login`, `/auth/callback`, `/auth/logout` and `/auth/me`, a `RequireRole(View|Edit)` middleware, role checks in one server with a cache and Discord outage handling, `CanonicalHost`, and `Actor` for the share and changelog packages |
| `changelog` | append-only `changes.jsonl`: who (Discord ID and name) did what to which target, synced on every write |
| `share` | public read-only links: 128-bit tokens in `shares.json`, create, list and revoke handlers for editors, and a public handler that serves whatever the app's resolver returns for the link's target. Create and revoke go to the change log. |

Put a site behind sign-in with the standard environment (`DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_GUILD_ID`, `DISCORD_VIEW_ROLE_IDS`, `DISCORD_EDIT_ROLE_IDS`, `PUBLIC_URL`, `DATA_DIR`). Routes left outside `RequireRole` stay public; keep `/healthz`, `/__build_id` and the auth routes there:

```go
cfg := auth.FromEnv()
a, err := auth.New(cfg)
a.Routes(mux)
mux.Handle("GET /api/maps", a.RequireRole(auth.View)(listMaps))
mux.Handle("PUT /api/maps/{id}", a.RequireRole(auth.Edit)(saveMap))
handler := auth.CanonicalHost(srv.Wrap(mux, nil), cfg.PublicHost())
```

A page without a session is sent to sign-in and back; a fetch gets 401. A member without the role gets a "not a member" page or 403. An empty `DISCORD_VIEW_ROLE_IDS` lets every member of the server view; an empty `DISCORD_EDIT_ROLE_IDS` lets nobody edit. `GET /auth/me` tells the page who is signed in, whether they may view or edit, and the CSRF token. `RequireRole` refuses any method other than GET, HEAD and OPTIONS without it, as the `X-CSRF-Token` header or the `csrf` field of a form body, because every potato.red site is one site to the browser and the cookie alone would let another subdomain post as the visitor.

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
