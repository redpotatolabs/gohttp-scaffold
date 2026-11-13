// Package scaffold bundles the HTTP scaffolding shared across redpotatolabs Go
// services: middleware (security headers, panic recovery, rate limiting),
// JSON helpers, build/health endpoints, env-or-default, and an opinionated
// Run loop with graceful shutdown.
//
// The Server type owns the optional beacon client and exposes the
// scoped middleware (RecoverPanics, Wrap, Run) so error reporting routes
// through beacon without package-level globals. Helpers that don't need
// state (SecurityHeaders, RateLimiter, ReadJSON, WriteJSON,
// RegisterBuildRoutes, EnvOrDefault) are plain package functions.
package scaffold

import (
	"context"
	"log"
	"net/http"

	beacon "github.com/redpotatolabs/beacon-client"
)

// Server bundles cross-cutting concerns shared by redpotatolabs HTTP services.
// The zero value is usable; beacon reporting is a no-op until SetBeacon
// is called.
type Server struct {
	bc *beacon.Client
}

// New returns a Server with no beacon client.
func New() *Server { return &Server{} }

// SetBeacon installs the beacon client. Pass nil to disable.
func (s *Server) SetBeacon(bc *beacon.Client) { s.bc = bc }

// Report logs msg and, if a beacon client is configured, posts it as a
// structured event. Beacon failures are logged but never propagated —
// observability must not break the caller's main flow.
func (s *Server) Report(ctx context.Context, level, msg string, fields ...beacon.FieldKV) {
	log.Print(msg)
	if s == nil || s.bc == nil {
		return
	}
	if _, err := s.bc.Error(ctx, beacon.ErrorRequest{
		Level:   level,
		Message: msg,
		Fields:  fields,
	}); err != nil {
		log.Printf("beacon: post failed: %v", err)
	}
}

// WrapOptions tunes the standard middleware chain. Pass nil for defaults
// (RPS=10, Burst=30).
type WrapOptions struct {
	RPS   int
	Burst int
}

// Wrap applies the default middleware stack:
//
//	SecurityHeaders → RecoverPanics → RateLimiter
//
// The order is intentional and not configurable; see the API doc.
func (s *Server) Wrap(h http.Handler, opts *WrapOptions) http.Handler {
	if opts == nil {
		opts = &WrapOptions{}
	}
	if opts.RPS <= 0 {
		opts.RPS = 10
	}
	if opts.Burst <= 0 {
		opts.Burst = 30
	}
	h = SecurityHeaders(h)
	h = s.RecoverPanics(h)
	h = RateLimiter(opts.RPS, opts.Burst)(h)
	return h
}
