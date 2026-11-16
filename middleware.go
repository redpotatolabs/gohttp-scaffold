package scaffold

import (
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	beacon "github.com/redpotatolabs/beacon-client"
)

// Cloudflare adds its Web Analytics beacon to every potato.red page it serves,
// so the policy lets the beacon load and report (RED-168, as admin did in
// RED-164). There is no snippet in the pages. The beacon usually reports to the
// site's own /cdn-cgi/rum, which 'self' covers; cloudflareinsights.com is for
// when it reports there instead.
const (
	AnalyticsScript = "https://static.cloudflareinsights.com"
	AnalyticsReport = "https://cloudflareinsights.com"
)

// ContentSecurityPolicy only allows the site's own scripts, styles, forms and
// frames, plus Cloudflare's analytics beacon. form-action also covers where a
// submitted form redirects to, so a form that redirects off-site needs its own
// policy. An app that must connect elsewhere too (a Sentry ingest host) uses
// ContentSecurityPolicyWith rather than appending a second connect-src, which
// the browser would ignore.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self' " + AnalyticsScript + "; style-src 'self' 'unsafe-inline'; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; " +
	"connect-src 'self' " + AnalyticsReport

// ContentSecurityPolicyWith is ContentSecurityPolicy with extra origins the
// browser may connect to, such as https://o1.ingest.us.sentry.io. They join the
// one connect-src: a browser keeps only the first of two directives with the
// same name. Empty origins are skipped.
func ContentSecurityPolicyWith(connect ...string) string {
	policy := ContentSecurityPolicy
	for _, origin := range connect {
		if origin = strings.TrimSpace(origin); origin != "" {
			policy += " " + origin
		}
	}
	return policy
}

// SecurityHeaders sets the standard redpotatolabs response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// RateLimiter returns a per-IP token-bucket middleware. Clients are identified by
// clientIP. Spawns a cleanup
// goroutine that drops entries idle > 5 min; the goroutine runs for the
// process lifetime (acceptable for long-running servers — revisit if this
// is embedded in a test that spins servers up and down).
func RateLimiter(rps int, burst int) func(http.Handler) http.Handler {
	type visitor struct {
		tokens float64
		last   time.Time
	}
	var mu sync.Mutex
	visitors := make(map[string]*visitor)

	go func() {
		for {
			time.Sleep(time.Minute)
			mu.Lock()
			now := time.Now()
			for ip, v := range visitors {
				if now.Sub(v.last) > 5*time.Minute {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)

			mu.Lock()
			v, ok := visitors[ip]
			if !ok {
				v = &visitor{tokens: float64(burst), last: time.Now()}
				visitors[ip] = v
			}
			now := time.Now()
			elapsed := now.Sub(v.last).Seconds()
			v.last = now
			v.tokens += elapsed * float64(rps)
			if v.tokens > float64(burst) {
				v.tokens = float64(burst)
			}
			if v.tokens < 1 {
				mu.Unlock()
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			v.tokens--
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// RecoverPanics turns panics in downstream handlers into 500 responses and
// reports them via the Server's beacon client (no-op when unset). The
// http.ErrAbortHandler sentinel is intentionally re-panicked.
func (s *Server) RecoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			stack := string(debug.Stack())
			s.Report(r.Context(), "fatal",
				fmt.Sprintf("panic in HTTP handler %s %s: %v", r.Method, r.URL.Path, rec),
				beacon.FieldKV{Name: "method", Value: r.Method, Inline: true},
				beacon.FieldKV{Name: "path", Value: r.URL.Path, Inline: true},
				beacon.FieldKV{Name: "stack", Value: stack},
			)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP is the address a request came from. Behind Cloudflare that's
// Cf-Connecting-Ip, which Cloudflare sets itself. Otherwise it's the last
// X-Forwarded-For entry, added by the nearest proxy: earlier entries come from the
// client, which could change them to dodge the limit. Without either it's the
// connection's address, without the port, so new connections from one client share
// a bucket.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); ip != "" {
		return ip
	}
	if fwd := r.Header.Values("X-Forwarded-For"); len(fwd) > 0 {
		parts := strings.Split(fwd[len(fwd)-1], ",")
		if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
			return ip
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
