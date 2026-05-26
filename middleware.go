package scaffold

import (
	"fmt"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/epistemi/beacon/pkg/beacon"
)

// SecurityHeaders sets the standard epistemi response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

// RateLimiter returns a per-IP token-bucket middleware. Identifies clients
// by X-Forwarded-For if present, else RemoteAddr. Spawns a cleanup
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
			ip := r.RemoteAddr
			if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
				ip = fwd
			}

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
