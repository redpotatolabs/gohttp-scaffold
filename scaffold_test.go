package scaffold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnvOrDefault(t *testing.T) {
	t.Setenv("SCAFFOLD_TEST_VAL", "from-env")
	if got := EnvOrDefault("SCAFFOLD_TEST_VAL", "fallback"); got != "from-env" {
		t.Errorf("want from-env, got %q", got)
	}
	t.Setenv("SCAFFOLD_TEST_VAL", "")
	if got := EnvOrDefault("SCAFFOLD_TEST_VAL", "fallback"); got != "fallback" {
		t.Errorf("want fallback, got %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	wantHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	}
	for k, v := range wantHeaders {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}
}

func TestReadJSON_Success(t *testing.T) {
	body := bytes.NewBufferString(`{"x":42}`)
	req := httptest.NewRequest("POST", "/", body)
	w := httptest.NewRecorder()
	var dst struct{ X int }
	if !ReadJSON(w, req, &dst, 0) {
		t.Fatal("ReadJSON returned false")
	}
	if dst.X != 42 {
		t.Errorf("dst.X = %d, want 42", dst.X)
	}
}

func TestReadJSON_BadBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	var dst struct{ X int }
	if ReadJSON(w, req, &dst, 0) {
		t.Fatal("ReadJSON should return false on bad body")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, map[string]int{"x": 1})
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type %q", got)
	}
	var out map[string]int
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["x"] != 1 {
		t.Errorf("body %v", out)
	}
}

func TestRegisterBuildRoutes(t *testing.T) {
	mux := http.NewServeMux()
	RegisterBuildRoutes(mux, BuildInfo{BuildID: "abc123"})

	t.Run("healthz", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
		if w.Code != 200 {
			t.Errorf("status %d", w.Code)
		}
	})

	t.Run("build id", func(t *testing.T) {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", "/__build_id", nil))
		if w.Code != 200 {
			t.Errorf("status %d", w.Code)
		}
		var out struct{ ID string }
		_ = json.NewDecoder(w.Body).Decode(&out)
		if out.ID != "abc123" {
			t.Errorf("id %q", out.ID)
		}
	})

	t.Run("default id is 'dev' when unset", func(t *testing.T) {
		mux2 := http.NewServeMux()
		RegisterBuildRoutes(mux2, BuildInfo{})
		w := httptest.NewRecorder()
		mux2.ServeHTTP(w, httptest.NewRequest("GET", "/__build_id", nil))
		var out struct{ ID string }
		_ = json.NewDecoder(w.Body).Decode(&out)
		if out.ID != "dev" {
			t.Errorf("default id %q", out.ID)
		}
	})
}

func TestRateLimiter_AllowsBurst(t *testing.T) {
	rl := RateLimiter(1, 3) // 1 rps, burst of 3
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := rl(next)
	allowed := 0
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == 200 {
			allowed++
		}
	}
	if allowed < 3 {
		t.Errorf("burst not honored: allowed = %d, want >= 3", allowed)
	}
}

func TestRateLimiter_PerIP(t *testing.T) {
	rl := RateLimiter(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := rl(next)
	hit := func(ip string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	if c := hit("a:1"); c != 200 {
		t.Errorf("first hit a should pass, got %d", c)
	}
	if c := hit("b:1"); c != 200 {
		t.Errorf("first hit b should pass (separate IP), got %d", c)
	}
	if c := hit("a:1"); c == 200 {
		t.Errorf("second a should rate-limit after using its burst")
	}
}

func TestRateLimiter_HonorsXForwardedFor(t *testing.T) {
	rl := RateLimiter(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := rl(next)

	req := func(fwd string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Forwarded-For", fwd)
		return r
	}
	// Two different XFF values should each get their burst even though
	// RemoteAddr is the same (same proxy in front).
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req("1.1.1.1"))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req("2.2.2.2"))
	if w1.Code != 200 || w2.Code != 200 {
		t.Errorf("both XFFs should pass: %d %d", w1.Code, w2.Code)
	}
	// A client can put anything before the proxy's entry, so only the last one counts.
	w3 := httptest.NewRecorder()
	h.ServeHTTP(w3, req("9.9.9.9, 1.1.1.1"))
	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("a made-up earlier entry got past the limit: %d", w3.Code)
	}
}

func TestClientIP(t *testing.T) {
	for _, c := range []struct {
		name, remote, cf, xff, want string
	}{
		{"cloudflare", "127.0.0.1:5000", "203.0.113.7", "1.2.3.4, 203.0.113.7", "203.0.113.7"},
		{"proxy", "127.0.0.1:5000", "", "9.9.9.9, 198.51.100.2", "198.51.100.2"},
		{"direct, port dropped", "192.0.2.5:61234", "", "", "192.0.2.5"},
		{"ipv6", "[2001:db8::1]:443", "", "", "2001:db8::1"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.cf != "" {
			r.Header.Set("Cf-Connecting-Ip", c.cf)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("%s: clientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRateLimiter_NewConnectionsShareABucket(t *testing.T) {
	h := RateLimiter(1, 1)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	codes := []int{}
	for _, port := range []string{"1001", "1002"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.0.2.5:" + port
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
		t.Errorf("codes = %v, want 200 then 429", codes)
	}
}

func TestRecoverPanics(t *testing.T) {
	s := New()
	called := false
	h := s.RecoverPanics(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		panic("boom")
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !called {
		t.Error("handler never ran")
	}
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestRecoverPanics_ReabortRepanicsAbortHandler(t *testing.T) {
	s := New()
	h := s.RecoverPanics(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("expected re-panic with ErrAbortHandler, got %v", r)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

func TestWrap_DefaultsAndChain(t *testing.T) {
	s := New()
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := s.Wrap(inner, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.99:9"
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("status %d", w.Code)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers not applied")
	}
}

func TestRun_GracefulShutdownOnCtxCancel(t *testing.T) {
	s := New()
	ctx, cancel := context.WithCancel(context.Background())
	shutdownCalled := false
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		done <- s.Run(ctx, RunConfig{
			Addr:    "127.0.0.1:0",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
			OnShutdown: func(_ context.Context) {
				mu.Lock()
				shutdownCalled = true
				mu.Unlock()
			},
		})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Run returned err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after ctx cancel")
	}
	mu.Lock()
	defer mu.Unlock()
	if !shutdownCalled {
		t.Error("OnShutdown was not called")
	}
}

func TestRun_RejectsNilHandler(t *testing.T) {
	s := New()
	err := s.Run(context.Background(), RunConfig{})
	if err == nil {
		t.Fatal("expected error for nil handler")
	}
}
