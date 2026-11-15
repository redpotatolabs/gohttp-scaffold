package share

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redpotatolabs/gohttp-scaffold/changelog"
)

type memLog struct {
	entries []changelog.Entry
	fail    error
}

func (m *memLog) Append(e changelog.Entry) error {
	if m.fail != nil {
		return m.fail
	}
	m.entries = append(m.entries, e)
	return nil
}

var alice = changelog.Actor{ID: "111", Name: "Alice"}

func openStore(t *testing.T, log changelog.Recorder) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shares.json")
	s, err := Open(path, log)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestCreateLookupRevokePersist(t *testing.T) {
	log := &memLog{}
	s, path := openStore(t, log)

	l, err := s.Create("rev-1", alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Token) != 22 {
		t.Errorf("token %q: want 22 chars (128 bits, base64url)", l.Token)
	}
	if l2, _ := s.Create("rev-1", alice); l2.Token == l.Token {
		t.Error("two links got the same token")
	}
	if got, ok := s.Lookup(l.Token); !ok || got.Target != "rev-1" || got.Creator != alice {
		t.Errorf("lookup = %+v, %v", got, ok)
	}

	// Reload from disk.
	s2, err := Open(path, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Lookup(l.Token); !ok {
		t.Fatal("link lost on reload")
	}

	bob := changelog.Actor{ID: "222", Name: "Bob"}
	if err := s2.Revoke(l.Token, bob); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Lookup(l.Token); ok {
		t.Error("revoked link still resolves")
	}
	if err := s2.Revoke(l.Token, bob); err != nil {
		t.Errorf("second revoke: %v", err)
	}
	if err := s2.Revoke("nope", bob); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown revoke: %v", err)
	}

	s3, _ := Open(path, nil)
	if _, ok := s3.Lookup(l.Token); ok {
		t.Error("revoke not persisted")
	}
	list := s3.List("rev-1")
	if len(list) != 2 {
		t.Fatalf("list = %d, want 2 (revoked ones included)", len(list))
	}
	for _, x := range list {
		if x.Token == l.Token && (!x.Revoked || x.RevokedBy == nil || *x.RevokedBy != bob) {
			t.Errorf("revoked link = %+v", x)
		}
	}
	if len(s3.List("other")) != 0 {
		t.Error("list by target leaks other targets")
	}

	// Two creates and one revoke logged; the repeat revoke is not.
	var actions []string
	for _, e := range log.entries {
		actions = append(actions, e.Action+" "+e.Actor.ID+" "+e.Target)
	}
	want := "share.create 111 rev-1,share.create 111 rev-1,share.revoke 222 rev-1"
	if strings.Join(actions, ",") != want {
		t.Errorf("log = %v, want %s", actions, want)
	}
}

func TestCreateUndoneWhenLogFails(t *testing.T) {
	log := &memLog{fail: errors.New("disk full")}
	s, path := openStore(t, log)
	if _, err := s.Create("rev-1", alice); err == nil {
		t.Fatal("want error")
	}
	if len(s.List("")) != 0 {
		t.Error("link kept in memory although the log failed")
	}
	s2, _ := Open(path, nil)
	if len(s2.List("")) != 0 {
		t.Error("link kept on disk although the log failed")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	s, _ := openStore(t, nil)
	if _, err := s.Create("", alice); !errors.Is(err, ErrBadTarget) {
		t.Errorf("empty target: %v", err)
	}
	if _, err := s.Create(strings.Repeat("x", MaxTargetLen+1), alice); !errors.Is(err, ErrBadTarget) {
		t.Errorf("long target: %v", err)
	}
	if _, err := s.Create("rev-1", changelog.Actor{}); err == nil {
		t.Error("no creator: want error")
	}
}

// --- handlers ---

func newMux(t *testing.T, signedIn *changelog.Actor) (*http.ServeMux, *Store, map[string]string) {
	t.Helper()
	s, _ := openStore(t, nil)
	targets := map[string]string{"rev-1": `{"hexes":1}`}
	h := &Handlers{
		Store: s,
		Resolve: func(_ context.Context, target string) (json.RawMessage, error) {
			p, ok := targets[target]
			if !ok {
				return nil, fmt.Errorf("revision %s: %w", target, ErrNotFound)
			}
			return json.RawMessage(p), nil
		},
		Identify: func(*http.Request) (changelog.Actor, bool) {
			if signedIn == nil {
				return changelog.Actor{}, false
			}
			return *signedIn, true
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/shares", h.Create)
	mux.HandleFunc("GET /api/shares", h.List)
	mux.HandleFunc("DELETE /api/shares/{token}", h.Revoke)
	mux.HandleFunc("GET /api/s/{token}", h.Public)
	return mux, s, targets
}

func do(mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
	return w
}

func TestHandlersFlow(t *testing.T) {
	mux, _, targets := newMux(t, &alice)

	w := do(mux, "POST", "/api/shares", `{"target":"rev-1"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var l Link
	json.Unmarshal(w.Body.Bytes(), &l)
	if l.Creator != alice {
		t.Errorf("creator = %+v, want the signed-in person", l.Creator)
	}

	w = do(mux, "GET", "/api/s/"+l.Token, "")
	if w.Code != 200 {
		t.Fatalf("public: %d", w.Code)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"payload":{"hexes":1}}` {
		t.Errorf("public body = %s", got)
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") {
		t.Errorf("public headers = %v", w.Header())
	}

	w = do(mux, "GET", "/api/shares?target=rev-1", "")
	var list []Link
	json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != 200 || len(list) != 1 {
		t.Errorf("list: %d %s", w.Code, w.Body)
	}

	// A link whose target was deleted answers like an unknown one.
	delete(targets, "rev-1")
	if w = do(mux, "GET", "/api/s/"+l.Token, ""); w.Code != 404 {
		t.Errorf("dangling public: %d", w.Code)
	}
	targets["rev-1"] = `{}`

	if w = do(mux, "DELETE", "/api/shares/"+l.Token, ""); w.Code != http.StatusNoContent {
		t.Errorf("revoke: %d", w.Code)
	}
	if w = do(mux, "GET", "/api/s/"+l.Token, ""); w.Code != 404 {
		t.Errorf("revoked public: %d", w.Code)
	}
	if w = do(mux, "DELETE", "/api/shares/unknown", ""); w.Code != 404 {
		t.Errorf("revoke unknown: %d", w.Code)
	}
	if w = do(mux, "GET", "/api/s/unknown", ""); w.Code != 404 {
		t.Errorf("unknown public: %d", w.Code)
	}
}

func TestCreateUnknownTarget(t *testing.T) {
	mux, s, _ := newMux(t, &alice)
	if w := do(mux, "POST", "/api/shares", `{"target":"rev-9"}`); w.Code != 404 {
		t.Errorf("create unknown target: %d", w.Code)
	}
	if w := do(mux, "POST", "/api/shares", `{"target":""}`); w.Code != 400 {
		t.Errorf("create empty target: %d", w.Code)
	}
	if len(s.List("")) != 0 {
		t.Error("link created for a bad target")
	}
}

func TestManageNeedsSignIn(t *testing.T) {
	mux, s, _ := newMux(t, nil)
	if w := do(mux, "POST", "/api/shares", `{"target":"rev-1"}`); w.Code != 401 {
		t.Errorf("create: %d", w.Code)
	}
	if w := do(mux, "GET", "/api/shares", ""); w.Code != 401 {
		t.Errorf("list: %d", w.Code)
	}
	l, _ := s.Create("rev-1", alice)
	if w := do(mux, "DELETE", "/api/shares/"+l.Token, ""); w.Code != 401 {
		t.Errorf("revoke: %d", w.Code)
	}
	// The public route needs nobody.
	if w := do(mux, "GET", "/api/s/"+l.Token, ""); w.Code != 200 {
		t.Errorf("public: %d", w.Code)
	}
}
