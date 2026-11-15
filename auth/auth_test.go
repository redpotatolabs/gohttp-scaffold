package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	discordoauth "github.com/redpotatolabs/discord-oauth"
	"golang.org/x/oauth2"
)

const (
	guild    = "g1"
	viewRole = "r-view"
	editRole = "r-edit"
)

// fakeDiscord stands in for Discord. Roles and errors are set per test.
type fakeDiscord struct {
	mu         sync.Mutex
	roles      []string
	rolesErr   error
	refreshErr error
	fetches    int
	refreshes  int
	user       *discordoauth.User
}

func (f *fakeDiscord) AuthCodeURL(state string) string {
	return "https://discord.test/authorize?state=" + url.QueryEscape(state) + "&client_id=x"
}

func (f *fakeDiscord) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if code != "good" {
		return nil, errors.New("bad code")
	}
	return &oauth2.Token{AccessToken: "tok-" + code, RefreshToken: "ref-1", Expiry: time.Now().Add(time.Hour)}, nil
}

func (f *fakeDiscord) FetchUser(ctx context.Context, token *oauth2.Token) (*discordoauth.User, error) {
	if f.user != nil {
		return f.user, nil
	}
	return &discordoauth.User{ID: "u1", Username: "roy"}, nil
}

func (f *fakeDiscord) FetchGuildMemberRoles(ctx context.Context, token *oauth2.Token, guildID string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	if guildID != guild {
		return nil, errors.New("wrong guild " + guildID)
	}
	if f.rolesErr != nil {
		return nil, f.rolesErr
	}
	return append([]string(nil), f.roles...), nil
}

func (f *fakeDiscord) Refresh(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	if f.refreshErr != nil {
		return nil, f.refreshErr
	}
	return token, nil
}

func (f *fakeDiscord) set(roles []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.roles, f.rolesErr = roles, err
}

func (f *fakeDiscord) fetched() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

type fixture struct {
	t       *testing.T
	auth    *Auth
	discord *fakeDiscord
	mux     *http.ServeMux
	clock   time.Time
	file    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := &fakeDiscord{roles: []string{viewRole}}
	file := filepath.Join(t.TempDir(), "sessions.json")
	a, err := New(Config{
		PublicURL:   "https://mud.test",
		GuildID:     guild,
		ViewRoleIDs: []string{viewRole},
		EditRoleIDs: []string{editRole},
		SessionFile: file,
		Client:      d,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, auth: a, discord: d, mux: http.NewServeMux(), clock: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), file: file}
	a.now = func() time.Time { return f.clock }
	a.Routes(f.mux)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	f.mux.Handle("GET /view", a.RequireRole(View)(ok))
	f.mux.Handle("GET /edit", a.RequireRole(Edit)(ok))
	f.mux.Handle("GET /api/data", a.RequireRole(View)(ok))
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct{ N int }
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		_, _ = w.Write([]byte("saved"))
	})
	f.mux.Handle("PUT /api/data", a.RequireRole(Edit)(echo))
	f.mux.Handle("POST /api/form", a.RequireRole(Edit)(ok))
	return f
}

func (f *fixture) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signIn runs the login and callback and returns the session cookie.
func (f *fixture) signIn() *http.Cookie {
	f.t.Helper()
	login := f.do(httptest.NewRequest("GET", LoginPath+"?next=/maps/7", nil))
	if login.Code != http.StatusFound {
		f.t.Fatalf("login: %d %s", login.Code, login.Body)
	}
	loc, _ := url.Parse(login.Header().Get("Location"))
	if loc.Query().Get("prompt") != "none" {
		f.t.Fatalf("login should skip the authorize screen, got %s", loc)
	}
	state := cookie(login, stateCookie)
	if state == nil || !state.Secure || !state.HttpOnly || state.Path != CallbackPath {
		f.t.Fatalf("state cookie wrong: %+v", state)
	}
	cb := httptest.NewRequest("GET", CallbackPath+"?state="+url.QueryEscape(state.Value)+"&code=good", nil)
	cb.AddCookie(state)
	cb.AddCookie(cookie(login, stateCookie+"_next"))
	rec := f.do(cb)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/maps/7" {
		f.t.Fatalf("callback: %d %s -> %s", rec.Code, rec.Body, rec.Header().Get("Location"))
	}
	c := cookie(rec, "session")
	if c == nil || c.Value == "" || !c.Secure || !c.HttpOnly {
		f.t.Fatalf("session cookie wrong: %+v", c)
	}
	return c
}

func page(path string, c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Accept", "text/html,*/*")
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func fetch(path string, c *http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestSignInAndView(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	if rec := f.do(page("/view", c)); rec.Code != 200 {
		t.Fatalf("view with role: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(page("/edit", c)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "View only") {
		t.Fatalf("edit with view role: %d %s", rec.Code, rec.Body)
	}
	if got, ok := f.auth.Actor(page("/", c)); !ok || got.ID != "u1" || got.Name != "roy" {
		t.Fatalf("actor: %+v %v", got, ok)
	}
	// The sign-in role check is cached: no second call.
	if n := f.discord.fetched(); n != 1 {
		t.Fatalf("fetches after sign-in and two requests: %d", n)
	}
}

func TestNotSignedIn(t *testing.T) {
	f := newFixture(t)
	rec := f.do(page("/view?x=1", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != LoginPath+"?next="+url.QueryEscape("/view?x=1") {
		t.Fatalf("page without session: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := f.do(fetch("/api/data", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fetch without session: %d", rec.Code)
	}
	if rec := f.do(fetch(MePath, nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me without session: %d", rec.Code)
	}
	if _, ok := f.auth.Actor(page("/", nil)); ok {
		t.Fatal("actor without session")
	}
}

func TestLoginNextMustBeLocal(t *testing.T) {
	f := newFixture(t)
	for _, next := range []string{"https://evil.test/", "//evil.test", "/ok\r\nSet-Cookie: x"} {
		rec := f.do(httptest.NewRequest("GET", LoginPath+"?next="+url.QueryEscape(next), nil))
		if cookie(rec, stateCookie+"_next") != nil {
			t.Fatalf("next %q was kept", next)
		}
	}
}

func TestNonMemberGetsNoSession(t *testing.T) {
	f := newFixture(t)
	f.discord.set(nil, errors.New("discord returned 404: unknown member"))
	login := f.do(httptest.NewRequest("GET", LoginPath, nil))
	state := cookie(login, stateCookie)
	cb := httptest.NewRequest("GET", CallbackPath+"?state="+url.QueryEscape(state.Value)+"&code=good", nil)
	cb.AddCookie(state)
	rec := f.do(cb)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Not a member") {
		t.Fatalf("non-member callback: %d %s", rec.Code, rec.Body)
	}
	if cookie(rec, "session") != nil {
		t.Fatal("non-member got a session cookie")
	}
	if _, err := os.Stat(f.file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sessions file written for a non-member: %v", err)
	}
}

func TestMemberWithoutRole(t *testing.T) {
	f := newFixture(t)
	f.discord.set([]string{"other"}, nil)
	c := f.signIn()
	rec := f.do(page("/view", c))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Not a member") {
		t.Fatalf("member without role: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(fetch("/api/data", c)); rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("fetch without role should be plain 403: %d %s", rec.Code, rec.Body)
	}
}

func TestEmptyViewRolesMeansAnyMember(t *testing.T) {
	f := newFixture(t)
	f.auth.cfg.ViewRoleIDs = nil
	f.discord.set([]string{}, nil)
	c := f.signIn()
	if rec := f.do(page("/view", c)); rec.Code != 200 {
		t.Fatalf("member with no roles: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(page("/edit", c)); rec.Code != http.StatusForbidden {
		t.Fatalf("edit with no roles: %d", rec.Code)
	}
}

func TestEditRoleImpliesView(t *testing.T) {
	f := newFixture(t)
	f.discord.set([]string{editRole}, nil)
	c := f.signIn()
	for _, p := range []string{"/view", "/edit"} {
		if rec := f.do(page(p, c)); rec.Code != 200 {
			t.Fatalf("%s with edit role: %d", p, rec.Code)
		}
	}
	rec := f.do(fetch(MePath, c))
	var me Me
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil || !me.View || !me.Edit || me.CSRF == "" || me.Name != "roy" {
		t.Fatalf("me: %d %s (%v)", rec.Code, rec.Body, err)
	}
}

func TestRolesRecheckedAfterCacheTTL(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	f.clock = f.clock.Add(roleCacheTTL + time.Second)
	f.discord.set([]string{"other"}, nil)
	if rec := f.do(page("/view", c)); rec.Code != http.StatusForbidden {
		t.Fatalf("removed role still works: %d", rec.Code)
	}
	if n := f.discord.fetched(); n != 2 {
		t.Fatalf("fetches: %d", n)
	}
}

func TestStaleRolesKeptWhileDiscordFails(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	f.clock = f.clock.Add(roleCacheTTL + time.Second)
	f.discord.set(nil, errors.New("discord returned 503"))
	if rec := f.do(page("/view", c)); rec.Code != 200 {
		t.Fatalf("passing failure locked the visitor out: %d %s", rec.Code, rec.Body)
	}
	// The failure is remembered: no new call within roleFailureTTL.
	f.do(page("/view", c))
	if n := f.discord.fetched(); n != 2 {
		t.Fatalf("fetches during failure window: %d", n)
	}
	// After roleStaleTTL the old roles no longer count.
	f.clock = f.clock.Add(roleStaleTTL)
	if rec := f.do(page("/view", c)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "confirm") {
		t.Fatalf("stale roles kept too long: %d %s", rec.Code, rec.Body)
	}
}

func TestRefusedTokenDropsRoles(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	f.clock = f.clock.Add(roleCacheTTL + time.Second)
	f.discord.set(nil, errors.New("discord returned 403: forbidden"))
	if rec := f.do(page("/view", c)); rec.Code != http.StatusForbidden {
		t.Fatalf("refused token kept access: %d", rec.Code)
	}
}

func TestSignInAgainEndsSession(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	f.clock = f.clock.Add(roleCacheTTL + time.Second)
	f.discord.mu.Lock()
	f.discord.refreshErr = discordoauth.ErrSignInAgain
	f.discord.mu.Unlock()
	// Treated as signed out at once: a page goes to sign-in and back.
	rec := f.do(page("/view", c))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != LoginPath+"?next=%2Fview" {
		t.Fatalf("page on sign-in-again: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
	// The session is gone, so the next request has nothing to refresh.
	if rec := f.do(page("/view", c)); rec.Code != http.StatusFound {
		t.Fatalf("session should be deleted, got %d", rec.Code)
	}

	// A fetch gets 401, from RequireRole and from /auth/me.
	f2 := newFixture(t)
	c2 := f2.signIn()
	f2.clock = f2.clock.Add(roleCacheTTL + time.Second)
	f2.discord.mu.Lock()
	f2.discord.refreshErr = discordoauth.ErrSignInAgain
	f2.discord.mu.Unlock()
	if rec := f2.do(fetch("/api/data", c2)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fetch on sign-in-again: %d", rec.Code)
	}
	f3 := newFixture(t)
	c3 := f3.signIn()
	f3.clock = f3.clock.Add(roleCacheTTL + time.Second)
	f3.discord.mu.Lock()
	f3.discord.refreshErr = discordoauth.ErrSignInAgain
	f3.discord.mu.Unlock()
	if rec := f3.do(fetch(MePath, c3)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me on sign-in-again: %d", rec.Code)
	}
}

func TestUnsafeMethodsNeedCSRF(t *testing.T) {
	f := newFixture(t)
	f.discord.set([]string{editRole}, nil)
	c := f.signIn()
	sess := f.auth.SessionOf(page("/", c))

	put := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("PUT", "/api/data", strings.NewReader(`{"N":1}`))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("X-CSRF-Token", token)
		}
		r.AddCookie(c)
		return f.do(r)
	}
	if rec := put(""); rec.Code != http.StatusForbidden {
		t.Fatalf("PUT without token: %d %s", rec.Code, rec.Body)
	}
	if rec := put("wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("PUT with wrong token: %d", rec.Code)
	}
	// With the header the JSON body reaches the handler untouched.
	if rec := put(sess.CSRFToken); rec.Code != 200 || rec.Body.String() != "saved" {
		t.Fatalf("PUT with token: %d %s", rec.Code, rec.Body)
	}
	// A text/plain body, as a cross-site form would send, never reaches the handler.
	r := httptest.NewRequest("PUT", "/api/data", strings.NewReader(`{"N":1}`))
	r.Header.Set("Content-Type", "text/plain")
	r.AddCookie(c)
	if rec := f.do(r); rec.Code != http.StatusForbidden {
		t.Fatalf("text/plain PUT: %d", rec.Code)
	}
	// A form may carry the token as a field.
	form := httptest.NewRequest("POST", "/api/form", strings.NewReader("csrf="+url.QueryEscape(sess.CSRFToken)))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.AddCookie(c)
	if rec := f.do(form); rec.Code != 200 {
		t.Fatalf("form POST with field: %d", rec.Code)
	}
	// GET never needs it.
	if rec := f.do(page("/edit", c)); rec.Code != 200 {
		t.Fatalf("GET with no token: %d", rec.Code)
	}
}

func TestRetryKeepsNext(t *testing.T) {
	f := newFixture(t)
	login := f.do(httptest.NewRequest("GET", LoginPath+"?next=/maps/9", nil))
	// The state cookie is lost but the next cookie survived.
	cb := httptest.NewRequest("GET", CallbackPath+"?state=whatever&code=good", nil)
	cb.AddCookie(cookie(login, stateCookie+"_next"))
	rec := f.do(cb)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Path != LoginPath || loc.Query().Get("retry") != "1" || loc.Query().Get("next") != "/maps/9" {
		t.Fatalf("retry should keep next: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRateLimitRetriedOnce(t *testing.T) {
	f := newFixture(t)
	f.discord.set(nil, errors.New(`discord returned 429: {"retry_after":0.01}`))
	// The first call fails with 429, the second succeeds.
	go func() {
		time.Sleep(5 * time.Millisecond)
		f.discord.set([]string{viewRole}, nil)
	}()
	c := f.signIn()
	if rec := f.do(page("/view", c)); rec.Code != 200 {
		t.Fatalf("after retry: %d", rec.Code)
	}
}

func TestCallbackStateMismatch(t *testing.T) {
	f := newFixture(t)
	login := f.do(httptest.NewRequest("GET", LoginPath, nil))
	state := cookie(login, stateCookie)
	cb := httptest.NewRequest("GET", CallbackPath+"?state=forged&code=good", nil)
	cb.AddCookie(state)
	rec := f.do(cb)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != LoginPath+"?retry=1" {
		t.Fatalf("mismatch should retry once: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
	if cookie(rec, "session") != nil {
		t.Fatal("forged state got a session")
	}
	// A retry that still has no cookie is an error, not a loop.
	again := f.do(httptest.NewRequest("GET", CallbackPath+"?state="+retryStatePrefix+"x&code=good", nil))
	if again.Code != http.StatusBadRequest {
		t.Fatalf("second failure should stop: %d", again.Code)
	}
}

func TestDiscordRefusesSilentSignIn(t *testing.T) {
	f := newFixture(t)
	login := f.do(httptest.NewRequest("GET", LoginPath+"?next=/maps/2", nil))
	state := cookie(login, stateCookie)
	cb := httptest.NewRequest("GET", CallbackPath+"?state="+url.QueryEscape(state.Value)+"&error=consent_required", nil)
	cb.AddCookie(state)
	cb.AddCookie(cookie(login, stateCookie+"_next"))
	rec := f.do(cb)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || loc.Path != LoginPath || loc.Query().Get("ask") != "1" || loc.Query().Get("next") != "/maps/2" {
		t.Fatalf("should ask with the authorize screen: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}
	// The ask sign-in shows the screen and does not loop.
	ask := f.do(httptest.NewRequest("GET", rec.Header().Get("Location"), nil))
	askURL, _ := url.Parse(ask.Header().Get("Location"))
	if askURL.Query().Get("prompt") == "none" {
		t.Fatal("ask sign-in still skips the screen")
	}
	askState := cookie(ask, stateCookie)
	cb2 := httptest.NewRequest("GET", CallbackPath+"?state="+url.QueryEscape(askState.Value)+"&error=access_denied", nil)
	cb2.AddCookie(askState)
	if rec := f.do(cb2); rec.Code != http.StatusBadRequest {
		t.Fatalf("cancelled ask sign-in should be 400, got %d", rec.Code)
	}
}

func TestLogoutNeedsCSRF(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	sess := f.auth.SessionOf(page("/", c))
	bad := httptest.NewRequest("POST", LogoutPath, strings.NewReader("csrf=wrong"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(c)
	if rec := f.do(bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("logout with wrong csrf: %d", rec.Code)
	}
	if rec := f.do(page("/view", c)); rec.Code != 200 {
		t.Fatalf("session should survive a bad logout: %d", rec.Code)
	}
	good := httptest.NewRequest("POST", LogoutPath, nil)
	good.Header.Set("X-CSRF-Token", sess.CSRFToken)
	good.AddCookie(c)
	rec := f.do(good)
	if rec.Code != http.StatusFound || cookie(rec, "session").MaxAge != -1 {
		t.Fatalf("logout: %d %+v", rec.Code, cookie(rec, "session"))
	}
	if rec := f.do(page("/view", c)); rec.Code != http.StatusFound {
		t.Fatalf("session should be gone: %d", rec.Code)
	}
}

func TestSessionsSurviveRestart(t *testing.T) {
	f := newFixture(t)
	c := f.signIn()
	info, err := os.Stat(f.file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("sessions file is world readable: %v", info.Mode())
	}
	a2, err := New(Config{GuildID: guild, ViewRoleIDs: []string{viewRole}, SessionFile: f.file, Client: f.discord})
	if err != nil {
		t.Fatal(err)
	}
	a2.now = f.auth.now
	if got, ok := a2.Actor(page("/", c)); !ok || got.ID != "u1" {
		t.Fatalf("session not reloaded: %+v %v", got, ok)
	}
	// Expired sessions are dropped.
	f.clock = f.clock.Add(sessionTTL + time.Hour)
	if _, ok := a2.Actor(page("/", c)); ok {
		t.Fatal("expired session still valid")
	}
}

func TestCorruptSessionsFileIsAnError(t *testing.T) {
	file := filepath.Join(t.TempDir(), "sessions.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{GuildID: guild, SessionFile: file, Client: &fakeDiscord{}}); err == nil {
		t.Fatal("corrupt sessions file accepted")
	}
}

func TestNewNeedsGuildAndClient(t *testing.T) {
	if _, err := New(Config{Client: &fakeDiscord{}}); err == nil {
		t.Fatal("missing guild accepted")
	}
	if _, err := New(Config{GuildID: guild}); err == nil {
		t.Fatal("missing client id accepted")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("DISCORD_CLIENT_ID", "id")
	t.Setenv("DISCORD_CLIENT_SECRET", "secret")
	t.Setenv("DISCORD_GUILD_ID", guild)
	t.Setenv("DISCORD_VIEW_ROLE_IDS", "a, b,,")
	t.Setenv("DISCORD_EDIT_ROLE_IDS", "c")
	t.Setenv("PUBLIC_URL", "http://localhost:8080")
	t.Setenv("DATA_DIR", "/data")
	cfg := FromEnv()
	if cfg.ClientID != "id" || cfg.GuildID != guild || len(cfg.ViewRoleIDs) != 2 || cfg.EditRoleIDs[0] != "c" ||
		cfg.SessionFile != "/data/sessions.json" || !cfg.Insecure || cfg.PublicHost() != "localhost:8080" {
		t.Fatalf("FromEnv: %+v", cfg)
	}
	cfg.SessionFile = ""
	if _, err := New(cfg); err != nil {
		t.Fatalf("New from env: %v", err)
	}
}

func TestCanonicalHost(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	h := CanonicalHost(next, "mud.potato.red")

	r := httptest.NewRequest("GET", "/maps/1?x=1", nil)
	r.Host = "mud.klinke.wtf"
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Cf-Connecting-Ip", "1.2.3.4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://mud.potato.red/maps/1?x=1" {
		t.Fatalf("other host: %d -> %s", rec.Code, rec.Header().Get("Location"))
	}

	r = httptest.NewRequest("POST", "/auth/logout", nil)
	r.Host = "mud.klinke.wtf"
	r.Header.Set("Cf-Connecting-Ip", "1.2.3.4")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("POST on other host: %d", rec.Code)
	}

	r = httptest.NewRequest("GET", "/healthz", nil)
	r.Host = "localhost:8080"
	r.RemoteAddr = "127.0.0.1:5555"
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 204 {
		t.Fatalf("direct local: %d", rec.Code)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Host = "MUD.potato.red"
	r.Header.Set("Cf-Connecting-Ip", "1.2.3.4")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 204 {
		t.Fatalf("canonical host: %d", rec.Code)
	}

	r = httptest.NewRequest("GET", "/", nil)
	r.Host = "anything.test"
	r.Header.Set("Cf-Connecting-Ip", "1.2.3.4")
	rec = httptest.NewRecorder()
	CanonicalHost(next, "").ServeHTTP(rec, r)
	if rec.Code != 204 {
		t.Fatalf("empty host should pass through: %d", rec.Code)
	}
}
