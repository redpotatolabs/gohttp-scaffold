// Package auth puts a redpotatolabs site behind Discord sign-in, the way the
// schedule does it. A visitor signs in with their own Discord account; the
// site reads their roles in one server and lets them view or edit by role.
//
// Sessions live in memory and in DATA_DIR/sessions.json. The cookie carries
// only a random ID; the Discord token never leaves the server. Each session
// has a CSRF token for POST forms.
//
// Mounting:
//
//	a, err := auth.New(cfg)            // or auth.FromEnv()
//	a.Routes(mux)                      // /auth/login, /auth/callback, /auth/logout, /auth/me
//	mux.Handle("GET /api/maps", a.RequireRole(auth.View)(h))
//	mux.Handle("PUT /api/maps/{id}", a.RequireRole(auth.Edit)(h))
//	handler := auth.CanonicalHost(mux, cfg.PublicHost())
//
// Routes the app leaves outside RequireRole stay public: /healthz,
// /__build_id, the auth routes themselves, and public share links.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	discordoauth "github.com/redpotatolabs/discord-oauth"
	"golang.org/x/oauth2"

	"github.com/redpotatolabs/gohttp-scaffold/changelog"
)

const (
	// LoginPath starts a sign-in. ?next= names the page to return to.
	LoginPath = "/auth/login"
	// CallbackPath is where Discord sends the visitor back.
	CallbackPath = discordoauth.CallbackPath
	// LogoutPath ends the session. POST with the CSRF token.
	LogoutPath = "/auth/logout"
	// MePath tells the page who is signed in and what they may do.
	MePath = "/auth/me"

	stateCookie = "oauth_state"
	// retryStatePrefix marks a sign-in that is already an automatic retry
	// after a missing state cookie.
	retryStatePrefix = "retry."
	// askStatePrefix marks a sign-in that shows Discord's authorize screen,
	// after Discord refused one that skipped it.
	askStatePrefix  = "ask."
	exchangeTimeout = 15 * time.Second
)

// Scopes is what sign-in asks Discord for: who the visitor is and their
// roles in the server. guilds.members.read is what lets the visitor's own
// token read their roles, so no bot token is needed.
var Scopes = []string{discordoauth.ScopeIdentify, discordoauth.ScopeGuilds, "guilds.members.read"}

// DiscordClient is the part of discordoauth.Client this package uses.
// Tests pass a fake.
type DiscordClient interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchUser(ctx context.Context, token *oauth2.Token) (*discordoauth.User, error)
	FetchGuildMemberRoles(ctx context.Context, token *oauth2.Token, guildID string) ([]string, error)
	Refresh(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
}

// Config is everything sign-in needs. FromEnv fills it from the standard
// environment variables.
type Config struct {
	// ClientID and ClientSecret identify the Discord application. Not
	// needed when Client is set.
	ClientID     string
	ClientSecret string
	// PublicURL is the site's address, such as https://mud.potato.red. The
	// callback is PublicURL + CallbackPath, and CanonicalHost sends other
	// addresses here.
	PublicURL string
	// GuildID is the Discord server whose roles count.
	GuildID string
	// ViewRoleIDs may view. Empty means every member of the server may view.
	ViewRoleIDs []string
	// EditRoleIDs may edit, and may view. Empty means nobody may edit.
	EditRoleIDs []string
	// SessionFile is where sessions are kept across restarts, normally
	// DATA_DIR/sessions.json. Empty keeps them in memory only.
	SessionFile string
	// CookieName is the session cookie's name. Default "session".
	CookieName string
	// Client replaces the Discord client built from ClientID, ClientSecret
	// and PublicURL. Tests use it.
	Client DiscordClient
	// Insecure allows the cookies over plain HTTP, for local runs. Default
	// off: cookies carry Secure.
	Insecure bool
}

// PublicHost is PublicURL's host, for CanonicalHost. Empty when PublicURL
// is empty or not a URL.
func (c Config) PublicHost() string {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// FromEnv reads DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_GUILD_ID,
// DISCORD_VIEW_ROLE_IDS, DISCORD_EDIT_ROLE_IDS (comma-separated), PUBLIC_URL
// and DATA_DIR (default "."). A PUBLIC_URL that starts with http:// turns
// Insecure on, for local runs.
func FromEnv() Config {
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "."
	}
	publicURL := os.Getenv("PUBLIC_URL")
	return Config{
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		PublicURL:    publicURL,
		GuildID:      os.Getenv("DISCORD_GUILD_ID"),
		ViewRoleIDs:  splitIDs(os.Getenv("DISCORD_VIEW_ROLE_IDS")),
		EditRoleIDs:  splitIDs(os.Getenv("DISCORD_EDIT_ROLE_IDS")),
		SessionFile:  filepath.Join(dataDir, "sessions.json"),
		Insecure:     strings.HasPrefix(publicURL, "http://"),
	}
}

func splitIDs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Auth serves sign-in and guards handlers.
type Auth struct {
	cfg      Config
	client   DiscordClient
	sessions *sessionStore
	now      func() time.Time
}

// New checks cfg and loads the saved sessions.
func New(cfg Config) (*Auth, error) {
	if cfg.GuildID == "" {
		return nil, errors.New("auth: GuildID is required")
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "session"
	}
	client := cfg.Client
	if client == nil {
		c, err := discordoauth.New(discordoauth.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			PublicURL:    cfg.PublicURL,
			Scopes:       Scopes,
		})
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		client = c
	}
	sessions, err := newSessionStore(cfg.SessionFile)
	if err != nil {
		return nil, err
	}
	return &Auth{cfg: cfg, client: client, sessions: sessions, now: time.Now}, nil
}

// Routes mounts the sign-in routes on mux. They must stay outside
// RequireRole.
func (a *Auth) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+LoginPath, a.handleLogin)
	mux.HandleFunc("GET "+CallbackPath, a.handleCallback)
	mux.HandleFunc("POST "+LogoutPath, a.handleLogout)
	mux.HandleFunc("GET "+MePath, a.handleMe)
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := randomID()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ask := r.URL.Query().Get("ask") != ""
	if ask {
		state = askStatePrefix + state
	}
	if r.URL.Query().Get("retry") != "" {
		state = retryStatePrefix + state
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookie,
		Value:    state,
		Path:     CallbackPath,
		HttpOnly: true,
		Secure:   !a.cfg.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	if next := safeNext(r.URL.Query().Get("next")); next != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookie + "_next",
			Value:    next,
			Path:     CallbackPath,
			HttpOnly: true,
			Secure:   !a.cfg.Insecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
	}
	authURL := a.client.AuthCodeURL(state)
	if !ask {
		authURL = withoutReapproval(authURL)
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// safeNext keeps a return path on this site: an absolute path, not a URL.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return ""
	}
	return next
}

// withoutReapproval asks Discord to skip its authorize screen for a visitor
// who already approved the app with these scopes. Discord still asks the
// first time, and after the scopes change.
func withoutReapproval(authURL string) string {
	u, err := url.Parse(authURL)
	if err != nil {
		return authURL
	}
	q := u.Query()
	q.Set("prompt", "none")
	u.RawQuery = q.Encode()
	return u.String()
}

func (a *Auth) handleCallback(w http.ResponseWriter, r *http.Request) {
	state, err := r.Cookie(stateCookie)
	if err != nil || state.Value == "" {
		a.recoverSignIn(w, r, "Sign-in expired. Please try signing in again.")
		return
	}
	clear := func(name string) {
		http.SetCookie(w, &http.Cookie{Name: name, Path: CallbackPath, MaxAge: -1})
	}
	clear(stateCookie)
	landing := "/"
	if c, err := r.Cookie(stateCookie + "_next"); err == nil {
		if next := safeNext(c.Value); next != "" {
			landing = next
		}
		clear(stateCookie + "_next")
	}

	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(state.Value)) != 1 {
		a.recoverSignIn(w, r, "Sign-in failed: the request did not match. Please try again.")
		return
	}
	code := r.URL.Query().Get("code")
	// If Discord won't skip its authorize screen, sign in once more with it.
	if code == "" && r.URL.Query().Get("error") != "" && !strings.HasPrefix(state.Value, askStatePrefix) {
		log.Printf("auth: discord refused a sign-in without its authorize screen (%s): asking", r.URL.Query().Get("error"))
		http.Redirect(w, r, LoginPath+"?ask=1&next="+url.QueryEscape(landing), http.StatusFound)
		return
	}
	if code == "" {
		writeMessage(w, http.StatusBadRequest, "Sign-in cancelled", "Discord did not complete the sign-in.")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), exchangeTimeout)
	defer cancel()
	token, err := a.client.Exchange(ctx, code)
	if err != nil {
		log.Printf("auth: oauth exchange: %v", err)
		writeMessage(w, http.StatusBadGateway, "Sign-in failed", "Could not complete sign-in with Discord.")
		return
	}
	user, err := a.client.FetchUser(ctx, token)
	if err != nil {
		log.Printf("auth: fetch discord user: %v", err)
		writeMessage(w, http.StatusBadGateway, "Sign-in failed", "Could not load your Discord profile.")
		return
	}
	// Only members of the server get a session, so nobody else is kept
	// signed in or saved to the session file.
	roles, err := a.lookupRoles(ctx, token)
	if err != nil {
		log.Printf("auth: sign-in role check user=%s: %v", user.ID, err)
		if refused(err) {
			writeMessage(w, http.StatusForbidden, "Not a member", "You are not in our Discord server, so you cannot use this site.")
			return
		}
		writeMessage(w, http.StatusForbidden, "Could not confirm your roles",
			"Discord did not confirm your membership of the server. Make sure you are in it, then try again shortly.")
		return
	}
	sess, err := a.sessions.create(user.ID, user.DisplayName(), token, a.now())
	if err != nil {
		log.Printf("auth: create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess.mu.Lock()
	sess.roles, sess.rolesCheckedAt = roles, a.now()
	sess.mu.Unlock()
	http.SetCookie(w, a.sessionCookie(sess.ID, sess.ExpiresAt))
	log.Printf("auth: sign-in user=%q id=%s", sess.Username, sess.UserID)
	http.Redirect(w, r, landing, http.StatusFound)
}

// recoverSignIn handles a callback that cannot be trusted because its state
// cookie is missing or does not match. The code in it is never used.
// Someone already signed in just continues, and anyone else gets one fresh
// attempt. The state marks that attempt, because a browser that lost the
// cookie cannot be relied on to keep another one.
func (a *Auth) recoverSignIn(w http.ResponseWriter, r *http.Request, message string) {
	if a.sessions.fromRequest(r, a.cfg.CookieName, a.now()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if strings.HasPrefix(r.URL.Query().Get("state"), retryStatePrefix) {
		writeMessage(w, http.StatusBadRequest, "Sign-in failed", message)
		return
	}
	log.Printf("auth: sign-in callback without a valid state cookie: retrying")
	http.Redirect(w, r, LoginPath+"?retry=1", http.StatusFound)
}

// handleLogout ends the session. The CSRF token comes as the form field
// "csrf" or the X-CSRF-Token header.
func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess := a.sessions.fromRequest(r, a.cfg.CookieName, a.now()); sess != nil {
		if !a.validCSRF(r, sess) {
			writeMessage(w, http.StatusBadRequest, "Sign-out failed", "Please reload the page and try again.")
			return
		}
		a.sessions.delete(sess.ID)
	}
	http.SetCookie(w, a.sessionCookie("", time.Time{}))
	http.Redirect(w, r, "/", http.StatusFound)
}

// Me is what /auth/me returns.
type Me struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// View and Edit say what the visitor may do right now.
	View bool `json:"view"`
	Edit bool `json:"edit"`
	// CSRF goes in the "csrf" form field or the X-CSRF-Token header of
	// every POST, PUT and DELETE.
	CSRF string `json:"csrf"`
}

// handleMe answers 401 when nobody is signed in, so a page can offer the
// sign-in link instead of redirecting a fetch.
func (a *Auth) handleMe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess := a.sessions.fromRequest(r, a.cfg.CookieName, a.now())
	if sess == nil {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	roles, err := a.memberRoles(r.Context(), sess)
	if err != nil {
		log.Printf("auth: role check user=%s: %v", sess.UserID, err)
		http.Error(w, "could not confirm your roles", http.StatusForbidden)
		return
	}
	level := a.levelFor(roles)
	writeJSON(w, Me{ID: sess.UserID, Name: sess.Username, View: level >= View, Edit: level >= Edit, CSRF: sess.CSRFToken})
}

func (a *Auth) sessionCookie(id string, expires time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     a.cfg.CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   !a.cfg.Insecure,
		SameSite: http.SameSiteLaxMode,
	}
	if id == "" {
		c.MaxAge = -1
	} else {
		c.Expires = expires
	}
	return c
}

// validCSRF says whether r carries sess's token, in the "csrf" form field
// or the X-CSRF-Token header.
func (a *Auth) validCSRF(r *http.Request, sess *Session) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			return false
		}
		got = r.PostForm.Get("csrf")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) == 1
}

func randomID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Actor is the signed-in visitor behind r, for the share and changelog
// packages (share.Identify has this shape). ok is false when nobody is
// signed in. It does not check roles; RequireRole does that.
func (a *Auth) Actor(r *http.Request) (changelog.Actor, bool) {
	sess := a.sessions.fromRequest(r, a.cfg.CookieName, a.now())
	if sess == nil {
		return changelog.Actor{}, false
	}
	return changelog.Actor{ID: sess.UserID, Name: sess.Username}, true
}

// SessionOf returns r's session, or nil. Handlers that need the CSRF token
// use it; most only need Actor.
func (a *Auth) SessionOf(r *http.Request) *Session {
	return a.sessions.fromRequest(r, a.cfg.CookieName, a.now())
}
