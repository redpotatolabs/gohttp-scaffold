package auth

import (
	"encoding/json"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// RequireRole lets a request through when the visitor is signed in and
// holds a role at least as high as level. Otherwise: nobody signed in gets
// a redirect to sign-in for a page, or 401 for anything else; a member
// without the role gets a "not a member" page or 403; a visitor whose roles
// Discord cannot confirm gets 403 with that message.
//
// A page is a GET or HEAD whose Accept header prefers text/html. Fetches
// from a page get the status codes, so the page can show the sign-in link
// itself instead of following a redirect into HTML.
func (a *Auth) RequireRole(level Level) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := a.sessions.fromRequest(r, a.cfg.CookieName, a.now())
			if sess == nil {
				if isPage(r) {
					http.Redirect(w, r, LoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
					return
				}
				http.Error(w, "sign in first", http.StatusUnauthorized)
				return
			}
			roles, err := a.memberRoles(r.Context(), sess)
			if err != nil {
				log.Printf("auth: role check user=%s: %v", sess.UserID, err)
				if refused(err) {
					a.deny(w, r, "Not a member", "You are not in our Discord server, so you cannot use this site.")
					return
				}
				a.deny(w, r, "Could not confirm your roles", "Discord did not confirm your membership of the server. Please try again shortly.")
				return
			}
			if a.levelFor(roles) < level {
				if level == Edit && a.levelFor(roles) == View {
					a.deny(w, r, "View only", "Your role lets you look but not change anything.")
					return
				}
				a.deny(w, r, "Not a member", "You do not have a role that can use this site.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// deny answers 403: a short page for a page request, plain text otherwise.
func (a *Auth) deny(w http.ResponseWriter, r *http.Request, title, message string) {
	if isPage(r) {
		writeMessage(w, http.StatusForbidden, title, message)
		return
	}
	http.Error(w, message, http.StatusForbidden)
}

// isPage says whether r is a browser navigating to a page, as opposed to a
// script fetching data.
func isPage(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Sec-Fetch-Mode") == "cors" || r.Header.Get("Sec-Fetch-Dest") == "empty" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// writeMessage renders a minimal page with a title and one line, and a link
// home. It needs no template and fits the scaffold's security policy.
func writeMessage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	t, m := html.EscapeString(title), html.EscapeString(message)
	_, _ = w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + t +
		"</title><style>body{font-family:system-ui,sans-serif;margin:3rem auto;max-width:32rem;padding:0 1rem;line-height:1.5}</style></head><body><h1>" + t +
		"</h1><p>" + m + "</p><p><a href=\"/\">Back to the site</a> · <a href=\"" + LoginPath + "\">Sign in again</a></p></body></html>"))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// CanonicalHost sends visits that come through the tunnel on any other
// address, like the site's old one, to host. Each address keeps its own
// sign-in, so a home screen shortcut to an old address would otherwise
// sign in on the new one and be signed out again on its next launch.
// Requests made directly on this host, like health checks, are left alone.
// An empty host does nothing.
func CanonicalHost(next http.Handler, host string) http.Handler {
	if host == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isDirectLocal(r) || strings.EqualFold(r.Host, host) {
			next.ServeHTTP(w, r)
			return
		}
		target := "https://" + host + r.URL.RequestURI()
		code := http.StatusMovedPermanently
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Keeps a form's method and body.
			code = http.StatusPermanentRedirect
		}
		http.Redirect(w, r, target, code)
	})
}

// isDirectLocal says whether r came straight from this machine, not
// through Cloudflare's tunnel.
func isDirectLocal(r *http.Request) bool {
	if r.Header.Get("Cf-Connecting-Ip") != "" {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
