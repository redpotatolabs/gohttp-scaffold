package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	discordoauth "github.com/redpotatolabs/discord-oauth"
	"golang.org/x/oauth2"
)

const (
	// roleCacheTTL limits calls to Discord's rate-limited member endpoint.
	// A removed role therefore keeps working for at most this long.
	roleCacheTTL = 5 * time.Minute
	// roleFailureTTL keeps a failed role lookup for a short while, so
	// someone who left the server cannot make every request call Discord.
	roleFailureTTL = time.Minute
	// roleStaleTTL is how long roles Discord last confirmed keep working
	// while Discord cannot be asked again, such as when it rate-limits or
	// is down. A visitor is not locked out by a passing failure, and a
	// removed role still stops working once Discord answers again, or
	// after this long.
	roleStaleTTL = time.Hour
	// rateLimitWait is the longest a role lookup waits for Discord's rate
	// limit before trying once more.
	rateLimitWait = 2 * time.Second
	// roleCheckTimeout bounds one role lookup, which runs on even if the
	// page that started it went away.
	roleCheckTimeout = 10 * time.Second
)

// Level is what a visitor may do.
type Level int

const (
	// None is a visitor who may not use the site.
	None Level = iota
	// View may read.
	View
	// Edit may change things, and may view.
	Edit
)

func (l Level) String() string {
	switch l {
	case View:
		return "view"
	case Edit:
		return "edit"
	}
	return "none"
}

// levelFor is the highest level roles grant. An empty ViewRoleIDs lets any
// member of the server view; roles came from the server, so a visitor with
// any answer is a member.
func (a *Auth) levelFor(roles []string) Level {
	if holdsAny(roles, a.cfg.EditRoleIDs) {
		return Edit
	}
	if len(a.cfg.ViewRoleIDs) == 0 || holdsAny(roles, a.cfg.ViewRoleIDs) {
		return View
	}
	return None
}

func holdsAny(roles, wanted []string) bool {
	return slices.ContainsFunc(roles, func(role string) bool { return slices.Contains(wanted, role) })
}

// lookupRoles reads the visitor's roles in the server with their own token,
// once more if Discord rate-limits briefly.
func (a *Auth) lookupRoles(ctx context.Context, token *oauth2.Token) ([]string, error) {
	roles, err := retryOnce(ctx, func() ([]string, error) {
		return a.client.FetchGuildMemberRoles(ctx, token, a.cfg.GuildID)
	})
	if err != nil {
		return nil, err
	}
	if roles == nil {
		roles = []string{}
	}
	return roles, nil
}

// memberRoles returns sess's roles, from the cache when it is fresh. A
// failed lookup keeps the roles Discord last confirmed, for up to
// roleStaleTTL, unless Discord refused the visitor's token itself. Otherwise
// it returns an error, so access is denied rather than assumed. A failure
// is kept for roleFailureTTL, so Discord is not asked on every request
// while it is failing.
func (a *Auth) memberRoles(ctx context.Context, sess *Session) ([]string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	now := a.now()
	if !sess.rolesCheckedAt.IsZero() && now.Sub(sess.rolesCheckedAt) < roleCacheTTL {
		return sess.roles, nil
	}
	if sess.rolesErr != nil && now.Sub(sess.rolesFailedAt) < roleFailureTTL {
		if a.lastGood(sess) {
			return sess.roles, nil
		}
		return nil, sess.rolesErr
	}
	// The check finishes even if the page that started it goes away, such
	// as on a reload, so it is not counted as a failure.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), roleCheckTimeout)
	defer cancel()
	// Holding sess.mu keeps two requests from using the same refresh token,
	// which Discord only accepts once.
	token, err := a.client.Refresh(ctx, sess.Token)
	if errors.Is(err, discordoauth.ErrSignInAgain) {
		a.sessions.delete(sess.ID)
		return nil, err
	}
	if err != nil {
		return a.keepOrFail(sess, err, now)
	}
	if token != sess.Token {
		a.sessions.updateToken(sess, token)
	}
	roles, err := a.lookupRoles(ctx, sess.Token)
	if err != nil {
		return a.keepOrFail(sess, err, now)
	}
	sess.roles, sess.rolesErr = roles, nil
	sess.rolesCheckedAt = now
	return roles, nil
}

// keepOrFail records a failed lookup and returns the last confirmed roles
// when they are recent enough and Discord did not refuse the visitor.
func (a *Auth) keepOrFail(sess *Session, err error, now time.Time) ([]string, error) {
	sess.rolesErr, sess.rolesFailedAt = err, now
	if a.lastGood(sess) && !refused(err) {
		log.Printf("auth: role check user=%s failed, keeping the roles from %s: %v", sess.UserID, sess.rolesCheckedAt.UTC().Format(time.TimeOnly), err)
		return sess.roles, nil
	}
	return nil, err
}

// lastGood reports whether sess has roles Discord confirmed recently enough
// to keep using while Discord cannot be asked.
func (a *Auth) lastGood(sess *Session) bool {
	return sess.roles != nil && !sess.rolesCheckedAt.IsZero() && a.now().Sub(sess.rolesCheckedAt) < roleStaleTTL
}

// refused reports whether Discord turned the visitor's token away, as
// opposed to failing for a while. Then the old roles must not be kept. A
// 404 from the member endpoint means they are not in the server.
func refused(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, " returned 401") || strings.Contains(msg, " returned 403") || strings.Contains(msg, " returned 404")
}

// rateLimited reports how long Discord asked to wait, when err is its rate
// limit.
func rateLimited(err error) (time.Duration, bool) {
	msg := err.Error()
	if !strings.Contains(msg, " returned 429") {
		return 0, false
	}
	wait := time.Second
	if i := strings.Index(msg, `"retry_after":`); i >= 0 {
		var secs float64
		if _, err := fmt.Sscan(strings.TrimSpace(msg[i+len(`"retry_after":`):]), &secs); err == nil && secs > 0 {
			wait = time.Duration(secs * float64(time.Second))
		}
	}
	return wait, true
}

// retryOnce calls fn, and once more if Discord rate-limited it for no
// longer than rateLimitWait.
func retryOnce[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	v, err := fn()
	if err == nil {
		return v, nil
	}
	wait, ok := rateLimited(err)
	if !ok || wait > rateLimitWait {
		return v, err
	}
	select {
	case <-ctx.Done():
		return v, err
	case <-time.After(wait):
	}
	return fn()
}
