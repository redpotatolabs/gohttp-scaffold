package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const sessionTTL = 30 * 24 * time.Hour

// signInVersion goes up when sign-in asks Discord for more, so sessions
// made before it are dropped and their visitors sign in again. Version 1
// asks for identify, guilds and guilds.members.read.
const signInVersion = 1

// Session is one signed-in visitor. The cookie carries only ID.
type Session struct {
	ID        string
	UserID    string
	Username  string
	CSRFToken string
	Token     *oauth2.Token
	ExpiresAt time.Time

	mu             sync.Mutex
	roles          []string
	rolesCheckedAt time.Time
	rolesErr       error
	rolesFailedAt  time.Time
}

// savedSession is a Session as sessions.json keeps it. Role checks are not
// saved, so they run again after a restart.
type savedSession struct {
	ID        string
	UserID    string
	Username  string
	CSRFToken string
	Token     *oauth2.Token
	ExpiresAt time.Time
	Version   int `json:",omitempty"`
}

// sessionStore holds the live sessions and mirrors them to a file.
// Handlers keep *Session pointers for their role caches, so the map is the
// source of truth and the file its copy.
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	path     string
}

// newSessionStore loads path, or starts empty when it does not exist. An
// empty path keeps sessions in memory only. A file that cannot be parsed
// is an error, so a corrupt file is noticed rather than silently emptied.
func newSessionStore(path string) (*sessionStore, error) {
	s := &sessionStore{sessions: map[string]*Session{}, path: path}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("auth: read %s: %w", path, err)
	}
	var saved []savedSession
	if err := json.Unmarshal(raw, &saved); err != nil {
		return nil, fmt.Errorf("auth: parse %s: %w", path, err)
	}
	now := time.Now()
	for _, v := range saved {
		if !now.Before(v.ExpiresAt) || v.Version < signInVersion || v.Token == nil {
			continue
		}
		s.sessions[v.ID] = &Session{
			ID: v.ID, UserID: v.UserID, Username: v.Username,
			CSRFToken: v.CSRFToken, Token: v.Token, ExpiresAt: v.ExpiresAt,
		}
	}
	return s, nil
}

// saveLocked writes every session to a temp file and renames it over path.
// A failure is logged rather than returned: it only costs a sign-in after
// the next restart.
func (s *sessionStore) saveLocked() {
	if s.path == "" {
		return
	}
	list := make([]savedSession, 0, len(s.sessions))
	for _, v := range s.sessions {
		list = append(list, savedSession{
			ID: v.ID, UserID: v.UserID, Username: v.Username, CSRFToken: v.CSRFToken,
			Token: v.Token, ExpiresAt: v.ExpiresAt, Version: signInVersion,
		})
	}
	if err := writeFileAtomic(s.path, list); err != nil {
		log.Printf("auth: save sessions: %v", err)
	}
}

func writeFileAtomic(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sessions-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// The file holds Discord tokens: owner and group only.
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *sessionStore) create(userID, username string, token *oauth2.Token, now time.Time) (*Session, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	csrf, err := randomID()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:        id,
		UserID:    userID,
		Username:  username,
		CSRFToken: csrf,
		Token:     token,
		ExpiresAt: now.Add(sessionTTL),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Expired sessions are only ever removed here or on lookup; sign-ins
	// are rare enough that a sweep on create is cheap and keeps the map
	// bounded.
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[id] = sess
	s.saveLocked()
	return sess, nil
}

func (s *sessionStore) fromRequest(r *http.Request, cookieName string, now time.Time) *Session {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return nil
	}
	if now.After(sess.ExpiresAt) {
		delete(s.sessions, c.Value)
		s.saveLocked()
		return nil
	}
	return sess
}

// updateToken saves a renewed Discord token. Discord replaces the refresh
// token each time, so losing it would mean signing in again. The caller
// holds sess.mu.
func (s *sessionStore) updateToken(sess *Session, token *oauth2.Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.Token = token
	s.saveLocked()
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return
	}
	delete(s.sessions, id)
	s.saveLocked()
}
