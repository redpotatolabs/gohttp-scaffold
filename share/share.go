// Package share keeps public read-only links. A link is an unguessable token
// that points at a target the app names (a map id, a revision id, ...). The
// package knows nothing about what a target is: the app resolves it to the
// payload the link shows, so one app can show the live map and another a
// saved snapshot.
//
// Links are stored in one JSON file (shares.json), rewritten atomically on
// every change. Creating and revoking a link are written to the change log
// when one is configured.
package share

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/redpotatolabs/gohttp-scaffold/changelog"
)

// Change log actions written by the store.
const (
	ActionCreate = "share.create"
	ActionRevoke = "share.revoke"
)

// MaxTargetLen bounds the target string an app may store.
const MaxTargetLen = 256

// tokenBytes is the random part of a token: 128 bits.
const tokenBytes = 16

var (
	// ErrNotFound means the token does not exist, or (for Lookup) was revoked.
	ErrNotFound = errors.New("share: link not found")
	// ErrBadTarget means the target is empty or too long.
	ErrBadTarget = errors.New("share: bad target")
)

// Link is one public link.
type Link struct {
	Token     string           `json:"token"`
	Target    string           `json:"target"`
	Creator   changelog.Actor  `json:"creator"`
	Created   time.Time        `json:"created"`
	Revoked   bool             `json:"revoked,omitempty"`
	RevokedBy *changelog.Actor `json:"revoked_by,omitempty"`
	RevokedAt *time.Time       `json:"revoked_at,omitempty"`
}

// Store holds the links in memory and in a file.
type Store struct {
	mu    sync.Mutex
	path  string
	links map[string]*Link
	log   changelog.Recorder
	now   func() time.Time
}

// Open loads the links from path, or starts empty when the file does not
// exist. log may be nil, in which case nothing is logged.
func Open(path string, log changelog.Recorder) (*Store, error) {
	s := &Store{path: path, links: map[string]*Link{}, log: log, now: time.Now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("share: read %s: %w", path, err)
	}
	var list []*Link
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("share: parse %s: %w", path, err)
	}
	for _, l := range list {
		s.links[l.Token] = l
	}
	return s, nil
}

// Create makes a new link to target on behalf of by.
func (s *Store) Create(target string, by changelog.Actor) (Link, error) {
	if target == "" || len(target) > MaxTargetLen {
		return Link{}, ErrBadTarget
	}
	if by.ID == "" {
		return Link{}, errors.New("share: creator needs an id")
	}
	tok, err := newToken()
	if err != nil {
		return Link{}, err
	}
	now := s.now().UTC()
	l := &Link{Token: tok, Target: target, Creator: by, Created: now}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.links[tok] = l
	if err := s.saveLocked(); err != nil {
		delete(s.links, tok)
		return Link{}, err
	}
	if err := s.record(changelog.Entry{Time: now, Actor: by, Action: ActionCreate, Target: target}); err != nil {
		// A link nobody can account for must not exist: undo it.
		delete(s.links, tok)
		_ = s.saveLocked()
		return Link{}, err
	}
	return *l, nil
}

// Revoke turns a link off. Revoking a link that is already off does nothing.
//
// If the change log write fails, the link stays off and Revoke still returns
// the error, so the caller sees a failure; a retry then succeeds without a
// second log entry. This is deliberate: a link must never stay public because
// logging failed.
func (s *Store) Revoke(token string, by changelog.Actor) error {
	if by.ID == "" {
		return errors.New("share: revoker needs an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[token]
	if !ok {
		return ErrNotFound
	}
	if l.Revoked {
		return nil
	}
	now := s.now().UTC()
	prev := *l
	l.Revoked, l.RevokedBy, l.RevokedAt = true, &by, &now
	if err := s.saveLocked(); err != nil {
		*l = prev
		return err
	}
	if err := s.record(changelog.Entry{Time: now, Actor: by, Action: ActionRevoke, Target: l.Target}); err != nil {
		// The link stays off: leaving it on because the log failed would be worse.
		return err
	}
	return nil
}

// Lookup returns the link for token if it exists and is not revoked.
func (s *Store) Lookup(token string) (Link, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.links[token]
	if !ok || l.Revoked {
		return Link{}, false
	}
	return *l, true
}

// List returns the links for target, or every link when target is empty,
// newest first. Revoked links are included so editors can see them.
func (s *Store) List(target string) []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Link, 0, len(s.links))
	for _, l := range s.links {
		if target == "" || l.Target == target {
			out = append(out, *l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].Token < out[j].Token
	})
	return out
}

func (s *Store) record(e changelog.Entry) error {
	if s.log == nil {
		return nil
	}
	return s.log.Append(e)
}

// saveLocked writes every link to a temp file and renames it over path.
func (s *Store) saveLocked() error {
	list := make([]*Link, 0, len(s.links))
	for _, l := range s.links {
		list = append(list, l)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Token < list[j].Token })
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("share: encode: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".shares-*.json")
	if err != nil {
		return fmt.Errorf("share: save: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("share: save: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("share: save: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("share: save: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o640); err != nil {
		return fmt.Errorf("share: save: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("share: save: %w", err)
	}
	return nil
}

func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("share: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
