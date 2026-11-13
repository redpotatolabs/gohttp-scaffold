// Package changelog keeps an append-only record of who changed what, one JSON
// object per line (changes.jsonl). Entries are written and synced before
// Append returns, so a change the app reports as saved is also logged.
package changelog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Actor is the person behind a change: their Discord user ID and the name
// shown for them at the time.
type Actor struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// Entry is one line of the log.
type Entry struct {
	Time   time.Time `json:"time"`
	Actor  Actor     `json:"actor"`
	Action string    `json:"action"`
	// Target names what changed, for example "map" or "revision:<id>". The
	// share store logs the link's raw target; its share.* action is what marks
	// the entry as being about a link, so apps should not prefix it.
	Target string `json:"target"`
}

// Recorder is anything that takes log entries. *Log implements it; tests
// and callers that want no log can pass their own.
type Recorder interface {
	Append(Entry) error
}

// Log appends entries to a file.
type Log struct {
	mu  sync.Mutex
	f   *os.File
	now func() time.Time
}

// Open opens (or creates) the log file at path for appending.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("changelog: open %s: %w", path, err)
	}
	return &Log{f: f, now: time.Now}, nil
}

// Append writes e as one line. A zero Time is set to now (UTC). Action and
// Actor.ID are required.
func (l *Log) Append(e Entry) error {
	if e.Action == "" {
		return errors.New("changelog: entry needs an action")
	}
	if e.Actor.ID == "" {
		return errors.New("changelog: entry needs an actor id")
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("changelog: encode: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return errors.New("changelog: log is closed")
	}
	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("changelog: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("changelog: sync: %w", err)
	}
	return nil
}

// Close closes the file. Append after Close returns an error.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
