package changelog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendWritesOneLinePerEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changes.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 11, 13, 20, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return fixed }

	a := Actor{ID: "111", Name: "Alice"}
	if err := l.Append(Entry{Actor: a, Action: "map.save", Target: "map"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{Actor: a, Action: "revision.delete", Target: "revision:abc"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening appends rather than truncating.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append(Entry{Actor: Actor{ID: "222"}, Action: "map.save", Target: "map"}); err != nil {
		t.Fatal(err)
	}
	l2.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		got = append(got, e)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if !got[0].Time.Equal(fixed) || got[0].Actor != a || got[0].Action != "map.save" {
		t.Errorf("first entry = %+v", got[0])
	}
	if got[1].Target != "revision:abc" || got[2].Actor.ID != "222" {
		t.Errorf("entries = %+v", got)
	}
}

func TestAppendRejectsIncompleteEntries(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "changes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Append(Entry{Actor: Actor{ID: "1"}}); err == nil {
		t.Error("missing action: want error")
	}
	if err := l.Append(Entry{Action: "x"}); err == nil {
		t.Error("missing actor id: want error")
	}
}

func TestAppendAfterClose(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "changes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := l.Append(Entry{Actor: Actor{ID: "1"}, Action: "x"}); err == nil {
		t.Error("want error after close")
	}
}
