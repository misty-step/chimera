package inlet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"chimera/pkg/objstore"
)

// Entry is one item of the triage inbox: the request body exactly as it
// arrived, and nothing derived from it.
type Entry struct {
	Schema     string    `json:"schema"`
	ReceivedAt time.Time `json:"received_at"`
	Owner      bool      `json:"owner"`            // true only for an owner nit that could not be routed
	Reason     string    `json:"reason,omitempty"` // why an owner nit landed here
	Body       []byte    `json:"body"`             // verbatim; base64 in JSON
}

// EntrySchema identifies a stored triage entry.
const EntrySchema = "chimera.inlet.triage/v1"

// Inbox is the triage inbox. Append is the only compute unauthenticated
// input ever triggers (PRODUCT.md §2.6).
type Inbox interface {
	Append(ctx context.Context, e Entry) error
}

// MemInbox is an in-memory Inbox for tests.
type MemInbox struct {
	mu      sync.Mutex
	entries []Entry
}

// Append implements Inbox.
func (m *MemInbox) Append(_ context.Context, e Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.Body = append([]byte{}, e.Body...)
	m.entries = append(m.entries, e)
	return nil
}

// Entries returns a copy of everything appended so far.
func (m *MemInbox) Entries() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Entry{}, m.entries...)
}

// StoreInbox appends triage entries to the object store as write-once
// objects inlet/<repo>/triage/<YYYY-MM-DD>/<seq>.json. The sequence number
// is claimed by the conditional PUT itself, so concurrent writers never
// overwrite one another.
type StoreInbox struct {
	Store objstore.Store
	Repo  string

	mu   sync.Mutex
	day  string
	next int
}

// maxTriagePerDay bounds the inbox; the rate limiter keeps real traffic far below it.
const maxTriagePerDay = 999999

// TriageKey is the object-store key of a triage entry.
func TriageKey(repo, day string, seq int) string {
	return fmt.Sprintf("inlet/%s/triage/%s/%06d.json", repo, day, seq)
}

// highest lists the day's entries and returns the next free sequence number.
func (s *StoreInbox) highest(ctx context.Context, day string) (int, error) {
	keys, err := s.Store.List(ctx, fmt.Sprintf("inlet/%s/triage/%s/", s.Repo, day))
	if err != nil {
		return 0, err
	}
	next := 1
	for _, k := range keys {
		var n int
		if _, err := fmt.Sscanf(k[strings.LastIndexByte(k, '/')+1:], "%06d.json", &n); err == nil && n >= next {
			next = n + 1
		}
	}
	return next, nil
}

// Append implements Inbox. The usual cost is one conditional PUT. When
// another writer has taken the sequence number, the day is listed once to
// find where it stands, instead of probing number after number with the
// whole body.
func (s *StoreInbox) Append(ctx context.Context, e Entry) error {
	if e.Schema == "" {
		e.Schema = EntrySchema
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("triage entry: cannot encode")
	}
	day := e.ReceivedAt.UTC().Format("2006-01-02")
	s.mu.Lock()
	if s.day != day {
		s.day, s.next = day, 1
		// One listing per day and process finds where the day's sequence stands.
		if next, err := s.highest(ctx, day); err == nil {
			s.next = next
		}
	}
	seq := s.next
	s.next++
	s.mu.Unlock()
	listed := false
	for attempt := 0; seq <= maxTriagePerDay && attempt < 64; attempt++ {
		created, err := s.Store.Put(ctx, TriageKey(s.Repo, day, seq), raw)
		if err != nil {
			return fmt.Errorf("triage inbox: %w", err)
		}
		if created {
			s.mu.Lock()
			if s.day == day && s.next <= seq {
				s.next = seq + 1
			}
			s.mu.Unlock()
			return nil
		}
		seq++
		if !listed {
			// Someone else is writing this day too: ask once where it stands.
			listed = true
			if next, err := s.highest(ctx, day); err == nil && next > seq {
				seq = next
			}
		}
		s.mu.Lock()
		if s.day == day && s.next <= seq {
			s.next = seq + 1
		}
		s.mu.Unlock()
	}
	return fmt.Errorf("triage inbox: full for %s", day)
}
