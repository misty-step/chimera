package forge

import (
	"context"
	"sync"
)

// PushRecord is one Push the fake saw, with what it answered.
type PushRecord struct {
	Ref      string
	Old, New SHA
	Err      error // nil when the ref moved
}

// ReportRecord is one Report the fake saw.
type ReportRecord struct {
	SHA   SHA
	Check Check
}

// Notification is one Notify the fake saw.
type Notification struct {
	Change Change
	Msg    string
}

// Fake is the in-memory forge for tests: refs with real compare-and-swap,
// the ref-backed queue, and a record of every push, report, and
// notification. It is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	refs    map[string]SHA
	pushes  []PushRecord
	reports []ReportRecord
	notes   []Notification
	fail    map[string][]error
	onPush  func(ref string, old, new SHA)
}

// NewFake returns an empty fake forge.
func NewFake() *Fake { return &Fake{refs: map[string]SHA{}, fail: map[string][]error{}} }

// SetRef moves a ref unconditionally, as an outside writer would. Zero deletes it.
func (f *Fake) SetRef(ref string, sha SHA) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sha.IsZero() {
		delete(f.refs, RefName(ref))
		return
	}
	f.refs[RefName(ref)] = sha
}

// Refs returns a copy of every ref.
func (f *Fake) Refs() map[string]SHA {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]SHA, len(f.refs))
	for k, v := range f.refs {
		out[k] = v
	}
	return out
}

// Pushes returns every Push seen so far, in order.
func (f *Fake) Pushes() []PushRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]PushRecord{}, f.pushes...)
}

// Reports returns every Report seen so far, in order.
func (f *Fake) Reports() []ReportRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ReportRecord{}, f.reports...)
}

// Notifications returns every Notify seen so far, in order.
func (f *Fake) Notifications() []Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Notification{}, f.notes...)
}

// FailNext makes the next call of method ("Head", "Push", "Queue",
// "Report", "Notify") return err. Calls queue up.
func (f *Fake) FailNext(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[method] = append(f.fail[method], err)
}

// OnPush installs a hook that runs before every Push is decided, outside the
// fake's lock, so a test can move a ref in the window between a lander's
// Head and its Push.
func (f *Fake) OnPush(fn func(ref string, old, new SHA)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onPush = fn
}

func (f *Fake) injected(method string) error {
	if q := f.fail[method]; len(q) > 0 {
		f.fail[method] = q[1:]
		return q[0]
	}
	return nil
}

// Head implements Forge.
func (f *Fake) Head(ctx context.Context, ref string) (SHA, error) {
	if err := ctx.Err(); err != nil {
		return Zero, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("Head"); err != nil {
		return Zero, err
	}
	sha, ok := f.refs[RefName(ref)]
	if !ok {
		return Zero, ErrNotFound
	}
	return sha, nil
}

// Push implements Forge: the ref moves only if it is at old.
func (f *Fake) Push(ctx context.Context, ref string, old, new SHA) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ref = RefName(ref)
	f.mu.Lock()
	hook := f.onPush
	f.mu.Unlock()
	if hook != nil {
		hook(ref, old, new)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.injected("Push")
	if err == nil && !Same(f.refs[ref], old) {
		err = ErrStale
	}
	f.pushes = append(f.pushes, PushRecord{Ref: ref, Old: old, New: new, Err: err})
	if err != nil {
		return err
	}
	if new.IsZero() {
		delete(f.refs, ref)
	} else {
		f.refs[ref] = new
	}
	return nil
}

// Queue implements Forge.
func (f *Fake) Queue(ctx context.Context, target string) ([]Change, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("Queue"); err != nil {
		return nil, err
	}
	return QueueFromRefs(target, f.refs), nil
}

// Report implements Forge.
func (f *Fake) Report(ctx context.Context, sha SHA, check Check) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("Report"); err != nil {
		return err
	}
	f.reports = append(f.reports, ReportRecord{SHA: sha, Check: check})
	return nil
}

// Notify implements Forge.
func (f *Fake) Notify(ctx context.Context, c Change, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.injected("Notify"); err != nil {
		return err
	}
	f.notes = append(f.notes, Notification{Change: c, Msg: msg})
	return nil
}
