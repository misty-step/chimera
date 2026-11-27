// Package land is the MergeTrain (PRODUCT.md §2.5): many agents author on
// independent branches concurrently; exactly one serialized critical section
// lands them.
//
//	loop:
//	  c        ← next queued change (FIFO)
//	  base     ← Forge.Head(target)
//	  rebased  ← rebase c onto base          # conflict → evict c, continue
//	  verdict  ← verify(rebased) in a Lane   # the tree that will land, not the tree that was authored
//	  Forge.Push(target, old=base, new=rebased)   # compare-and-swap; stale → retry from rebase
//
// The queue lives on the forge as refs (pkg/forge); the epoch fence and the
// record of what landed or was evicted live in the object store.
package land

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/objstore"
)

// CheckName is the name of the check the lander reports on the forge.
const CheckName = "chimera/land"

// Outcome and result states. Always words (DESIGN.md §1.4).
const (
	Landed  = "LANDED"
	Evicted = "EVICTED"
	Pending = "PENDING"
)

// DefaultMaxStale bounds how often one change is rebased again after a
// stale compare-and-swap before it is left in the queue as pending.
const DefaultMaxStale = 5

// ErrFenced is returned when a higher epoch exists: another lander has taken
// over, and this one must not push.
var ErrFenced = errors.New("fenced by a higher epoch")

// ErrEmpty is returned by a Workspace when nothing of the change is left to
// apply on the base.
var ErrEmpty = errors.New("nothing to land")

// ConflictError is a rebase that stopped on conflicting paths.
type ConflictError struct{ Paths []string }

func (e *ConflictError) Error() string {
	return "conflict in " + strings.Join(e.Paths, ", ")
}

// RejectError is a change the lander refuses for a stated reason other than
// a conflict, such as a rebase that would lose trailers.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return e.Reason }

// Rebased is a change replayed onto a base: the commit that would land.
type Rebased struct {
	SHA     forge.SHA     // tip of the rebased change
	Base    forge.SHA     // the target head it sits on
	Sources []gitx.Commit // the authored commits, oldest first
	Commits []gitx.Commit // the rebased commits, oldest first
	Paths   []string      // files that differ between Base and SHA, sorted
}

// Workspace is the lander's own Git clone: where changes are rebased and
// from where their objects reach the forge.
type Workspace interface {
	// Rebase replays c onto base, as one commit when squash is set. It
	// returns *ConflictError, *RejectError, or ErrEmpty (with Sources filled)
	// for a change that cannot or need not land.
	Rebase(ctx context.Context, c forge.Change, base forge.SHA, squash bool) (Rebased, error)
	// Publish makes sha's objects readable by the forge before the
	// compare-and-swap. It returns the staging ref it created there, or ""
	// when the forge already reads this repository.
	Publish(ctx context.Context, sha forge.SHA) (stagingRef string, err error)
}

// Verification is the verdict on a rebased tree.
type Verification struct {
	Pass    bool
	Capsule string // address of the Capsule that records the verdict; may be empty in tests
	Reason  string // why it failed
}

// Train is one lander.
type Train struct {
	Forge  forge.Forge
	Store  objstore.Store
	Repo   string // names land/<repo>/…
	Target string
	Git    Workspace
	// Verify judges the rebased tree. An error means no verdict could be
	// reached: nothing lands and the change stays queued.
	Verify func(ctx context.Context, c forge.Change, rb Rebased) (Verification, error)
	Squash bool
	// Ring0 reports Ring-0 paths; nil means none.
	Ring0 func(path string) bool
	// Approved reports explicit owner approval for a change touching the
	// given Ring-0 paths; nil means never approved.
	Approved func(ctx context.Context, c forge.Change, rb Rebased, paths []string) bool
	Holder   string           // identifies this lander in the epoch record
	Now      func() time.Time // nil means time.Now
	MaxStale int              // 0 means DefaultMaxStale
	Log      func(format string, a ...any)

	epoch int
}

// Result is what happened to one change in a run.
type Result struct {
	Change   forge.Change `json:"change"`
	State    string       `json:"state"` // LANDED | EVICTED | PENDING
	Reason   string       `json:"reason,omitempty"`
	Base     forge.SHA    `json:"base,omitempty"`
	Landed   forge.SHA    `json:"landed,omitempty"`
	Capsule  string       `json:"capsule,omitempty"`
	Attempts int          `json:"attempts"` // rebases performed
}

// Summary is one run of a lander.
type Summary struct {
	Epoch   int      `json:"epoch"`
	Results []Result `json:"results"`
}

// Count returns how many results are in state.
func (s Summary) Count(state string) int {
	n := 0
	for _, r := range s.Results {
		if r.State == state {
			n++
		}
	}
	return n
}

// EpochRecord is the body of land/<repo>/epoch-<n>.
type EpochRecord struct {
	Holder     string `json:"holder"`
	AcquiredAt string `json:"acquired_at"`
}

// Outcome is the write-once record of a change that left the queue.
type Outcome struct {
	Change  forge.Change `json:"change"`
	State   string       `json:"state"` // LANDED | EVICTED
	Reason  string       `json:"reason,omitempty"`
	Epoch   int          `json:"epoch"`
	Base    forge.SHA    `json:"base,omitempty"`
	Landed  forge.SHA    `json:"landed,omitempty"`
	Capsule string       `json:"capsule,omitempty"`
	At      string       `json:"at"`
}

func epochPrefix(repo string) string { return "land/" + repo + "/epoch-" }

func outcomePrefix(repo, target string) string {
	return "land/" + repo + "/outcome/" + forge.Branch(target) + "/"
}

func outcomeKey(repo string, c forge.Change) string {
	return fmt.Sprintf("%s%08d-%s.json", outcomePrefix(repo, c.Target), c.Seq, c.Head.Short())
}

func (t *Train) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Train) logf(format string, a ...any) {
	if t.Log != nil {
		t.Log(format, a...)
	}
}

// HighestEpoch returns the highest epoch written for repo and its record;
// 0 when no lander has ever acquired one.
func HighestEpoch(ctx context.Context, store objstore.Store, repo string) (int, EpochRecord, error) {
	keys, err := store.List(ctx, epochPrefix(repo))
	if err != nil {
		return 0, EpochRecord{}, err
	}
	highest := 0
	for _, k := range keys {
		num := strings.TrimPrefix(k, epochPrefix(repo))
		if n, err := strconv.Atoi(num); err == nil && n > highest && strconv.Itoa(n) == num {
			highest = n
		}
	}
	var rec EpochRecord
	if highest > 0 {
		raw, err := store.Get(ctx, epochPrefix(repo)+strconv.Itoa(highest))
		if err != nil {
			return 0, rec, err
		}
		_ = json.Unmarshal(raw, &rec)
	}
	return highest, rec, nil
}

// Acquire takes the next epoch: it writes land/<repo>/epoch-<n> with
// If-None-Match: * (Store.Put), so exactly one lander holds each n. A lander
// that finds n taken tries n+1. Acquiring fences every earlier holder.
func (t *Train) Acquire(ctx context.Context) (int, error) {
	if t.Repo == "" {
		return 0, fmt.Errorf("land: no repository name")
	}
	highest, _, err := HighestEpoch(ctx, t.Store, t.Repo)
	if err != nil {
		return 0, err
	}
	rec, _ := json.Marshal(EpochRecord{Holder: t.Holder, AcquiredAt: t.now().UTC().Format(time.RFC3339)})
	for n := highest + 1; ; n++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		created, err := t.Store.Put(ctx, epochPrefix(t.Repo)+strconv.Itoa(n), rec)
		if err != nil {
			return 0, err
		}
		if created {
			t.epoch = n
			return n, nil
		}
	}
}

// Epoch returns the epoch this lander holds; 0 before Acquire.
func (t *Train) Epoch() int { return t.epoch }

// fenced fails closed: a lander that cannot read the epochs does not push.
func (t *Train) fenced(ctx context.Context) error {
	highest, _, err := HighestEpoch(ctx, t.Store, t.Repo)
	if err != nil {
		return fmt.Errorf("epoch fence unreadable: %w", err)
	}
	if highest != t.epoch {
		return ErrFenced
	}
	return nil
}

// Run lands queued changes in FIFO order until the queue is empty, a change
// is left pending, or (with once) one change has been processed. It acquires
// an epoch first if this lander holds none. It returns ErrFenced, with the
// results so far, as soon as a higher epoch appears.
func (t *Train) Run(ctx context.Context, once bool) (Summary, error) {
	var sum Summary
	if t.Forge == nil || t.Store == nil || t.Git == nil || t.Verify == nil || t.Target == "" {
		return sum, fmt.Errorf("land: train is not fully configured")
	}
	if err := ctx.Err(); err != nil {
		return sum, err
	}
	if t.epoch == 0 {
		if _, err := t.Acquire(ctx); err != nil {
			return sum, err
		}
	}
	sum.Epoch = t.epoch
	for {
		if err := ctx.Err(); err != nil {
			return sum, err
		}
		if err := t.fenced(ctx); err != nil {
			return sum, err
		}
		queue, err := t.Forge.Queue(ctx, t.Target)
		if err != nil {
			return sum, err
		}
		if len(queue) == 0 {
			return sum, nil
		}
		res, err := t.land(ctx, queue[0])
		if res.State != "" {
			sum.Results = append(sum.Results, res)
		}
		if err != nil {
			return sum, err
		}
		if once || res.State == Pending {
			// A pending change keeps its place: nothing behind it may pass it.
			return sum, nil
		}
	}
}

// land takes one change through the loop.
func (t *Train) land(ctx context.Context, c forge.Change) (Result, error) {
	res := Result{Change: c}
	maxStale := t.MaxStale
	if maxStale <= 0 {
		maxStale = DefaultMaxStale
	}
	for res.Attempts < maxStale {
		base, err := t.Forge.Head(ctx, t.Target)
		if err != nil {
			return Result{}, fmt.Errorf("target %s: %w", forge.Branch(t.Target), err)
		}
		res.Base = base
		res.Attempts++
		rb, err := t.Git.Rebase(ctx, c, base, t.Squash)
		var conflict *ConflictError
		var reject *RejectError
		switch {
		case errors.As(err, &conflict):
			return t.evict(ctx, res, fmt.Sprintf("conflict rebasing onto %s %s: %s", forge.Branch(t.Target), base.Short(), strings.Join(conflict.Paths, ", ")))
		case errors.As(err, &reject):
			return t.evict(ctx, res, reject.Reason)
		case errors.Is(err, ErrEmpty) && len(rb.Sources) > 0:
			// Every commit is already in the target: a lander pushed it and
			// died before it could dequeue. That is a landing, not an eviction.
			res.Landed = base
			return t.landed(ctx, res, "already in "+forge.Branch(t.Target))
		case errors.Is(err, ErrEmpty):
			return t.evict(ctx, res, "nothing to land: the branch has no commits beyond "+forge.Branch(t.Target))
		case err != nil:
			return Result{}, fmt.Errorf("rebase %s: %w", c.Branch, err)
		}
		if t.Ring0 != nil {
			var touched []string
			for _, p := range rb.Paths {
				if t.Ring0(p) {
					touched = append(touched, p)
				}
			}
			if len(touched) > 0 && (t.Approved == nil || !t.Approved(ctx, c, rb, touched)) {
				return t.evict(ctx, res, fmt.Sprintf("touches Ring-0 (%s); needs explicit owner approval", strings.Join(touched, ", ")))
			}
		}
		t.logf("verify %s at %s (rebased onto %s)", c.Branch, rb.SHA.Short(), base.Short())
		v, err := t.Verify(ctx, c, rb)
		if err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return Result{}, fmt.Errorf("verify %s: %w", c.Branch, err)
		}
		res.Capsule = v.Capsule
		if !v.Pass {
			reason := v.Reason
			if reason == "" {
				reason = "verification failed"
			}
			return t.evict(ctx, res, fmt.Sprintf("%s on the tree rebased onto %s %s", reason, forge.Branch(t.Target), base.Short()))
		}
		// Only the holder of the highest epoch may push.
		if err := t.fenced(ctx); err != nil {
			return Result{}, err
		}
		staging, err := t.Git.Publish(ctx, rb.SHA)
		if err != nil {
			return Result{}, fmt.Errorf("publish %s: %w", rb.SHA.Short(), err)
		}
		// The forge's compare-and-swap is the final fence.
		err = t.Forge.Push(ctx, t.Target, base, rb.SHA)
		if staging != "" {
			if derr := t.Forge.Push(context.WithoutCancel(ctx), staging, rb.SHA, forge.Zero); derr != nil && !errors.Is(derr, forge.ErrStale) {
				t.logf("staging ref %s not removed: %v", staging, derr)
			}
		}
		if errors.Is(err, forge.ErrStale) {
			t.logf("stale: %s moved off %s; rebasing %s again", forge.Branch(t.Target), base.Short(), c.Branch)
			continue
		}
		if err != nil {
			return Result{}, fmt.Errorf("push %s: %w", forge.Branch(t.Target), err)
		}
		res.Landed = rb.SHA
		return t.landed(ctx, res, "")
	}
	res.State = Pending
	res.Reason = fmt.Sprintf("%s moved %d times while this change was being verified; still queued", forge.Branch(t.Target), res.Attempts)
	return res, nil
}

// landed finishes a change that is in the target: dequeue, report, record.
// The target has already moved, so none of this is undone by a failure; a
// failure here is logged and the next run converges.
func (t *Train) landed(ctx context.Context, res Result, note string) (Result, error) {
	ctx = context.WithoutCancel(ctx)
	c := res.Change
	res.State, res.Reason = Landed, note
	if err := t.Forge.Push(ctx, c.Ref, c.Head, forge.Zero); err != nil && !errors.Is(err, forge.ErrStale) {
		t.logf("dequeue %s: %v", c.Branch, err)
	}
	title := fmt.Sprintf("landed on %s at %s", forge.Branch(t.Target), res.Landed.Short())
	summary := fmt.Sprintf("change %s (%s) rebased onto %s and verified post-rebase.", c.Branch, c.Head.Short(), res.Base.Short())
	if res.Capsule != "" {
		summary += " Capsule " + res.Capsule + "."
	}
	if note != "" {
		title = note
	}
	if err := t.Forge.Report(ctx, res.Landed, forge.Check{Name: CheckName, State: forge.Pass, Title: title, Summary: summary}); err != nil {
		t.logf("report %s: %v", res.Landed.Short(), err)
	}
	if err := t.record(ctx, res); err != nil {
		t.logf("outcome %s: %v", c.Branch, err)
	}
	t.logf("landed %s at %s", c.Branch, res.Landed.Short())
	return res, nil
}

// evict returns a change to its owning branch with the reason, at once: the
// queue ref goes, the owner is told, the check fails, the outcome is
// recorded, and the train moves on.
func (t *Train) evict(ctx context.Context, res Result, reason string) (Result, error) {
	c := res.Change
	if err := t.fenced(ctx); err != nil {
		return Result{}, err
	}
	res.State, res.Reason = Evicted, reason
	if err := t.Forge.Push(ctx, c.Ref, c.Head, forge.Zero); err != nil && !errors.Is(err, forge.ErrStale) {
		return Result{}, fmt.Errorf("dequeue %s: %w", c.Branch, err)
	}
	msg := fmt.Sprintf("chimera land: %s (%s) was evicted from the queue for %s: %s", c.Branch, c.Head.Short(), forge.Branch(t.Target), reason)
	if err := t.Forge.Notify(ctx, c, msg); err != nil {
		t.logf("notify %s: %v", c.Branch, err)
	}
	if err := t.Forge.Report(ctx, c.Head, forge.Check{Name: CheckName, State: forge.Fail, Title: "evicted: " + reason, Summary: msg}); err != nil {
		t.logf("report %s: %v", c.Head.Short(), err)
	}
	if err := t.record(ctx, res); err != nil {
		t.logf("outcome %s: %v", c.Branch, err)
	}
	t.logf("evicted %s: %s", c.Branch, reason)
	return res, nil
}

func (t *Train) record(ctx context.Context, res Result) error {
	out := Outcome{Change: res.Change, State: res.State, Reason: res.Reason, Epoch: t.epoch, Base: res.Base, Landed: res.Landed,
		Capsule: res.Capsule, At: t.now().UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = t.Store.Put(ctx, outcomeKey(t.Repo, res.Change), raw)
	return err
}

// Enqueue pins branch's current commit in target's queue through the forge:
// a compare-and-swap that creates the next queue ref. Queuing a commit that
// is already queued returns the existing change (created is false). A branch
// queued at an older commit is moved: the old entry is removed and the new
// commit takes a place at the back. position counts from 1.
func Enqueue(ctx context.Context, f forge.Forge, target, branch string) (c forge.Change, position int, created bool, err error) {
	if forge.Branch(target) == "" || forge.Branch(branch) == "" {
		return c, 0, false, fmt.Errorf("enqueue needs a target and a branch")
	}
	head, err := f.Head(ctx, branch)
	if err != nil {
		return c, 0, false, err
	}
	for attempt := 0; attempt < 100; attempt++ {
		queue, err := f.Queue(ctx, target)
		if err != nil {
			return c, 0, false, err
		}
		next, stale := 1, false
		for i, q := range queue {
			if q.Seq >= next {
				next = q.Seq + 1
			}
			if q.Branch != forge.Branch(branch) {
				continue
			}
			if q.Head == head {
				return q, i + 1, false, nil
			}
			// The branch moved since it was queued: its old pin leaves.
			if err := f.Push(ctx, q.Ref, q.Head, forge.Zero); err != nil && !errors.Is(err, forge.ErrStale) {
				return c, 0, false, err
			}
			stale = true
		}
		if stale {
			continue // read the queue again without the old pin
		}
		ref := forge.QueueRef(target, next, branch)
		err = f.Push(ctx, ref, forge.Zero, head)
		if errors.Is(err, forge.ErrStale) {
			continue
		}
		if err != nil {
			return c, 0, false, err
		}
		c, _ = forge.ChangeFromRef(target, ref, head)
		queue, err = f.Queue(ctx, target)
		if err != nil {
			return c, 0, true, err
		}
		for i, q := range queue {
			if q.Ref == ref {
				position = i + 1
			}
		}
		return c, position, true, nil
	}
	return c, 0, false, fmt.Errorf("enqueue %s: the queue kept changing", forge.Branch(branch))
}

// StatusReport is what `chimera land status` shows.
type StatusReport struct {
	Schema     string         `json:"schema"`
	Repo       string         `json:"repo"`
	Target     string         `json:"target"`
	Head       forge.SHA      `json:"head"`
	Epoch      int            `json:"epoch"`
	Holder     string         `json:"holder"`
	AcquiredAt string         `json:"acquired_at"`
	Queue      []forge.Change `json:"queue"`
	Outcomes   []Outcome      `json:"outcomes"`
}

// StatusSchema names the JSON form of a StatusReport.
const StatusSchema = "chimera.land.status/v1"

// Status reads the target head and queue from the forge, and the highest
// epoch and every outcome (newest first) from the store.
func Status(ctx context.Context, f forge.Forge, store objstore.Store, repo, target string) (StatusReport, error) {
	rep := StatusReport{Schema: StatusSchema, Repo: repo, Target: forge.Branch(target), Queue: []forge.Change{}, Outcomes: []Outcome{}}
	head, err := f.Head(ctx, target)
	if err != nil && !errors.Is(err, forge.ErrNotFound) {
		return rep, err
	}
	rep.Head = head
	queue, err := f.Queue(ctx, target)
	if err != nil {
		return rep, err
	}
	rep.Queue = append(rep.Queue, queue...)
	epoch, rec, err := HighestEpoch(ctx, store, repo)
	if err != nil {
		return rep, err
	}
	rep.Epoch, rep.Holder, rep.AcquiredAt = epoch, rec.Holder, rec.AcquiredAt
	keys, err := store.List(ctx, outcomePrefix(repo, target))
	if err != nil {
		return rep, err
	}
	for _, k := range keys {
		raw, err := store.Get(ctx, k)
		if err != nil {
			return rep, err
		}
		var o Outcome
		if json.Unmarshal(raw, &o) != nil {
			return rep, fmt.Errorf("outcome %s: malformed", strings.TrimPrefix(k, outcomePrefix(repo, target)))
		}
		rep.Outcomes = append(rep.Outcomes, o)
	}
	sort.SliceStable(rep.Outcomes, func(i, j int) bool {
		a, b := rep.Outcomes[i], rep.Outcomes[j]
		if a.At != b.At {
			return a.At > b.At
		}
		return a.Change.Seq > b.Change.Seq
	})
	return rep, nil
}
