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
// The queue lives on the forge as refs (pkg/forge); the epoch fence, the push
// intents, and the record of what landed or was evicted live in the object
// store.
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
	// returns *ConflictError, *RejectError, or ErrEmpty for a change that
	// cannot land; an error wrapping forge.ErrUnavailable when the forge's
	// Git transport did not answer; any other error is the change's own.
	Rebase(ctx context.Context, c forge.Change, base forge.SHA, squash bool) (Rebased, error)
	// Contains reports whether sha is tip or an ancestor of it. A commit this
	// repository has never seen (after fetching tip) is not contained.
	Contains(ctx context.Context, tip, sha forge.SHA) (bool, error)
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
	// Warnings are side effects that failed after the change's fate was
	// decided: a notification, a check, an outcome record, a dequeue, a
	// staging ref. They never change State; they must not go unseen.
	Warnings []string `json:"warnings,omitempty"`
}

func (r *Result) warn(format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
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

// Attempt is the write-once push intent a lander stores before the target
// compare-and-swap: land/<repo>/attempt/<target>/<seq>-<head12>/<rebased12>.json.
// It is how a later run tells "this change's rebased commit is in the target"
// (a lander pushed and died, or a push answered with an error yet applied)
// from "nothing of this change is left to apply": only the first is a landing.
type Attempt struct {
	Change  forge.Change `json:"change"`
	Base    forge.SHA    `json:"base"`
	Rebased forge.SHA    `json:"rebased"`
	Capsule string       `json:"capsule,omitempty"`
	Epoch   int          `json:"epoch"`
	At      string       `json:"at"`
}

func epochPrefix(repo string) string { return "land/" + repo + "/epoch-" }

func outcomePrefix(repo, target string) string {
	return "land/" + repo + "/outcome/" + forge.TargetSegment(target) + "/"
}

func attemptPrefix(repo string, c forge.Change) string {
	return fmt.Sprintf("land/%s/attempt/%s/%08d-%s/", repo, forge.TargetSegment(c.Target), c.Seq, c.Head.Short())
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

// unavailable reports a failure of the store or the forge to answer: the
// one kind of failure that is nobody's fault and stops the run with the
// change still queued.
func unavailable(err error) bool {
	return errors.Is(err, objstore.ErrUnavailable) || errors.Is(err, forge.ErrUnavailable)
}

func firstLine(err error) string {
	msg := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if r := []rune(msg); len(r) > 300 {
		msg = string(r[:299]) + "…"
	}
	return msg
}

// landedAttempt looks for a push intent of c whose rebased commit is in the
// target: proof that the change has landed, whoever pushed it.
func (t *Train) landedAttempt(ctx context.Context, c forge.Change, head forge.SHA) (Attempt, bool, error) {
	keys, err := t.Store.List(ctx, attemptPrefix(t.Repo, c))
	if err != nil {
		return Attempt{}, false, err
	}
	for _, k := range keys {
		raw, err := t.Store.Get(ctx, k)
		if err != nil {
			return Attempt{}, false, err
		}
		var a Attempt
		if json.Unmarshal(raw, &a) != nil || a.Rebased.IsZero() || a.Change.Ref != c.Ref || a.Change.Head != c.Head {
			continue
		}
		in, err := t.Git.Contains(ctx, head, a.Rebased)
		if err != nil {
			return Attempt{}, false, err
		}
		if in {
			return a, true, nil
		}
	}
	return Attempt{}, false, nil
}

// land takes one change through the loop.
func (t *Train) land(ctx context.Context, c forge.Change) (Result, error) {
	res := Result{Change: c}
	maxStale := t.MaxStale
	if maxStale <= 0 {
		maxStale = DefaultMaxStale
	}
	target := forge.Branch(t.Target)
	for res.Attempts < maxStale {
		base, err := t.Forge.Head(ctx, t.Target)
		if err != nil {
			return Result{}, fmt.Errorf("target %s: %w", target, err)
		}
		res.Base = base
		// A lander that pushed this change and died before dequeuing it — or a
		// push that answered with an error and applied anyway — left its push
		// intent behind. If that commit is in the target, the change landed.
		if a, ok, err := t.landedAttempt(ctx, c, base); err != nil {
			return Result{}, fmt.Errorf("push intents of %s: %w", c.Branch, err)
		} else if ok {
			res.Base, res.Landed, res.Capsule = a.Base, a.Rebased, a.Capsule
			// The lander that pushed it may not have lived to remove its staging ref.
			staging := StagingPrefix + a.Rebased.Short()
			if derr := t.Forge.Push(context.WithoutCancel(ctx), staging, a.Rebased, forge.Zero); derr != nil && !errors.Is(derr, forge.ErrStale) {
				res.warn("staging ref %s not removed: %v", staging, derr)
			}
			return t.landed(ctx, res, "already in "+target)
		}
		res.Attempts++
		rb, err := t.Git.Rebase(ctx, c, base, t.Squash)
		var conflict *ConflictError
		var reject *RejectError
		switch {
		case errors.As(err, &conflict):
			return t.evict(ctx, res, fmt.Sprintf("conflict rebasing onto %s %s: %s", target, base.Short(), strings.Join(conflict.Paths, ", ")))
		case errors.As(err, &reject):
			return t.evict(ctx, res, reject.Reason)
		case errors.Is(err, ErrEmpty):
			// With no push intent in the target this is never a landing, and no
			// check is ever reported for a commit this train did not verify.
			return t.evict(ctx, res, fmt.Sprintf("nothing to land relative to %s %s", target, base.Short()))
		case err != nil && ctx.Err() != nil:
			return Result{}, ctx.Err()
		case err != nil && unavailable(err):
			return Result{}, fmt.Errorf("rebase %s: %w", c.Branch, err)
		case err != nil:
			// A change that cannot be rebased must not hold up the ones behind it.
			return t.evict(ctx, res, fmt.Sprintf("could not be rebased onto %s: %s", target, firstLine(err)))
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
			return t.evict(ctx, res, fmt.Sprintf("%s on the tree rebased onto %s %s", reason, target, base.Short()))
		}
		// Only the holder of the highest epoch may push.
		if err := t.fenced(ctx); err != nil {
			return Result{}, err
		}
		// The push intent is stored before the push, so no outcome of the push
		// — not even one this lander never learns — can strand the change.
		intent, _ := json.Marshal(Attempt{Change: c, Base: base, Rebased: rb.SHA, Capsule: v.Capsule, Epoch: t.epoch, At: t.now().UTC().Format(time.RFC3339)})
		if _, err := t.Store.Put(ctx, attemptPrefix(t.Repo, c)+rb.SHA.Short()+".json", intent); err != nil {
			return Result{}, fmt.Errorf("push intent of %s: %w", c.Branch, err)
		}
		staging, err := t.Git.Publish(ctx, rb.SHA)
		if err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			return Result{}, fmt.Errorf("publish %s: %w", rb.SHA.Short(), err)
		}
		// The forge's compare-and-swap is the final fence.
		err = t.Forge.Push(ctx, t.Target, base, rb.SHA)
		if staging != "" {
			if derr := t.Forge.Push(context.WithoutCancel(ctx), staging, rb.SHA, forge.Zero); derr != nil && !errors.Is(derr, forge.ErrStale) {
				res.warn("staging ref %s not removed: %v", staging, derr)
				t.logf("staging ref %s not removed: %v", staging, derr)
			}
		}
		if errors.Is(err, forge.ErrStale) {
			t.logf("stale: %s moved off %s; rebasing %s again", target, base.Short(), c.Branch)
			continue
		}
		if err != nil {
			// The push may have applied all the same; the next run reads the
			// push intent and finds out.
			return Result{}, fmt.Errorf("push %s: %w", target, err)
		}
		res.Landed = rb.SHA
		return t.landed(ctx, res, "")
	}
	res.State = Pending
	res.Reason = fmt.Sprintf("%s moved %d times while this change was being verified; still queued", target, res.Attempts)
	return res, nil
}

// landed finishes a change that is in the target: dequeue, report, record.
// The target has already moved, so none of this is undone by a failure. A
// failed report or record is a warning. A failed dequeue also stops the run:
// the change would otherwise be picked up again at once, forever.
func (t *Train) landed(ctx context.Context, res Result, note string) (Result, error) {
	ctx = context.WithoutCancel(ctx)
	c := res.Change
	res.State, res.Reason = Landed, note
	derr := t.Forge.Push(ctx, c.Ref, c.Head, forge.Zero)
	if errors.Is(derr, forge.ErrStale) {
		derr = nil // already gone: another lander finished the same landing
	}
	title := fmt.Sprintf("landed on %s at %s", forge.Branch(t.Target), res.Landed.Short())
	summary := fmt.Sprintf("change %s (%s) rebased onto %s and verified post-rebase.", c.Branch, c.Head.Short(), res.Base.Short())
	if res.Capsule != "" {
		summary += " Capsule " + res.Capsule + "."
	}
	if err := t.Forge.Report(ctx, res.Landed, forge.Check{Name: CheckName, State: forge.Pass, Title: title, Summary: summary}); err != nil {
		res.warn("report %s: %v", res.Landed.Short(), err)
		t.logf("report %s: %v", res.Landed.Short(), err)
	}
	if err := t.record(ctx, res); err != nil {
		res.warn("outcome %s: %v", c.Branch, err)
		t.logf("outcome %s: %v", c.Branch, err)
	}
	t.logf("landed %s at %s", c.Branch, res.Landed.Short())
	if derr != nil {
		res.warn("dequeue %s: %v", c.Branch, derr)
		return res, fmt.Errorf("dequeue %s after landing: %w", c.Branch, derr)
	}
	return res, nil
}

// evict returns a change to its owning branch with the reason, at once: the
// outcome is recorded, the queue ref goes, the owner is told, the check
// fails, and the train moves on. Once begun it is not interrupted: a
// cancelled run never leaves a change dequeued but untold.
func (t *Train) evict(ctx context.Context, res Result, reason string) (Result, error) {
	c := res.Change
	if err := t.fenced(ctx); err != nil {
		return Result{}, err
	}
	ctx = context.WithoutCancel(ctx)
	res.State, res.Reason = Evicted, reason
	if err := t.record(ctx, res); err != nil {
		res.warn("outcome %s: %v", c.Branch, err)
		t.logf("outcome %s: %v", c.Branch, err)
	}
	if err := t.Forge.Push(ctx, c.Ref, c.Head, forge.Zero); err != nil && !errors.Is(err, forge.ErrStale) {
		return Result{}, fmt.Errorf("dequeue %s: %w", c.Branch, err)
	}
	msg := fmt.Sprintf("chimera land: %s (%s) was evicted from the queue for %s: %s", c.Branch, c.Head.Short(), forge.Branch(t.Target), reason)
	if err := t.Forge.Notify(ctx, c, msg); err != nil {
		res.warn("notify %s: %v", c.Branch, err)
		t.logf("notify %s: %v", c.Branch, err)
	}
	if err := t.Forge.Report(ctx, c.Head, forge.Check{Name: CheckName, State: forge.Fail, Title: "evicted: " + reason, Summary: msg}); err != nil {
		res.warn("report %s: %v", c.Head.Short(), err)
		t.logf("report %s: %v", c.Head.Short(), err)
	}
	t.logf("evicted %s: %s", c.Branch, reason)
	return res, nil
}

// maxOutcomesPerEpoch bounds the search for a free outcome key.
const maxOutcomesPerEpoch = 1000

// record writes the outcome under a key no earlier outcome holds:
// <seq>-<head12>-e<epoch>.json, then -e<epoch>-2, -3, …. Sequence numbers
// are reused once a queue drains, so the same commit can be evicted, queued
// again, and land; every one of those is kept.
func (t *Train) record(ctx context.Context, res Result) error {
	out := Outcome{Change: res.Change, State: res.State, Reason: res.Reason, Epoch: t.epoch, Base: res.Base, Landed: res.Landed,
		Capsule: res.Capsule, At: t.now().UTC().Format(time.RFC3339)}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	stem := fmt.Sprintf("%s%08d-%s-e%d", outcomePrefix(t.Repo, res.Change.Target), res.Change.Seq, res.Change.Head.Short(), t.epoch)
	for n := 1; n <= maxOutcomesPerEpoch; n++ {
		key := stem + ".json"
		if n > 1 {
			key = fmt.Sprintf("%s-%d.json", stem, n)
		}
		created, err := t.Store.Put(ctx, key, raw)
		if err != nil {
			return err
		}
		if created {
			return nil
		}
	}
	return fmt.Errorf("no free outcome key for %s", res.Change.ID)
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
	type keyed struct {
		Outcome
		key string
	}
	var outcomes []keyed
	for _, k := range keys {
		raw, err := store.Get(ctx, k)
		if err != nil {
			return rep, err
		}
		var o Outcome
		if json.Unmarshal(raw, &o) != nil {
			return rep, fmt.Errorf("outcome %s: malformed", strings.TrimPrefix(k, outcomePrefix(repo, target)))
		}
		outcomes = append(outcomes, keyed{o, k})
	}
	// Newest first: by time, then epoch, then key (a later key of one epoch
	// was written later).
	sort.SliceStable(outcomes, func(i, j int) bool {
		a, b := outcomes[i], outcomes[j]
		if a.At != b.At {
			return a.At > b.At
		}
		if a.Epoch != b.Epoch {
			return a.Epoch > b.Epoch
		}
		if len(a.key) != len(b.key) {
			return len(a.key) > len(b.key)
		}
		return a.key > b.key
	})
	for _, o := range outcomes {
		rep.Outcomes = append(rep.Outcomes, o.Outcome)
	}
	return rep, nil
}
