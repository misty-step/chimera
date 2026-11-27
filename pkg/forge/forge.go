// Package forge is Chimera's entire forge surface (PRODUCT.md §2.5): five
// methods. Everything Land and Inlet need from a forge — reading a ref,
// compare-and-swap on a ref, the landing queue, a check on a commit, and a
// message to a change's owner — goes through them.
//
// The landing queue is made of refs, so the same five methods serve every
// forge that speaks Git: a change is queued by creating
// refs/chimera/land/<target>/<seq>/<branch> at the commit to land (a Push
// from Zero) and leaves the queue when that ref is deleted (a Push to Zero).
package forge

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SHA is a Git object name. The zero value means "no such ref".
type SHA string

// Zero is the SHA of a ref that does not exist: as old it makes Push create
// the ref, as new it makes Push delete it.
const Zero SHA = ""

// IsZero reports whether s names no object (empty or all zeros).
func (s SHA) IsZero() bool { return strings.Trim(string(s), "0") == "" }

// Short abbreviates s to 12 characters for humans.
func (s SHA) Short() string {
	if len(s) > 12 {
		return string(s[:12])
	}
	return string(s)
}

// Same reports whether two SHAs name the same object, treating every
// spelling of Zero alike.
func Same(a, b SHA) bool {
	if a.IsZero() || b.IsZero() {
		return a.IsZero() && b.IsZero()
	}
	return a == b
}

// ErrStale is returned by Push when the ref is not at old: someone else
// moved it. The caller starts over from the ref's new value.
var ErrStale = errors.New("stale ref")

// ErrNotFound is returned by Head for a ref that does not exist.
var ErrNotFound = errors.New("ref not found")

// Change is one queued change: a commit on an owning branch that asks to
// land on a target.
type Change struct {
	ID     string // "<seq>/<branch>": unique within the target's queue
	Ref    string // the queue ref holding the change; "" for a change that is not queued
	Seq    int    // queue position key; lower lands first
	Branch string // owning branch (short name)
	Head   SHA    // the commit queued to land
	Target string // ref the change lands on (short name)
}

// State is the outcome a Check reports. It is always a word (DESIGN.md §1.4).
type State string

const (
	Pass    State = "PASS"
	Fail    State = "FAIL"
	Pending State = "PENDING"
)

// Check is a named verdict attached to a commit on the forge.
type Check struct {
	Name    string // e.g. "chimera/land"
	State   State
	Title   string // one line
	Summary string // a few lines; never a secret, never a score
	URL     string // where the evidence is; may be empty
}

// Forge is the entire forge surface.
type Forge interface {
	Head(ctx context.Context, ref string) (SHA, error)
	Push(ctx context.Context, ref string, old, new SHA) error // ErrStale when ref != old
	Queue(ctx context.Context, target string) ([]Change, error)
	Report(ctx context.Context, sha SHA, check Check) error
	Notify(ctx context.Context, c Change, msg string) error
}

// QueuePrefix is the ref namespace of the landing queue.
const QueuePrefix = "refs/chimera/land/"

// RefName qualifies a ref: names starting with "refs/" are kept, anything
// else is a branch.
func RefName(ref string) string {
	if strings.HasPrefix(ref, "refs/") {
		return ref
	}
	return "refs/heads/" + ref
}

// Branch returns the short name of a branch ref ("refs/heads/x" → "x").
func Branch(ref string) string { return strings.TrimPrefix(ref, "refs/heads/") }

const seqDigits = 8

// QueueRef names the queue ref of a change.
func QueueRef(target string, seq int, branch string) string {
	return fmt.Sprintf("%s%s/%0*d/%s", QueuePrefix, Branch(target), seqDigits, seq, Branch(branch))
}

// QueueRefPrefix is the prefix every queue ref of target starts with.
func QueueRefPrefix(target string) string { return QueuePrefix + Branch(target) + "/" }

// ChangeFromRef decodes a queue ref of target; ok is false for any other ref.
func ChangeFromRef(target, ref string, head SHA) (c Change, ok bool) {
	rest, found := strings.CutPrefix(ref, QueueRefPrefix(target))
	if !found {
		return Change{}, false
	}
	num, branch, found := strings.Cut(rest, "/")
	if !found || len(num) != seqDigits || branch == "" {
		return Change{}, false
	}
	seq, err := strconv.Atoi(num)
	if err != nil || seq < 0 {
		return Change{}, false
	}
	return Change{ID: fmt.Sprintf("%d/%s", seq, branch), Ref: ref, Seq: seq, Branch: branch, Head: head, Target: Branch(target)}, true
}

// QueueFromRefs builds the FIFO queue of target from a ref listing: by
// sequence number, then by branch name, so every reader sees one order.
func QueueFromRefs(target string, refs map[string]SHA) []Change {
	var out []Change
	for ref, sha := range refs {
		if c, ok := ChangeFromRef(target, ref, sha); ok && !sha.IsZero() {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].Branch < out[j].Branch
	})
	return out
}
