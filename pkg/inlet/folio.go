package inlet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"chimera/pkg/forge"
	"chimera/pkg/gitx"
)

// ProposalFile is one Folio file a proposal writes.
type ProposalFile struct {
	Path    string
	Content []byte
	// Seen is the SHA-256 (hex) of the file as the classifier saw it. When
	// set, the file is written only if the Folio still reads that way; an
	// edit made against a Folio that has since moved is dropped, never
	// applied over someone else's change. Empty means unconditional.
	Seen string
}

// Proposal is one owner nit on its way into the Folio-only pull request.
type Proposal struct {
	ID         string // "<YYYYMMDD>-<n>", unique per repository
	ReceivedAt time.Time
	Summary    string // one line
	Files      []ProposalFile
}

// Update is what one update of the Folio pull request did.
type Update struct {
	Change  forge.Change // the branch, its new head, and the target
	Pushed  bool         // false when the branch already held everything
	Dropped []string     // "<proposal>: <path>" edits dropped as stale
}

// FolioPR is the one open Folio-only pull request of a repository.
type FolioPR interface {
	// Update adds a batch of proposals to the pull request, opening it if
	// there is none. It must never write a path outside the fence.
	Update(ctx context.Context, batch []Proposal) (Update, error)
}

// DefaultFolioBranch is the head of the Folio-only pull request.
const DefaultFolioBranch = "chimera/folio"

// BranchPR is the Folio pull request on a forge with only five methods: one
// well-known branch per repository, moved by compare-and-swap, announced
// through Notify (the forge adapter turns the first announcement of an
// unqueued branch into the pull request itself). One branch, so one open PR.
//
// The branch only ever fast-forwards: when the target has moved underneath
// it, the next update merges the target in rather than rewriting history.
// Commits are built with Git plumbing in a private index; the user's
// checkout and index are never touched.
type BranchPR struct {
	RepoDir string // a clone holding the target's objects
	Forge   forge.Forge
	Branch  string // "" means DefaultFolioBranch
	Target  string
	// Publish makes a new commit's objects reachable by the forge before the
	// compare-and-swap; nil means the forge reads this repository.
	Publish func(ctx context.Context, sha forge.SHA) error
	// Fetch brings a commit the forge names into this repository; nil means
	// its objects are already here.
	Fetch func(ctx context.Context, sha forge.SHA) error
	Now   func() time.Time // nil means time.Now
}

func (b *BranchPR) branch() string {
	if b.Branch == "" {
		return DefaultFolioBranch
	}
	return forge.Branch(b.Branch)
}

const pushAttempts = 5

func sum(content []byte) string {
	s := sha256.Sum256(content)
	return hex.EncodeToString(s[:])
}

// Update implements FolioPR.
func (b *BranchPR) Update(ctx context.Context, batch []Proposal) (Update, error) {
	if b.Forge == nil || b.RepoDir == "" || b.Target == "" {
		return Update{}, fmt.Errorf("folio pr: forge, repository, and target are required")
	}
	// First fence check: nothing outside the fence is even staged.
	for _, p := range batch {
		for _, f := range p.Files {
			if !InFence(f.Path) {
				return Update{}, fmt.Errorf("folio pr: proposal %s: path outside the folio fence; nothing pushed", p.ID)
			}
		}
	}
	var last error
	for attempt := 0; attempt < pushAttempts; attempt++ {
		up, err := b.update(ctx, batch)
		if !errors.Is(err, forge.ErrStale) {
			return up, err
		}
		last = err
	}
	return Update{}, fmt.Errorf("folio pr: branch kept moving: %w", last)
}

func (b *BranchPR) have(ctx context.Context, sha forge.SHA) error {
	if _, err := gitx.Run(ctx, b.RepoDir, "cat-file", "-e", string(sha)+"^{commit}"); err == nil {
		return nil
	}
	if b.Fetch != nil {
		if err := b.Fetch(ctx, sha); err != nil {
			return fmt.Errorf("folio pr: cannot fetch %s", sha.Short())
		}
		if _, err := gitx.Run(ctx, b.RepoDir, "cat-file", "-e", string(sha)+"^{commit}"); err == nil {
			return nil
		}
	}
	return fmt.Errorf("folio pr: commit %s is not in the repository", sha.Short())
}

func (b *BranchPR) isAncestor(ctx context.Context, a, of forge.SHA) bool {
	_, err := gitx.Run(ctx, b.RepoDir, "merge-base", "--is-ancestor", string(a), string(of))
	return err == nil
}

// blob returns the blob at rev:path, or "" when there is none.
func (b *BranchPR) blob(ctx context.Context, rev, path string) string {
	if rev == "" {
		return ""
	}
	out, err := gitx.Run(ctx, b.RepoDir, "rev-parse", "--verify", "--quiet", rev+":"+path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (b *BranchPR) update(ctx context.Context, batch []Proposal) (Update, error) {
	branch := b.branch()
	target, err := b.Forge.Head(ctx, b.Target)
	if err != nil {
		return Update{}, fmt.Errorf("folio pr: target %s: %w", forge.Branch(b.Target), err)
	}
	head, err := b.Forge.Head(ctx, branch)
	if errors.Is(err, forge.ErrNotFound) {
		head, err = forge.Zero, nil
	}
	if err != nil {
		return Update{}, fmt.Errorf("folio pr: branch %s: %w", branch, err)
	}
	if err := b.have(ctx, target); err != nil {
		return Update{}, err
	}
	if !head.IsZero() {
		if err := b.have(ctx, head); err != nil {
			return Update{}, err
		}
	}
	up := Update{Change: forge.Change{Branch: branch, Head: head, Target: forge.Branch(b.Target)}}

	// Where the new commit goes. Every case is a fast-forward of the branch.
	var parents []forge.SHA
	base := target
	diverged := false
	switch {
	case head.IsZero() || b.isAncestor(ctx, head, target): // no branch, or it was merged
		parents = []forge.SHA{target}
	case b.isAncestor(ctx, target, head): // the branch is up to date with the target
		parents, base = []forge.SHA{head}, head
	default: // the target moved: merge it in
		parents, diverged = []forge.SHA{head, target}, true
	}

	tmp, err := os.MkdirTemp("", "chimera-folio-")
	if err != nil {
		return Update{}, fmt.Errorf("folio pr: cannot create scratch directory")
	}
	defer os.RemoveAll(tmp)
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(tmp, "index")}
	git := func(stdin []byte, args ...string) (string, error) {
		out, err := gitx.RunInput(ctx, b.RepoDir, stdin, env, args...)
		return strings.TrimSpace(string(out)), err
	}
	stage := func(blob, path string) error {
		_, err := git(nil, "update-index", "--add", "--cacheinfo", "100644,"+blob+","+path)
		return err
	}
	if _, err := git(nil, "read-tree", string(base)); err != nil {
		return Update{}, err
	}
	if diverged {
		// Carry the branch's Folio changes over, file by file: a file the
		// target left alone keeps the branch's version; a file both changed
		// keeps the target's, and the branch's stale edit is dropped.
		mb := ""
		if out, err := gitx.Run(ctx, b.RepoDir, "merge-base", string(target), string(head)); err == nil {
			mb = strings.TrimSpace(string(out))
		}
		stats, err := gitx.DiffStat(ctx, b.RepoDir, mb, string(head))
		if err != nil {
			return Update{}, err
		}
		for _, st := range stats {
			if !InFence(st.Path) {
				continue // never carried: the pull request is Folio-only
			}
			ours, was, theirs := b.blob(ctx, string(head), st.Path), b.blob(ctx, mb, st.Path), b.blob(ctx, string(target), st.Path)
			switch {
			case ours == "" || ours == theirs:
			case theirs == was:
				if err := stage(ours, st.Path); err != nil {
					return Update{}, err
				}
			default:
				up.Dropped = append(up.Dropped, "branch: "+st.Path)
			}
		}
	}
	for _, p := range batch {
		for _, f := range p.Files {
			if !InFence(f.Path) {
				return Update{}, fmt.Errorf("folio pr: proposal %s: path outside the folio fence; nothing pushed", p.ID)
			}
			var current []byte
			present := false
			if listed, _ := git(nil, "ls-files", "-s", "--", f.Path); listed != "" {
				if fields := strings.Fields(listed); len(fields) >= 2 {
					raw, err := gitx.Run(ctx, b.RepoDir, "cat-file", "blob", fields[1])
					if err != nil {
						return Update{}, err
					}
					current, present = raw, true
				}
			}
			if present && bytes.Equal(current, f.Content) {
				continue // already there
			}
			if f.Seen != "" && sum(current) != f.Seen {
				up.Dropped = append(up.Dropped, p.ID+": "+f.Path)
				continue
			}
			blob, err := git(f.Content, "hash-object", "-w", "--stdin")
			if err != nil {
				return Update{}, err
			}
			if err := stage(blob, f.Path); err != nil {
				return Update{}, err
			}
		}
	}
	sort.Strings(up.Dropped)
	tree, err := git(nil, "write-tree")
	if err != nil {
		return Update{}, err
	}
	baseTree, err := gitx.RevParse(ctx, b.RepoDir, string(base)+"^{tree}")
	if err != nil {
		return Update{}, err
	}
	if tree == baseTree && !diverged {
		if base == target {
			// Nothing to propose on top of the target: no pull request to move.
			return up, nil
		}
		// The branch already holds the whole batch (an earlier update pushed
		// but could not announce): announce again, push nothing.
		return up, b.notify(ctx, up, batch)
	}

	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	stamp := fmt.Sprintf("@%d +0000", now.Unix())
	args := []string{"commit-tree", tree}
	for _, p := range parents {
		args = append(args, "-p", string(p))
	}
	commitEnv := append(append([]string{}, env...),
		"GIT_AUTHOR_NAME=chimera inlet", "GIT_AUTHOR_EMAIL=inlet@chimera.invalid", "GIT_AUTHOR_DATE="+stamp,
		"GIT_COMMITTER_NAME=chimera inlet", "GIT_COMMITTER_EMAIL=inlet@chimera.invalid", "GIT_COMMITTER_DATE="+stamp)
	out, err := gitx.RunInput(ctx, b.RepoDir, []byte(commitMessage(batch, diverged, forge.Branch(b.Target))), commitEnv, args...)
	if err != nil {
		return Update{}, err
	}
	commit := forge.SHA(strings.TrimSpace(string(out)))

	// Second, independent fence check, on the commit itself: what the pull
	// request would change on the target must be Folio and nothing else.
	stats, err := gitx.DiffStat(ctx, b.RepoDir, string(target), string(commit))
	if err != nil {
		return Update{}, err
	}
	for _, st := range stats {
		if !InFence(st.Path) {
			return Update{}, fmt.Errorf("folio pr: branch %s changes a path outside the folio fence; nothing pushed", branch)
		}
	}
	if b.Publish != nil {
		if err := b.Publish(ctx, commit); err != nil {
			return Update{}, fmt.Errorf("folio pr: cannot publish %s", commit.Short())
		}
	}
	if err := b.Forge.Push(ctx, forge.RefName(branch), head, commit); err != nil {
		if errors.Is(err, forge.ErrStale) {
			return Update{}, err
		}
		return Update{}, fmt.Errorf("folio pr: push %s: %w", branch, err)
	}
	up.Change.Head, up.Pushed = commit, true
	return up, b.notify(ctx, up, batch)
}

func (b *BranchPR) notify(ctx context.Context, up Update, batch []Proposal) error {
	var body strings.Builder
	body.WriteString("folio: owner nits for review\n\n")
	body.WriteString("Folio-only: every path is PRODUCT.md, DESIGN.md, or under folio/.\n\n")
	for _, p := range batch {
		var paths []string
		for _, f := range p.Files {
			paths = append(paths, f.Path)
		}
		fmt.Fprintf(&body, "- nit-%s: %s (%s)\n", p.ID, oneLine(p.Summary, 120), strings.Join(paths, ", "))
	}
	for _, d := range up.Dropped {
		fmt.Fprintf(&body, "- dropped as stale: %s\n", d)
	}
	if err := b.Forge.Notify(ctx, up.Change, body.String()); err != nil {
		return fmt.Errorf("folio pr: notify: %w", err)
	}
	return nil
}

func commitMessage(batch []Proposal, merged bool, target string) string {
	noun := "nits"
	if len(batch) == 1 {
		noun = "nit"
	}
	subject := fmt.Sprintf("folio: record %d owner %s", len(batch), noun)
	if merged {
		subject = fmt.Sprintf("folio: merge %s and record %d owner %s", target, len(batch), noun)
	}
	var m strings.Builder
	m.WriteString(subject + "\n\n")
	for _, p := range batch {
		fmt.Fprintf(&m, "- nit-%s: %s\n", p.ID, oneLine(p.Summary, 120))
	}
	m.WriteString("\nFolio-only: PRODUCT.md, DESIGN.md, folio/**.\n")
	return m.String()
}

// oneLine folds s onto one line of at most max runes.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}

// GitFolio returns a reader of the Folio a classifier should judge a nit
// against: the Folio pull request's branch while it is open (so a second nit
// sees what the first proposed), otherwise the target.
func GitFolio(repoDir string, f forge.Forge, branch, target string) func(ctx context.Context) (FolioSnapshot, error) {
	if branch == "" {
		branch = DefaultFolioBranch
	}
	return func(ctx context.Context) (FolioSnapshot, error) {
		rev, err := f.Head(ctx, target)
		if err != nil {
			return FolioSnapshot{}, fmt.Errorf("folio: target %s: %w", forge.Branch(target), err)
		}
		if head, err := f.Head(ctx, branch); err == nil && !head.IsZero() {
			if _, err := gitx.Run(ctx, repoDir, "merge-base", "--is-ancestor", string(head), string(rev)); err != nil {
				if _, err := gitx.Run(ctx, repoDir, "cat-file", "-e", string(head)+"^{commit}"); err == nil {
					rev = head
				}
			}
		}
		read := func(path string) string {
			out, err := gitx.Run(ctx, repoDir, "cat-file", "blob", string(rev)+":"+path)
			if err != nil {
				return ""
			}
			return string(out)
		}
		return FolioSnapshot{Product: read("PRODUCT.md"), Design: read("DESIGN.md")}, nil
	}
}

// Coalescer gathers intent nits into one update of the Folio pull request
// per debounce window (PRODUCT.md §2.6): the first proposal arms the window,
// later ones join the batch, and when the window has elapsed one update
// carries them all.
type Coalescer struct {
	PR     FolioPR
	Window time.Duration
	Now    func() time.Time
	// AfterFunc schedules the flush; nil means nothing is scheduled and the
	// owner of the Coalescer calls Tick.
	AfterFunc func(d time.Duration, f func()) (stop func())
	// OnFlush observes every flush, successful or not; may be nil.
	OnFlush func(Update, error)

	mu       sync.Mutex
	pending  []Proposal
	inflight []Proposal
	due      time.Time
	stop     func()
	flushMu  sync.Mutex
}

// Add queues a proposal and reports how many are now waiting.
func (c *Coalescer) Add(p Proposal) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = append(c.pending, p)
	if len(c.pending) == 1 {
		c.arm()
	}
	return len(c.pending)
}

// arm starts a window; c.mu is held.
func (c *Coalescer) arm() {
	c.due = c.Now().Add(c.Window)
	if c.AfterFunc != nil {
		c.stop = c.AfterFunc(c.Window, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			c.Flush(ctx)
		})
	}
}

// Pending reports how many proposals wait for the window to elapse.
func (c *Coalescer) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Proposed returns the newest content proposed for path and not yet in the
// pull request, if any.
func (c *Coalescer) Proposed(path string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, batch := range [][]Proposal{c.pending, c.inflight} {
		for i := len(batch) - 1; i >= 0; i-- {
			for j := len(batch[i].Files) - 1; j >= 0; j-- {
				if batch[i].Files[j].Path == path {
					return batch[i].Files[j].Content, true
				}
			}
		}
	}
	return nil, false
}

// Tick flushes if a window is armed and has elapsed at now.
func (c *Coalescer) Tick(ctx context.Context, now time.Time) (flushed bool, err error) {
	c.mu.Lock()
	ready := len(c.pending) > 0 && !now.Before(c.due)
	c.mu.Unlock()
	if !ready {
		return false, nil
	}
	_, err = c.Flush(ctx)
	return true, err
}

// Flush updates the pull request now with everything waiting. On failure the
// batch stays queued and a new window is armed, so nothing is lost and the
// pull request is still updated at most once per window.
func (c *Coalescer) Flush(ctx context.Context) (Update, error) {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	batch := c.pending
	c.pending, c.inflight = nil, batch
	if c.stop != nil {
		c.stop()
		c.stop = nil
	}
	c.mu.Unlock()
	if len(batch) == 0 {
		return Update{}, nil
	}
	up, err := c.PR.Update(ctx, batch)
	c.mu.Lock()
	c.inflight = nil
	if err != nil {
		rearm := len(c.pending) == 0
		c.pending = append(batch, c.pending...)
		if rearm {
			c.arm()
		}
	}
	c.mu.Unlock()
	if c.OnFlush != nil {
		c.OnFlush(up, err)
	}
	return up, err
}
