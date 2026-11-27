package inlet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// ProposalFile is one Folio file a proposal writes.
type ProposalFile struct {
	Path    string `json:"path"`
	Content []byte `json:"content"`
	// Seen is the SHA-256 (hex) of the file as the classifier saw it. When
	// set, the file is written only if the Folio still reads that way; an
	// edit made against a Folio that has since moved is dropped, never
	// applied over someone else's change. Empty means unconditional.
	Seen string `json:"seen,omitempty"`
}

// Proposal is one owner nit on its way into the Folio-only pull request.
type Proposal struct {
	ID         string         `json:"id"` // "<YYYYMMDD>-<n>", unique per repository
	ReceivedAt time.Time      `json:"received_at"`
	Summary    string         `json:"summary"` // one line
	Files      []ProposalFile `json:"files"`
}

// Refusal is a proposal the pull request will never take, and why. A refused
// proposal leaves its batch; the rest of the batch still lands.
type Refusal struct {
	ID     string // the proposal
	Reason string // path-fence | path-conflict | secret-gate | unstageable
	Detail string // locations and rules; never content
}

// Update is what one update of the Folio pull request did.
type Update struct {
	Change  forge.Change // the branch, its new head, and the target
	Pushed  bool         // false when the branch already held everything
	Capsule string       // address of the Capsule the new commit cites; "" when nothing was pushed
	Dropped []string     // "<proposal>: <path>" edits dropped as stale
	Refused []Refusal    // proposals refused whole
}

// FolioPR is the one open Folio-only pull request of a repository.
type FolioPR interface {
	// Update adds a batch of proposals to the pull request, opening it if
	// there is none. It must never write a path outside the fence. A proposal
	// that can never land is returned in Update.Refused rather than failing
	// the batch; an error means the whole batch should be tried again.
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
//
// Every commit it authors carries both trailers (PRODUCT.md §1):
// Chimera-Intent is the Folio Intent of the commit's own tree, and
// Chimera-Capsule is a Capsule — the coalesced nits, the diff, and the fence
// verdict — pushed through the secret gate before the commit exists.
type BranchPR struct {
	RepoDir string // a clone holding the target's objects
	Forge   forge.Forge
	Branch  string // "" means DefaultFolioBranch
	Target  string
	Store   objstore.Store      // where the commit's Capsule goes
	Gate    *secretscan.Scanner // nil means the built-in rules alone
	Repo    string              // repository name recorded in the Capsule
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

func (b *BranchPR) gate() *secretscan.Scanner {
	if b.Gate != nil {
		return b.Gate
	}
	return secretscan.New(nil)
}

const pushAttempts = 5

func sum(content []byte) string {
	s := sha256.Sum256(content)
	return hex.EncodeToString(s[:])
}

// errRebuild asks Update to build the commit again without a proposal that
// has just been refused.
var errRebuild = errors.New("rebuild without the refused proposal")

// Update implements FolioPR.
func (b *BranchPR) Update(ctx context.Context, batch []Proposal) (Update, error) {
	if b.Forge == nil || b.RepoDir == "" || b.Target == "" {
		return Update{}, fmt.Errorf("folio pr: forge, repository, and target are required")
	}
	if b.branch() == forge.Branch(b.Target) {
		return Update{}, fmt.Errorf("folio pr: the pull request's branch is its own target; nothing pushed")
	}
	if b.Store == nil {
		return Update{}, fmt.Errorf("folio pr: no store; every folio commit must cite a capsule")
	}
	refused := map[string]Refusal{}
	finish := func(up Update) Update {
		for _, p := range batch {
			if r, ok := refused[p.ID]; ok {
				up.Refused = append(up.Refused, r)
			}
		}
		return up
	}
	var last error
	stale := 0
	for rebuilds := 0; stale < pushAttempts && rebuilds <= len(batch); {
		up, err := b.update(ctx, batch, refused)
		switch {
		case errors.Is(err, errRebuild):
			rebuilds++
		case errors.Is(err, forge.ErrStale):
			stale++
			last = err
		default:
			return finish(up), err
		}
	}
	if last == nil {
		last = fmt.Errorf("proposals kept failing to stage")
	}
	return finish(Update{}), fmt.Errorf("folio pr: branch kept moving: %w", last)
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

// treePaths is the set of files and directories in the index being built, so
// a proposal that would put a file where a directory is (or the reverse) is
// refused before Git is asked to stage the impossible.
type treePaths struct{ files, dirs map[string]bool }

func (t *treePaths) add(p string) {
	t.files[p] = true
	for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
		t.dirs[p[:i]] = true
	}
}

func (t *treePaths) conflict(p string) bool {
	if t.dirs[p] {
		return true
	}
	for i := strings.LastIndexByte(p, '/'); i > 0; i = strings.LastIndexByte(p[:i], '/') {
		if t.files[p[:i]] {
			return true
		}
	}
	return false
}

// judge decides whether a proposal can ever be staged on the tree as it
// stands: every path in the fence, nothing the secret gate refuses, no file
// where a directory is.
func (b *BranchPR) judge(p Proposal, tree *treePaths) (Refusal, bool) {
	for _, f := range p.Files {
		if !InFence(f.Path) {
			return Refusal{ID: p.ID, Reason: "path-fence"}, true
		}
	}
	var findings []secretscan.Finding
	gate := b.gate()
	for _, f := range p.Files {
		findings = append(findings, gate.Scan(f.Path, f.Content)...)
	}
	findings = append(findings, gate.Scan("summary", []byte(p.Summary))...)
	if len(findings) > 0 {
		return Refusal{ID: p.ID, Reason: "secret-gate", Detail: locations(findings)}, true
	}
	own := &treePaths{files: map[string]bool{}, dirs: map[string]bool{}}
	for _, f := range p.Files {
		if tree.conflict(f.Path) || own.conflict(f.Path) {
			return Refusal{ID: p.ID, Reason: "path-conflict", Detail: f.Path}, true
		}
		own.add(f.Path)
	}
	return Refusal{}, false
}

// locations renders findings as member:line:col rule — never a value.
func locations(fs []secretscan.Finding) string {
	secretscan.Sort(fs)
	out := make([]string, 0, len(fs))
	for i, f := range fs {
		if i == 8 {
			out = append(out, fmt.Sprintf("and %d more", len(fs)-i))
			break
		}
		out = append(out, f.String())
	}
	return strings.Join(out, ", ")
}

func (b *BranchPR) update(ctx context.Context, batch []Proposal, refused map[string]Refusal) (Update, error) {
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
	// A private index, and paths taken literally: no name is ever a pattern.
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(tmp, "index"), "GIT_LITERAL_PATHSPECS=1"}
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
	listed, err := gitx.RunInput(ctx, b.RepoDir, nil, env, "ls-files", "-z")
	if err != nil {
		return Update{}, err
	}
	tree := &treePaths{files: map[string]bool{}, dirs: map[string]bool{}}
	for _, p := range strings.Split(string(listed), "\x00") {
		if p != "" {
			tree.add(p)
		}
	}

	var accepted []Proposal
	for _, p := range batch {
		if _, out := refused[p.ID]; out {
			continue
		}
		if r, no := b.judge(p, tree); no {
			refused[p.ID] = r
			continue
		}
		for _, f := range p.Files {
			var current []byte
			present := false
			if entry, _ := git(nil, "ls-files", "-s", "--", f.Path); entry != "" {
				if fields := strings.Fields(entry); len(fields) >= 2 {
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
			if err == nil {
				err = stage(blob, f.Path)
			}
			if err != nil {
				if ctx.Err() != nil {
					return Update{}, ctx.Err()
				}
				// Git will not stage it, for a reason the checks above did not
				// foresee. The proposal goes; the index is rebuilt without it.
				refused[p.ID] = Refusal{ID: p.ID, Reason: "unstageable", Detail: f.Path}
				return Update{}, errRebuild
			}
			tree.add(f.Path)
		}
		accepted = append(accepted, p)
	}
	sort.Strings(up.Dropped)
	if len(accepted) == 0 {
		return up, nil // nothing left to propose
	}
	newTree, err := git(nil, "write-tree")
	if err != nil {
		return Update{}, err
	}
	baseTree, err := gitx.RevParse(ctx, b.RepoDir, string(base)+"^{tree}")
	if err != nil {
		return Update{}, err
	}
	if newTree == baseTree && !diverged {
		if base == target {
			// Nothing to propose on top of the target: no pull request to move.
			return up, nil
		}
		// The branch already holds the whole batch (an earlier update pushed
		// but could not announce): announce again, push nothing.
		return up, b.notify(ctx, up, accepted)
	}

	// Second, independent fence check, on the tree itself: what the pull
	// request would change on the target must be plain Folio files and
	// nothing else — no path outside the fence, no symlink, no executable, no
	// submodule.
	raw, err := gitx.Run(ctx, b.RepoDir, "diff-tree", "-r", "-z", "--raw", "--no-renames", string(target), newTree)
	if err != nil {
		return Update{}, err
	}
	changed := 0
	recs := strings.Split(string(raw), "\x00")
	for i := 0; i+1 < len(recs); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(recs[i], ":"))
		path := recs[i+1]
		if len(meta) < 5 {
			return Update{}, fmt.Errorf("folio pr: cannot read the branch's changes; nothing pushed")
		}
		changed++
		if !InFence(path) {
			return Update{}, fmt.Errorf("folio pr: branch %s changes a path outside the folio fence; nothing pushed", branch)
		}
		if mode := meta[1]; mode != "100644" && mode != "000000" {
			return Update{}, fmt.Errorf("folio pr: branch %s holds a folio path that is not a plain file (mode %s); nothing pushed", branch, mode)
		}
	}

	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	// Evidence first: the Capsule must be in the store before a commit cites it.
	// For a merge the diff is taken against the target it merges — exactly
	// what the pull request proposes — otherwise against the parent.
	diffBase := base
	if diverged {
		diffBase = target
	}
	intent, err := gitx.FolioIntent(ctx, b.RepoDir, newTree)
	if err != nil {
		return Update{}, fmt.Errorf("folio pr: the tree holds no folio; nothing pushed")
	}
	address, err := b.seal(ctx, intent, diffBase, newTree, accepted, changed, now)
	if err != nil {
		return Update{}, err
	}
	msg, err := gitx.MessageWithTrailers(ctx, b.RepoDir, commitMessage(accepted, diverged, forge.Branch(b.Target)),
		[]gitx.Trailer{{Key: gitx.TrailerIntent, Value: intent}, {Key: gitx.TrailerCapsule, Value: address}})
	if err != nil {
		return Update{}, err
	}
	stamp := fmt.Sprintf("@%d +0000", now.Unix())
	args := []string{"commit-tree", newTree}
	for _, p := range parents {
		args = append(args, "-p", string(p))
	}
	commitEnv := append(append([]string{}, env...),
		"GIT_AUTHOR_NAME=chimera inlet", "GIT_AUTHOR_EMAIL=inlet@chimera.invalid", "GIT_AUTHOR_DATE="+stamp,
		"GIT_COMMITTER_NAME=chimera inlet", "GIT_COMMITTER_EMAIL=inlet@chimera.invalid", "GIT_COMMITTER_DATE="+stamp)
	out, err := gitx.RunInput(ctx, b.RepoDir, []byte(msg), commitEnv, args...)
	if err != nil {
		return Update{}, err
	}
	commit := forge.SHA(strings.TrimSpace(string(out)))

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
	up.Change.Head, up.Pushed, up.Capsule = commit, true, address
	return up, b.notify(ctx, up, accepted)
}

// seal packs and pushes the Capsule a Folio commit cites: one transcript
// line per coalesced nit, the diff, and the fence verdict. The secret gate
// scans every byte; a finding refuses the update (fail closed) and is
// reported as member:line:col rule, never as a value.
func (b *BranchPR) seal(ctx context.Context, intent string, base forge.SHA, tree string, batch []Proposal, changed int, now time.Time) (string, error) {
	diff, err := gitx.Run(ctx, b.RepoDir, "-c", "core.quotePath=false", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
		"diff", "--full-index", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color",
		"--src-prefix=a/", "--dst-prefix=b/", string(base), tree)
	if err != nil {
		return "", err
	}
	checkpoint, err := capsule.NewCheckpoint(now)
	if err != nil {
		return "", err
	}
	var transcript bytes.Buffer
	enc := json.NewEncoder(&transcript)
	enc.SetEscapeHTML(false)
	seq := 0
	event := func(e lane.Event) int {
		seq++
		e.Seq, e.Checkpoint = seq, checkpoint
		enc.Encode(e)
		return seq
	}
	event(lane.Event{Event: "start", BaseSHA: string(base), Tree: tree})
	for _, p := range batch {
		var paths []string
		for _, f := range p.Files {
			paths = append(paths, f.Path)
		}
		event(lane.Event{Event: "output", Step: "inlet", Line: fmt.Sprintf("nit-%s received %s: %s (%s)",
			p.ID, p.ReceivedAt.UTC().Format(time.RFC3339), oneLine(p.Summary, 200), strings.Join(paths, ", "))})
	}
	pass := true
	const criterion = "only PRODUCT.md, DESIGN.md, folio/** changed"
	at := event(lane.Event{Event: "verdict", ID: "fence", Criterion: criterion, Pass: &pass})
	event(lane.Event{Event: "end"})
	verdicts, _ := json.MarshalIndent([]capsule.Verdict{{ID: "fence", Criterion: criterion, Pass: true,
		Evidence: fmt.Sprintf("transcript:%d; %d paths changed against the target, all plain files inside the fence", at, changed)}}, "", "  ")

	dir, err := os.MkdirTemp("", "chimera-folio-capsule-")
	if err != nil {
		return "", fmt.Errorf("folio pr: cannot create capsule directory")
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{
		capsule.MemberTranscript: capsule.Zstd(transcript.Bytes()),
		capsule.MemberDiff:       diff,
		capsule.MemberVerdicts:   append(verdicts, '\n'),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return "", fmt.Errorf("folio pr: cannot write capsule member %s", name)
		}
	}
	addr, err := capsule.Pack(dir, capsule.Meta{Intent: intent, Checkpoint: checkpoint, Repo: b.Repo, BaseSHA: string(base),
		Lane:      capsule.LaneConfig{Harness: "inlet", ContextPolicy: "none", Runner: "local"},
		StartedAt: now, EndedAt: now, Tags: []string{"inlet:folio"}})
	if err != nil {
		return "", fmt.Errorf("folio pr: capsule: %w", err)
	}
	if _, err := capsule.Push(ctx, b.Store, dir, b.gate()); err != nil {
		var ge *capsule.GateError
		if errors.As(err, &ge) {
			return "", fmt.Errorf("folio pr: %s at %s; nothing pushed", ge.Error(), locations(ge.Findings))
		}
		return "", fmt.Errorf("folio pr: capsule: %w", err)
	}
	return string(addr), nil
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

// commitMessage is the subject and body of a Folio commit. Its last
// paragraph is prose, not a trailer: the trailer block holds exactly
// Chimera-Intent and Chimera-Capsule, in that order.
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
	m.WriteString("\nOnly PRODUCT.md, DESIGN.md, and files under folio/ change.\n")
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
	// OnSettled is told what left the queue for good: the proposals an
	// update carried into the pull request, and the ones it refused (with the
	// proposal each refusal is about). May be nil.
	OnSettled func(up Update, landed []Proposal, refused []Proposal)

	mu       sync.Mutex
	pending  []Proposal
	inflight []Proposal
	due      time.Time
	stop     func()
	closed   bool
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
	if c.AfterFunc != nil && !c.closed {
		c.stop = c.AfterFunc(c.Window, func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			c.Flush(ctx)
		})
	}
}

// Close stops the scheduled flush. What is waiting stays queued; whoever
// persisted it can queue it again.
func (c *Coalescer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.stop != nil {
		c.stop()
		c.stop = nil
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

// Flush updates the pull request now with everything waiting. A proposal the
// pull request refuses leaves the queue at once and for good, so one bad
// proposal never holds the others back. On any other failure the rest of the
// batch stays queued and a new window is armed: nothing is lost, and the
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
	out := map[string]bool{}
	for _, r := range up.Refused {
		out[r.ID] = true
	}
	var kept, refused []Proposal
	for _, p := range batch {
		if out[p.ID] {
			refused = append(refused, p)
		} else {
			kept = append(kept, p)
		}
	}
	c.mu.Lock()
	c.inflight = nil
	if err != nil && len(kept) > 0 {
		rearm := len(c.pending) == 0
		c.pending = append(kept, c.pending...)
		if rearm {
			c.arm()
		}
	}
	c.mu.Unlock()
	if c.OnSettled != nil {
		landed := kept
		if err != nil {
			landed = nil
		}
		if len(landed) > 0 || len(refused) > 0 {
			c.OnSettled(up, landed, refused)
		}
	}
	if c.OnFlush != nil {
		c.OnFlush(up, err)
	}
	return up, err
}
