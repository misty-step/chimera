package land

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"chimera/pkg/forge"
	"chimera/pkg/gitx"
)

// StagingPrefix is the ref namespace rebased commits are parked in on a
// remote forge between the upload and the compare-and-swap.
const StagingPrefix = "refs/chimera/staging/"

// Fallback committer identity for rebased commits when the lander's Git has
// none configured. It names no operator.
const (
	fallbackName  = "chimera"
	fallbackEmail = "land@chimera.invalid"
)

// GitWorkspace rebases in the lander's own clone using the git binary. The
// user's checkout, index, and branches are never touched: every rebase runs
// in a temporary detached worktree that is removed afterwards.
type GitWorkspace struct {
	Dir string // the lander's repository (work tree or bare)
	// Remote is the forge's Git remote (a name or URL) when the forge is not
	// this repository: changes are fetched from it and rebased commits pushed
	// to it. Empty means the forge reads Dir directly.
	Remote string
}

// pinned are the settings a rebase must not inherit from ambient config.
var pinned = []string{"-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-c", "rebase.autoStash=false",
	"-c", "rebase.autoSquash=false", "-c", "rebase.updateRefs=false", "-c", "advice.mergeConflict=false", "-c", "merge.conflictStyle=merge"}

func (w *GitWorkspace) git(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	out, err := gitx.RunInput(ctx, dir, nil, env, append(append([]string{}, pinned...), args...)...)
	if err != nil {
		// gitx names the failure after the first argument, which here is a pin.
		return "", fmt.Errorf("git %s: %s", args[0], strings.TrimPrefix(err.Error(), "git -c: "))
	}
	return strings.TrimSpace(string(out)), nil
}

// identity returns committer environment for a lander with no configured
// Git identity; nil when Git already has one.
func (w *GitWorkspace) identity(ctx context.Context) []string {
	env := []string{"GIT_EDITOR=true", "GIT_SEQUENCE_EDITOR=true", "GIT_TERMINAL_PROMPT=0"}
	if os.Getenv("GIT_COMMITTER_EMAIL") != "" {
		return env
	}
	if email, err := gitx.Run(ctx, w.Dir, "config", "user.email"); err == nil && strings.TrimSpace(string(email)) != "" {
		return env
	}
	return append(env, "GIT_COMMITTER_NAME="+fallbackName, "GIT_COMMITTER_EMAIL="+fallbackEmail)
}

func (w *GitWorkspace) has(ctx context.Context, sha forge.SHA) bool {
	_, err := gitx.Run(ctx, w.Dir, "cat-file", "-e", string(sha)+"^{commit}")
	return err == nil
}

// fetchRefs brings refs from the forge's remote into the lander's clone
// (objects only; no local ref moves). A remote that does not answer is the
// forge being unavailable, not a fault of any change.
func (w *GitWorkspace) fetchRefs(ctx context.Context, refs ...string) error {
	if w.Remote == "" || len(refs) == 0 {
		return nil
	}
	args := append([]string{"fetch", "--quiet", "--no-tags", "--no-write-fetch-head", w.Remote}, refs...)
	if _, err := w.git(ctx, w.Dir, []string{"GIT_TERMINAL_PROMPT=0"}, args...); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: %s", forge.ErrUnavailable, err)
	}
	return nil
}

// fetch brings the change and the base into the lander's clone.
func (w *GitWorkspace) fetch(ctx context.Context, c forge.Change) error {
	var refs []string
	if c.Ref != "" {
		refs = append(refs, c.Ref)
	}
	if c.Target != "" {
		refs = append(refs, forge.RefName(c.Target))
	}
	return w.fetchRefs(ctx, refs...)
}

// Contains implements Workspace with git merge-base --is-ancestor. When the
// tip is not in the clone yet it is fetched from the remote first; a commit
// still unknown after that is not in the tip's history.
func (w *GitWorkspace) Contains(ctx context.Context, tip, sha forge.SHA) (bool, error) {
	if tip.IsZero() || sha.IsZero() {
		return false, nil
	}
	if !w.has(ctx, tip) && w.Remote != "" {
		// By object name where the remote allows it, else every branch.
		if err := w.fetchRefs(ctx, string(tip)); err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			if err := w.fetchRefs(ctx, "refs/heads/*"); err != nil {
				return false, err
			}
		}
	}
	if !w.has(ctx, tip) {
		return false, fmt.Errorf("commit %s is not in the lander's repository", tip.Short())
	}
	if !w.has(ctx, sha) {
		return false, nil
	}
	if forge.Same(tip, sha) {
		return true, nil
	}
	_, err := gitx.Run(ctx, w.Dir, "merge-base", "--is-ancestor", string(sha), string(tip))
	switch {
	case err == nil:
		return true, nil
	case ctx.Err() != nil:
		return false, ctx.Err()
	case exitOne(err):
		return false, nil
	}
	return false, err
}

// exitOne reports a git command that exited 1 without a word: the way
// merge-base says "no".
func exitOne(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ": exit status 1")
}

// Rebase implements Workspace.
func (w *GitWorkspace) Rebase(ctx context.Context, c forge.Change, base forge.SHA, squash bool) (Rebased, error) {
	rb := Rebased{Base: base}
	if !w.has(ctx, c.Head) || !w.has(ctx, base) {
		if err := w.fetch(ctx, c); err != nil {
			return rb, err
		}
	}
	for _, sha := range []forge.SHA{c.Head, base} {
		if !w.has(ctx, sha) {
			return rb, fmt.Errorf("commit %s is not in the lander's repository", sha.Short())
		}
	}
	if _, err := gitx.Run(ctx, w.Dir, "merge-base", string(base), string(c.Head)); err != nil {
		if ctx.Err() != nil {
			return rb, ctx.Err()
		}
		if exitOne(err) {
			return rb, &RejectError{Reason: "no common history with " + forge.Branch(c.Target)}
		}
		return rb, err
	}
	sources, err := gitx.RangeCommits(ctx, w.Dir, string(base), string(c.Head))
	if err != nil {
		return rb, err
	}
	rb.Sources = sources
	if len(sources) == 0 {
		return rb, ErrEmpty
	}

	tmp, err := os.MkdirTemp("", "chimera-land-")
	if err != nil {
		return rb, fmt.Errorf("cannot create rebase directory")
	}
	tree := filepath.Join(tmp, filepath.Base(tmp)) // a unique name: worktrees are keyed by basename
	cleanup := context.WithoutCancel(ctx)
	defer func() {
		if _, err := gitx.Run(cleanup, w.Dir, "worktree", "remove", "--force", tree); err != nil {
			os.RemoveAll(tree)
			gitx.Run(cleanup, w.Dir, "worktree", "prune")
		}
		os.RemoveAll(tmp)
	}()
	if _, err := w.git(ctx, w.Dir, nil, "worktree", "add", "--quiet", "--detach", tree, string(c.Head)); err != nil {
		return rb, err
	}
	env := w.identity(ctx)
	if _, err := w.git(ctx, tree, env, "rebase", "--quiet", "--no-autostash", "--no-gpg-sign", "--onto", string(base), string(base)); err != nil {
		if ctx.Err() != nil {
			return rb, ctx.Err()
		}
		out, _ := gitx.Run(cleanup, tree, "-c", "core.quotePath=false", "diff", "--name-only", "--diff-filter=U", "-z")
		var paths []string
		for _, p := range strings.Split(string(out), "\x00") {
			if p != "" {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)
		gitx.RunInput(cleanup, tree, nil, env, "rebase", "--abort")
		if len(paths) == 0 {
			return rb, err // not a conflict: the change itself cannot be replayed
		}
		return rb, &ConflictError{Paths: paths}
	}
	tip, err := gitx.RevParse(ctx, tree, "HEAD^{commit}")
	if err != nil {
		return rb, err
	}
	if forge.Same(forge.SHA(tip), base) {
		return rb, ErrEmpty // every commit was already upstream
	}
	replayed, err := gitx.RangeCommits(ctx, w.Dir, string(base), tip)
	if err != nil {
		return rb, err
	}
	// Each replayed commit must be one of the sources, in order, with that
	// source's trailers intact.
	if err := sameTrailers(sources, replayed); err != nil {
		return rb, err
	}
	if !squash {
		// A rebase replays only non-merge commits that are not upstream yet. A
		// source it leaves out — a merge commit above all — must not take a
		// trailer with it: every source trailer has to be in the target's
		// history once this lands (PRODUCT.md §2.4).
		upstream, err := gitx.RangeCommits(ctx, w.Dir, string(c.Head), string(base))
		if err != nil {
			return rb, err
		}
		kept := map[string]bool{}
		for _, list := range [][]gitx.Commit{replayed, upstream} {
			for _, k := range list {
				for _, tr := range k.Trailers {
					kept[strings.ToLower(tr.Key)+"\x00"+tr.Value] = true
				}
			}
		}
		for _, src := range sources {
			for _, tr := range src.Trailers {
				if !kept[strings.ToLower(tr.Key)+"\x00"+tr.Value] {
					return rb, &RejectError{Reason: fmt.Sprintf("rebase would drop the trailer %s of %q (a commit a rebase does not replay, such as a merge); land it with --squash, which carries the union", tr.Key, src.Subject)}
				}
			}
		}
	}
	if squash {
		if tip, err = w.squash(ctx, c, base, tip, sources, env); err != nil {
			return rb, err
		}
		if replayed, err = gitx.RangeCommits(ctx, w.Dir, string(base), tip); err != nil {
			return rb, err
		}
		var all [][]gitx.Trailer
		for _, s := range sources {
			all = append(all, s.Trailers)
		}
		want := gitx.UnionTrailers(all...)
		if len(replayed) != 1 || !equalTrailers(replayed[0].Trailers, want) {
			return rb, &RejectError{Reason: "squash would not carry the union of the source commits' trailers"}
		}
	}
	stats, err := gitx.DiffStat(ctx, w.Dir, string(base), tip)
	if err != nil {
		return rb, err
	}
	if len(stats) == 0 {
		return rb, ErrEmpty
	}
	for _, s := range stats {
		rb.Paths = append(rb.Paths, s.Path)
	}
	rb.SHA, rb.Commits = forge.SHA(tip), replayed
	return rb, nil
}

// squash writes one commit on base with the rebased tree. Its message is the
// first source commit's, and its trailer block is the union of every source
// commit's trailers, de-duplicated and in original order (PRODUCT.md §2.4).
func (w *GitWorkspace) squash(ctx context.Context, c forge.Change, base forge.SHA, tip string, sources []gitx.Commit, env []string) (string, error) {
	first := sources[0]
	msg, err := gitx.Run(ctx, w.Dir, "log", "-1", "--format=%B", first.SHA)
	if err != nil {
		return "", err
	}
	// The first message's own trailer block comes off: the union is written
	// in its place, so a trailer the source repeats appears once.
	msg = []byte(stripTrailerBlock(string(msg), first.Trailers))
	if strings.TrimSpace(string(msg)) == "" {
		msg = []byte("land " + c.Branch + "\n")
	}
	var all [][]gitx.Trailer
	for _, s := range sources {
		all = append(all, s.Trailers)
	}
	full, err := gitx.MessageWithTrailers(ctx, w.Dir, string(msg), gitx.UnionTrailers(all...))
	if err != nil {
		return "", err
	}
	author, err := gitx.Run(ctx, w.Dir, "log", "-1", "--format=%an%x00%ae%x00%aI", first.SHA)
	if err != nil {
		return "", err
	}
	if f := strings.Split(strings.TrimSpace(string(author)), "\x00"); len(f) == 3 {
		env = append(append([]string{}, env...), "GIT_AUTHOR_NAME="+f[0], "GIT_AUTHOR_EMAIL="+f[1], "GIT_AUTHOR_DATE="+f[2])
	}
	out, err := gitx.RunInput(ctx, w.Dir, []byte(full), env, "commit-tree", tip+"^{tree}", "-p", string(base), "-F", "-")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// stripTrailerBlock removes the last paragraph of msg when it is exactly the
// trailer block git parsed (one line per trailer, plus folded continuation
// lines). A message whose last paragraph mixes prose with trailers is left
// as it is.
func stripTrailerBlock(msg string, trailers []gitx.Trailer) string {
	if len(trailers) == 0 {
		return msg
	}
	body := strings.TrimRight(msg, "\n")
	i := strings.LastIndex(body, "\n\n")
	if i < 0 {
		return msg
	}
	keys := 0
	for _, line := range strings.Split(body[i+2:], "\n") {
		if line != "" && (line[0] == ' ' || line[0] == '\t') {
			continue // continuation of a folded trailer
		}
		k, _, ok := strings.Cut(line, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return msg
		}
		keys++
	}
	if keys != len(trailers) {
		return msg
	}
	return body[:i] + "\n"
}

func equalTrailers(a, b []gitx.Trailer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameTrailers checks that every replayed commit is one of the sources, in
// order, carrying exactly that source's trailers.
func sameTrailers(sources, replayed []gitx.Commit) error {
	i := 0
	for _, r := range replayed {
		for i < len(sources) && !(sources[i].Subject == r.Subject && equalTrailers(sources[i].Trailers, r.Trailers)) {
			i++
		}
		if i == len(sources) {
			return &RejectError{Reason: fmt.Sprintf("rebase would lose trailers on %q", r.Subject)}
		}
		i++
	}
	return nil
}

// Publish implements Workspace: with a Remote, the rebased commit is pushed
// to a staging ref so the forge has its objects before the compare-and-swap.
func (w *GitWorkspace) Publish(ctx context.Context, sha forge.SHA) (string, error) {
	if w.Remote == "" {
		return "", nil
	}
	ref := StagingPrefix + sha.Short()
	if _, err := w.git(ctx, w.Dir, []string{"GIT_TERMINAL_PROMPT=0"}, "push", "--quiet", "--no-verify", w.Remote, string(sha)+":"+ref); err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("%w: %s", forge.ErrUnavailable, err)
	}
	return ref, nil
}
