// Package gitx invokes the git binary. Chimera uses no Git libraries.
package gitx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Run executes git in dir and returns stdout. stderr is folded into the error.
func Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", args[0], strings.TrimPrefix(msg, "fatal: "))
	}
	return stdout.Bytes(), nil
}

// Toplevel returns the absolute path of the work tree containing dir.
func Toplevel(ctx context.Context, dir string) (string, error) {
	out, err := Run(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// LsFiles lists tracked files under root, relative to root, sorted.
func LsFiles(ctx context.Context, root string) ([]string, error) {
	return lsFiles(ctx, root, "ls-files", "-z", "--cached")
}

// LsFilesWithUntracked lists tracked plus untracked, non-ignored files.
func LsFilesWithUntracked(ctx context.Context, root string) ([]string, error) {
	return lsFiles(ctx, root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
}

func lsFiles(ctx context.Context, root string, args ...string) ([]string, error) {
	out, err := Run(ctx, root, args...)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return files, nil
}

// RunInput is Run with stdin and extra environment (KEY=VALUE) entries.
func RunInput(ctx context.Context, dir string, stdin []byte, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(stdin)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", args[0], strings.TrimPrefix(strings.TrimPrefix(msg, "fatal: "), "error: "))
	}
	return stdout.Bytes(), nil
}

// RevParse resolves a revision to a full object name.
func RevParse(ctx context.Context, dir, rev string) (string, error) {
	out, err := Run(ctx, dir, "rev-parse", "--verify", "--quiet", rev)
	if err != nil {
		return "", fmt.Errorf("unknown revision %q", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

// Trailer names binding Git to evidence (PRODUCT.md §1). They are the only
// binding; Chimera never writes evidence into Git.
const (
	TrailerIntent  = "Chimera-Intent"
	TrailerCapsule = "Chimera-Capsule"
)

// Trailers are the Chimera trailers on one commit, in message order.
type Trailers struct {
	Intents  []string
	Capsules []string
}

// Empty reports whether the commit carries no Capsule trailer.
func (t Trailers) Empty() bool { return len(t.Capsules) == 0 }

// ReadTrailers parses the Chimera trailers of a commit.
func ReadTrailers(ctx context.Context, dir, commit string) (Trailers, error) {
	out, err := Run(ctx, dir, "log", "-1", "--format=%(trailers:only,unfold)", commit)
	if err != nil {
		return Trailers{}, err
	}
	var t Trailers
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case strings.EqualFold(k, TrailerIntent):
			t.Intents = append(t.Intents, v)
		case strings.EqualFold(k, TrailerCapsule):
			t.Capsules = append(t.Capsules, v)
		}
	}
	return t, nil
}

// WithTrailers returns msg with both Chimera trailers added, Intent first,
// using git interpret-trailers. A pair already present is not repeated.
func WithTrailers(ctx context.Context, dir, msg, intent, capsule string) (string, error) {
	// --no-divider: a commit message is not a patch, so a "---" line in its
	// body does not end it; trailers go at the very end.
	out, err := RunInput(ctx, dir, []byte(msg), nil, "interpret-trailers", "--no-divider", "--if-exists", "addIfDifferent",
		"--trailer", TrailerIntent+": "+intent, "--trailer", TrailerCapsule+": "+capsule)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// BlameLine returns the commit that last changed file:line.
func BlameLine(ctx context.Context, dir, file string, line int) (string, error) {
	out, err := Run(ctx, dir, "blame", "--porcelain", "-L", fmt.Sprintf("%d,%d", line, line), "--", file)
	if err != nil {
		return "", err
	}
	sha, _, _ := strings.Cut(string(out), " ")
	if len(sha) < 40 || strings.Trim(sha, "0") == "" {
		return "", fmt.Errorf("line %d is not committed", line)
	}
	return sha, nil
}

// LastCommit returns the newest commit that touched path.
func LastCommit(ctx context.Context, dir, path string) (string, error) {
	out, err := Run(ctx, dir, "log", "-1", "--format=%H", "--", path)
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(string(out))
	if sha == "" {
		return "", fmt.Errorf("no commit touches %s", path)
	}
	return sha, nil
}

// CountSince counts commits after `since` (exclusive) up to HEAD that touched
// path; an empty path counts every commit.
func CountSince(ctx context.Context, dir, since, path string) (int, error) {
	args := []string{"rev-list", "--count", since + "..HEAD"}
	if path != "" {
		args = append(args, "--", path)
	}
	out, err := Run(ctx, dir, args...)
	if err != nil {
		return 0, err
	}
	var n int
	fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &n)
	return n, nil
}

// TreeEntry is one blob in a tree.
type TreeEntry struct {
	Mode, SHA, Path string
}

// LsTree lists every blob reachable from rev, sorted by path.
func LsTree(ctx context.Context, dir, rev string) ([]TreeEntry, error) {
	out, err := Run(ctx, dir, "ls-tree", "-r", "-z", rev)
	if err != nil {
		return nil, err
	}
	var entries []TreeEntry
	for _, rec := range strings.Split(string(out), "\x00") {
		meta, path, ok := strings.Cut(rec, "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 || f[1] != "blob" {
			continue
		}
		entries = append(entries, TreeEntry{Mode: f[0], SHA: f[2], Path: path})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, nil
}

// CatBlobs reads many blobs with one git cat-file --batch process.
func CatBlobs(ctx context.Context, dir string, shas []string) (map[string][]byte, error) {
	out, err := RunInput(ctx, dir, []byte(strings.Join(shas, "\n")+"\n"), nil, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	blobs := make(map[string][]byte, len(shas))
	for len(out) > 0 {
		nl := bytes.IndexByte(out, '\n')
		if nl < 0 {
			break
		}
		f := strings.Fields(string(out[:nl]))
		out = out[nl+1:]
		if len(f) != 3 {
			continue // "<sha> missing"
		}
		var size int
		fmt.Sscanf(f[2], "%d", &size)
		if size > len(out) {
			return nil, fmt.Errorf("git cat-file: short output")
		}
		blobs[f[0]] = out[:size:size]
		out = out[size:]
		if len(out) > 0 && out[0] == '\n' {
			out = out[1:]
		}
	}
	return blobs, nil
}

// IsFolioPath reports whether a path is Folio source: PRODUCT.md, DESIGN.md,
// or anything under folio/assets/.
func IsFolioPath(p string) bool {
	return p == "PRODUCT.md" || p == "DESIGN.md" || strings.HasPrefix(p, "folio/assets/")
}

// FolioIntent computes the folio Intent ID at rev: SHA-256 over one line per
// Folio source file, sorted by path, "<path>\x00<git-blob-sha>\n".
func FolioIntent(ctx context.Context, dir, rev string) (string, error) {
	entries, err := LsTree(ctx, dir, rev)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n := 0
	for _, e := range entries {
		if IsFolioPath(e.Path) {
			fmt.Fprintf(h, "%s\x00%s\n", e.Path, e.SHA)
			n++
		}
	}
	if n == 0 {
		return "", fmt.Errorf("no folio at %s", rev)
	}
	return "folio:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Trailer is one "Key: value" line of a commit message's trailer block.
type Trailer struct {
	Key, Value string
}

func parseTrailers(block, sep string) []Trailer {
	var out []Trailer
	for _, line := range strings.Split(block, sep) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			continue
		}
		out = append(out, Trailer{Key: k, Value: strings.TrimSpace(v)})
	}
	return out
}

// CommitTrailers returns every trailer of a commit, in message order.
func CommitTrailers(ctx context.Context, dir, commit string) ([]Trailer, error) {
	out, err := Run(ctx, dir, "log", "-1", "--format=%(trailers:only,unfold)", commit)
	if err != nil {
		return nil, err
	}
	return parseTrailers(string(out), "\n"), nil
}

// UnionTrailers merges the trailers of source commits, given oldest first:
// every distinct trailer once, in the order it first appeared. Keys compare
// case-insensitively, values exactly. This is what a squash or rebase must
// write so that no source commit's evidence binding is lost (PRODUCT.md §2.4).
func UnionTrailers(sources ...[]Trailer) []Trailer {
	seen := map[string]bool{}
	var out []Trailer
	for _, src := range sources {
		for _, t := range src {
			k := strings.ToLower(t.Key) + "\x00" + t.Value
			if t.Key == "" || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, t)
		}
	}
	return out
}

// ChimeraTrailers picks the Intent and Capsule trailers out of a trailer list.
func ChimeraTrailers(ts []Trailer) Trailers {
	var t Trailers
	for _, tr := range ts {
		switch {
		case strings.EqualFold(tr.Key, TrailerIntent):
			t.Intents = append(t.Intents, tr.Value)
		case strings.EqualFold(tr.Key, TrailerCapsule):
			t.Capsules = append(t.Capsules, tr.Value)
		}
	}
	return t
}

// MessageWithTrailers returns msg (a subject and optional body, without a
// trailer block of its own that should be kept apart) with the given trailers
// appended in order, using git interpret-trailers. A trailer already present
// is not repeated.
func MessageWithTrailers(ctx context.Context, dir, msg string, trailers []Trailer) (string, error) {
	msg = strings.TrimRight(msg, "\n") + "\n"
	if len(trailers) == 0 {
		return msg, nil
	}
	args := []string{"-c", "trailer.ifexists=addIfDifferent", "-c", "trailer.ifmissing=add", "-c", "trailer.where=end",
		"interpret-trailers", "--no-divider", "--where", "end", "--if-exists", "addIfDifferent", "--if-missing", "add"}
	for _, t := range trailers {
		args = append(args, "--trailer", t.Key+": "+t.Value)
	}
	out, err := RunInput(ctx, dir, []byte(msg), nil, args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Commit is one commit of a range.
type Commit struct {
	SHA      string
	Parents  []string
	Subject  string
	Trailers []Trailer // every trailer, in message order
}

// Chimera returns the commit's Intent and Capsule trailers.
func (c Commit) Chimera() Trailers { return ChimeraTrailers(c.Trailers) }

// RangeCommits lists the commits in base..head, oldest first, in a stable
// topological order. Fields are framed with NUL, which no commit message can
// contain, and the parsed count is checked against git rev-list: a commit
// can never be silently dropped from a walk, whatever bytes its subject
// holds.
func RangeCommits(ctx context.Context, dir, base, head string) ([]Commit, error) {
	out, err := Run(ctx, dir, "log", "--reverse", "--topo-order",
		"--format=%H%x00%P%x00%s%x00%(trailers:only,unfold)%x00", base+".."+head)
	if err != nil {
		return nil, err
	}
	fields := strings.Split(string(out), "\x00")
	var commits []Commit
	for i := 0; i+3 < len(fields); i += 4 {
		sha := strings.TrimLeft(fields[i], "\n")
		if len(sha) < 40 {
			return nil, fmt.Errorf("git log: unreadable record in %s..%s", base, head)
		}
		commits = append(commits, Commit{SHA: sha, Parents: strings.Fields(fields[i+1]), Subject: fields[i+2], Trailers: parseTrailers(fields[i+3], "\n")})
	}
	count, err := Run(ctx, dir, "rev-list", "--count", base+".."+head)
	if err != nil {
		return nil, err
	}
	var want int
	fmt.Sscanf(strings.TrimSpace(string(count)), "%d", &want)
	if want != len(commits) {
		return nil, fmt.Errorf("git log: read %d of %d commits in %s..%s", len(commits), want, base, head)
	}
	return commits, nil
}

// FileStat is one file of a diff: lines added and deleted (both zero for a
// binary file, which sets Binary).
type FileStat struct {
	Path           string
	Added, Deleted int
	Binary         bool
}

// EmptyTree returns the object name of the empty tree in dir's object format.
func EmptyTree(ctx context.Context, dir string) (string, error) {
	out, err := RunInput(ctx, dir, nil, nil, "hash-object", "-t", "tree", "--stdin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// DiffStat lists the files that differ between two trees or commits, sorted
// by path, with renames off so a moved file counts on both sides. An empty
// from means the empty tree (a root commit's whole content).
//
// The counts do not depend on the checkout: the diff algorithm is pinned, and
// a file Git calls binary — truly binary, or marked "-diff" in a
// .gitattributes the change itself may carry — is counted again as text, so
// an attribute cannot switch the line count off. Binary stays set for it.
func DiffStat(ctx context.Context, dir, from, to string) ([]FileStat, error) {
	if from == "" {
		var err error
		if from, err = EmptyTree(ctx, dir); err != nil {
			return nil, err
		}
	}
	args := []string{"--literal-pathspecs", "-c", "core.quotePath=false", "-c", "diff.algorithm=myers", "diff", "--no-renames",
		"--no-ext-diff", "--no-textconv", "--no-color", "--diff-algorithm=myers"}
	out, err := Run(ctx, dir, append(append([]string{}, args...), "--numstat", "-z", from, to)...)
	if err != nil {
		return nil, err
	}
	var stats []FileStat
	for _, rec := range strings.Split(string(out), "\x00") {
		f := strings.SplitN(rec, "\t", 3)
		if len(f) != 3 || f[2] == "" {
			continue
		}
		st := FileStat{Path: f[2]}
		if f[0] == "-" {
			// --numstat honours the attribute even under --text; the patch does not.
			st.Binary = true
			patch, err := Run(ctx, dir, append(append([]string{}, args...), "--text", "-U0", from, to, "--", st.Path)...)
			if err != nil {
				return nil, err
			}
			inHunk := false
			for _, line := range strings.Split(string(patch), "\n") {
				switch {
				case strings.HasPrefix(line, "@@"):
					inHunk = true
				case inHunk && strings.HasPrefix(line, "+"):
					st.Added++
				case inHunk && strings.HasPrefix(line, "-"):
					st.Deleted++
				}
			}
		} else {
			fmt.Sscanf(f[0], "%d", &st.Added)
			fmt.Sscanf(f[1], "%d", &st.Deleted)
		}
		stats = append(stats, st)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Path < stats[j].Path })
	return stats, nil
}
