// Package lane implements the Lane and the Bench (PRODUCT.md §2.2): one
// engine that turns (Intent, LaneConfig) into a Capsule on an isolated,
// ephemeral sandbox. A production run is a Bench of K=1.
package lane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"chimera/pkg/gitx"
)

// Runner is the only sandbox abstraction. It provisions a workspace at
// (repo, base_sha); the workspace executes commands, collects artifacts, and
// tears down.
type Runner interface {
	Name() string
	Provision(ctx context.Context, repoDir, baseSHA string) (Workspace, error)
}

// Workspace is one provisioned sandbox.
type Workspace interface {
	// Dir is the checked-out tree as commands inside the sandbox see it.
	Dir() string
	// OutDir is a scratch directory outside the tree: the prompt and scent go
	// in; verdicts.json and usage.json come out.
	OutDir() string
	Put(ctx context.Context, name string, data []byte) error
	// Read returns a file from OutDir, or fs.ErrNotExist.
	Read(ctx context.Context, name string) ([]byte, error)
	// Exec runs argv in Dir. A command that outlives timeout is killed.
	Exec(ctx context.Context, argv, env []string, timeout time.Duration) ExecResult
	// Tree returns the Git tree hash of the checkout as provisioned.
	Tree(ctx context.Context) (string, error)
	// Diff returns base_sha..result in git format with full blob IDs.
	Diff(ctx context.Context) ([]byte, error)
	Teardown(ctx context.Context) error
}

// ExecResult is what one command did.
type ExecResult struct {
	ExitCode int
	Stdout   []byte // stdout alone, capped: what a caller parses
	// StdoutTruncated is set when Stdout hit the cap; a caller parsing it
	// must refuse rather than use a partial answer.
	StdoutTruncated bool
	Output          []byte // stdout and stderr, interleaved, capped
	TimedOut        bool
	WallMS          int64
	Err             string // why the command could not run at all; "" otherwise
}

// maxOutput caps captured output per command.
const maxOutput = 4 << 20

// capWriter is a bounded buffer. stdout and stderr are copied by separate
// goroutines into the same combined writer, so writes are serialized.
type capWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := maxOutput - w.buf.Len(); room < len(p) {
		if room > 0 {
			w.buf.Write(p[:room])
		}
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *capWriter) bytes() []byte {
	if w.truncated {
		return append(w.buf.Bytes(), []byte("\n[output truncated]\n")...)
	}
	return w.buf.Bytes()
}

// run executes one process with a timeout, killing its whole process group
// when the timeout or the parent context fires.
func run(ctx context.Context, dir string, argv, env []string, timeout time.Duration) ExecResult {
	if len(argv) == 0 {
		return ExecResult{ExitCode: -1, Err: "empty command"}
	}
	tctx := ctx
	cancel := func() {}
	if timeout > 0 {
		tctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	cmd := exec.CommandContext(tctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = env
	var out, stdout capWriter
	cmd.Stdout, cmd.Stderr = io.MultiWriter(&out, &stdout), &out
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	err := cmd.Run()
	// Whatever happened, nothing the command started may outlive it.
	killProcessGroup(cmd)
	res := ExecResult{Output: out.bytes(), Stdout: stdout.buf.Bytes(), StdoutTruncated: stdout.truncated, WallMS: time.Since(start).Milliseconds()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.Is(err, exec.ErrWaitDelay) && tctx.Err() == nil:
		// The command exited but a child it left behind held the output pipe
		// open. The command's own exit status stands.
		if cmd.ProcessState != nil {
			res.ExitCode = cmd.ProcessState.ExitCode()
		}
	case tctx.Err() != nil:
		res.TimedOut = ctx.Err() == nil
		res.ExitCode = -1
		if !res.TimedOut {
			res.Err = "interrupted"
		}
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
	default:
		res.ExitCode = -1
		res.Err = "cannot start " + filepath.Base(argv[0])
	}
	return res
}

// baseEnv is the process environment minus Chimera's own secrets, which no
// harness or verifier needs and no transcript should be able to echo.
func baseEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "CHIMERA_S3_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// Local runs lanes in a temporary git worktree of the repository. It is the
// adapter for development and tests.
type Local struct{}

func (Local) Name() string { return "local" }

type localWS struct {
	repoDir, root, tree, out, base string
}

// Provision implements Runner with `git worktree add --detach`.
func (Local) Provision(ctx context.Context, repoDir, baseSHA string) (Workspace, error) {
	root, err := os.MkdirTemp("", "chimera-lane-")
	if err != nil {
		return nil, fmt.Errorf("cannot create lane directory")
	}
	ws := &localWS{repoDir: repoDir, root: root, tree: filepath.Join(root, "tree"), out: filepath.Join(root, "out"), base: baseSHA}
	if err := os.Mkdir(ws.out, 0o755); err != nil {
		os.RemoveAll(root)
		return nil, fmt.Errorf("cannot create lane directory")
	}
	if _, err := gitx.Run(ctx, repoDir, "worktree", "add", "--quiet", "--detach", ws.tree, baseSHA); err != nil {
		os.RemoveAll(root)
		return nil, err
	}
	return ws, nil
}

func (w *localWS) Dir() string    { return w.tree }
func (w *localWS) OutDir() string { return w.out }

func (w *localWS) Put(_ context.Context, name string, data []byte) error {
	if err := os.WriteFile(filepath.Join(w.out, filepath.Base(name)), data, 0o644); err != nil {
		return fmt.Errorf("cannot write %s", name)
	}
	return nil
}

func (w *localWS) Read(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(w.out, filepath.Base(name)))
}

func (w *localWS) Exec(ctx context.Context, argv, env []string, timeout time.Duration) ExecResult {
	return run(ctx, w.tree, argv, append(baseEnv(), env...), timeout)
}

func (w *localWS) Tree(ctx context.Context) (string, error) {
	return gitx.RevParse(ctx, w.tree, "HEAD^{tree}")
}

// diffArgs is the one way Chimera renders a lane's diff. Every option that
// ambient or harness-written Git config could change is pinned, so the same
// tree change gives the same bytes on any machine.
func diffArgs(base string) []string {
	return []string{"-c", "core.quotePath=false", "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
		"diff", "--cached", "--full-index", "--binary", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color",
		"--src-prefix=a/", "--dst-prefix=b/", base}
}

// Diff stages the whole tree into a private index seeded from the base
// commit, so flags a harness set on the checkout's own index
// (skip-worktree, assume-unchanged) cannot hide a change.
func (w *localWS) Diff(ctx context.Context) ([]byte, error) {
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(w.root, "diff.index")}
	if _, err := gitx.RunInput(ctx, w.tree, nil, env, "read-tree", w.base); err != nil {
		return nil, err
	}
	if _, err := gitx.RunInput(ctx, w.tree, nil, env, "add", "-A"); err != nil {
		return nil, err
	}
	return gitx.RunInput(ctx, w.tree, nil, env, diffArgs(w.base)...)
}

func (w *localWS) Teardown(ctx context.Context) error {
	_, err := gitx.Run(ctx, w.repoDir, "worktree", "remove", "--force", w.tree)
	// Ring-0 files were made read-only; make the scratch tree removable.
	filepath.WalkDir(w.root, func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && d.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})
	if rerr := os.RemoveAll(w.root); err == nil && rerr != nil {
		err = fmt.Errorf("cannot remove lane directory")
	}
	gitx.Run(ctx, w.repoDir, "worktree", "prune")
	return err
}

// Boat runs lanes in a remote ephemeral sandbox through its CLI. Every
// interaction is one invocation of Command: new, ssh, scp, delete.
type Boat struct {
	Command string // executable name; "boat" when empty
}

func (Boat) Name() string { return "boat" }

func (b Boat) bin() string {
	if b.Command == "" {
		return "boat"
	}
	return b.Command
}

var boatIDRE = regexp.MustCompile(`\bbx_[A-Za-z0-9]+\b`)

const boatRoot = "chimera-lane"

type boatWS struct {
	bin, id, home, base string
}

// boatEnv keeps the CLI from updating itself in the middle of a lane.
func boatEnv() []string { return append(baseEnv(), "BOAT_NO_UPDATE=1") }

func (b Boat) cli(ctx context.Context, timeout time.Duration, args ...string) ExecResult {
	return run(ctx, "", append([]string{b.bin()}, args...), boatEnv(), timeout)
}

// Provision creates a sandbox and seeds it with the tree at baseSHA: a tar
// archive is copied over and committed, so the remote tree hash equals the
// local one and diffs carry the same blob IDs.
func (b Boat) Provision(ctx context.Context, repoDir, baseSHA string) (Workspace, error) {
	created := b.cli(ctx, 10*time.Minute, "new", "--json")
	id := boatIDRE.FindString(string(created.Stdout))
	if created.ExitCode != 0 || created.Err != "" || id == "" {
		return nil, fmt.Errorf("boat new failed")
	}
	ws := &boatWS{bin: b.bin(), id: id, base: baseSHA}
	fail := func(what string) (Workspace, error) {
		ws.Teardown(context.WithoutCancel(ctx))
		return nil, fmt.Errorf("boat %s failed", what)
	}
	home := ws.sh(ctx, time.Minute, "mkdir -p "+boatRoot+"/tree "+boatRoot+"/out && pwd")
	if home.ExitCode != 0 || home.Err != "" {
		return fail("ssh")
	}
	lines := strings.Split(strings.TrimSpace(string(home.Stdout)), "\n")
	ws.home = strings.TrimSpace(lines[len(lines)-1])
	tmp, err := os.CreateTemp("", "chimera-base-*.tar")
	if err != nil {
		return fail("archive")
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if _, err := gitx.Run(ctx, repoDir, "archive", "--format=tar", "-o", tmp.Name(), baseSHA); err != nil {
		return fail("archive")
	}
	if r := b.cli(ctx, 10*time.Minute, "scp", tmp.Name(), id+":"+boatRoot+"/base.tar"); r.ExitCode != 0 || r.Err != "" {
		return fail("scp")
	}
	seed := "cd " + boatRoot + "/tree && tar -xf ../base.tar && rm ../base.tar && git init -q && git add -A && " +
		"git -c user.name=chimera -c user.email=chimera@example.com commit -q --allow-empty -m base"
	if r := ws.sh(ctx, 5*time.Minute, seed); r.ExitCode != 0 || r.Err != "" {
		return fail("seed")
	}
	return ws, nil
}

// sh runs one shell command line in the sandbox. It is passed as a single
// argument so that the remote shell, not the local one, interprets it.
func (w *boatWS) sh(ctx context.Context, timeout time.Duration, script string) ExecResult {
	return run(ctx, "", []string{w.bin, "ssh", w.id, script}, boatEnv(), timeout)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (w *boatWS) Dir() string    { return w.home + "/" + boatRoot + "/tree" }
func (w *boatWS) OutDir() string { return w.home + "/" + boatRoot + "/out" }

func (w *boatWS) Put(ctx context.Context, name string, data []byte) error {
	tmp, err := os.CreateTemp("", "chimera-put-*")
	if err != nil {
		return fmt.Errorf("cannot write %s", name)
	}
	defer os.Remove(tmp.Name())
	tmp.Write(data)
	tmp.Close()
	r := run(ctx, "", []string{w.bin, "scp", tmp.Name(), w.id + ":" + boatRoot + "/out/" + filepath.Base(name)}, boatEnv(), 5*time.Minute)
	if r.ExitCode != 0 || r.Err != "" {
		return fmt.Errorf("boat scp failed")
	}
	return nil
}

func (w *boatWS) Read(ctx context.Context, name string) ([]byte, error) {
	p := shellQuote(boatRoot + "/out/" + filepath.Base(name))
	if r := w.sh(ctx, time.Minute, "test -f "+p); r.ExitCode != 0 {
		return nil, fs.ErrNotExist
	}
	r := w.sh(ctx, 5*time.Minute, "cat "+p)
	if r.ExitCode != 0 || r.Err != "" {
		return nil, fmt.Errorf("boat ssh failed")
	}
	if r.StdoutTruncated {
		return nil, fmt.Errorf("%s exceeds the %d MiB transfer cap", name, maxOutput>>20)
	}
	return r.Stdout, nil
}

func (w *boatWS) Exec(ctx context.Context, argv, env []string, timeout time.Duration) ExecResult {
	var b strings.Builder
	b.WriteString("cd " + shellQuote(boatRoot+"/tree") + " && env")
	for _, kv := range env {
		b.WriteString(" " + shellQuote(kv))
	}
	for _, a := range argv {
		b.WriteString(" " + shellQuote(a))
	}
	return w.sh(ctx, timeout, b.String())
}

func (w *boatWS) Tree(ctx context.Context) (string, error) {
	r := w.sh(ctx, time.Minute, "cd "+boatRoot+"/tree && git rev-parse 'HEAD^{tree}'")
	out := strings.TrimSpace(string(r.Stdout))
	if r.ExitCode != 0 || len(out) < 40 {
		return "", fmt.Errorf("boat ssh failed")
	}
	return out[len(out)-40:], nil
}

func (w *boatWS) Diff(ctx context.Context) ([]byte, error) {
	var quoted []string
	for _, a := range diffArgs("HEAD") {
		quoted = append(quoted, shellQuote(a))
	}
	script := "cd " + boatRoot + "/tree && export GIT_INDEX_FILE=\"$PWD/../diff.index\" && git read-tree HEAD && git add -A && git " + strings.Join(quoted, " ")
	r := w.sh(ctx, 5*time.Minute, script)
	if r.ExitCode != 0 || r.Err != "" {
		return nil, fmt.Errorf("boat ssh failed")
	}
	if r.StdoutTruncated {
		return nil, fmt.Errorf("diff exceeds the %d MiB transfer cap", maxOutput>>20)
	}
	return r.Stdout, nil
}

func (w *boatWS) Teardown(ctx context.Context) error {
	r := run(ctx, "", []string{w.bin, "delete", w.id, "--yes"}, boatEnv(), 5*time.Minute)
	if r.ExitCode != 0 || r.Err != "" {
		return fmt.Errorf("boat delete failed; sandbox %s may still exist", w.id)
	}
	return nil
}
