// Package gitx invokes the git binary. Chimera uses no Git libraries.
package gitx

import (
	"bytes"
	"context"
	"fmt"
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
