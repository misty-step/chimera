package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/misty-step/chimera/pkg/gitx"
	"github.com/misty-step/chimera/pkg/secretscan"
)

// RuleUnreadable marks a file the scanner could not read. It always fails the
// lint: a scanner that cannot read a file refuses (fail closed).
const RuleUnreadable = "unreadable"

type lintResult struct {
	Schema   string               `json:"schema"`
	Check    string               `json:"check"`
	Files    int                  `json:"files"`
	Terms    int                  `json:"terms"`
	Findings []secretscan.Finding `json:"findings"`
}

// target is one file to scan: shown is the path printed, read loads its bytes.
type target struct {
	shown string
	read  func() ([]byte, error)
}

func runLintTenantLeak(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	deny, err := cfg.DenylistTerms()
	if err != nil {
		return &cliError{code: ExitError, object: "denylist file", msg: strings.TrimPrefix(err.Error(), "denylist file "), next: "nothing scanned"}
	}
	scanner := secretscan.New(append(cfg.TenantTerms(), deny...))

	var targets []target
	if len(c.args) == 0 {
		targets, err = trackedTargets(c)
	} else {
		targets, err = pathTargets(c)
	}
	if err != nil {
		return err
	}

	findings := []secretscan.Finding{}
	for _, t := range targets {
		if c.Err() != nil {
			return &cliError{code: ExitError, msg: "interrupted", next: "nothing reported"}
		}
		data, err := t.read()
		if err != nil {
			findings = append(findings, secretscan.Finding{Path: t.shown, Rule: RuleUnreadable})
			continue
		}
		findings = append(findings, scanner.Scan(t.shown, data)...)
	}
	secretscan.Sort(findings)

	if len(findings) > 0 {
		if !c.json {
			for _, f := range findings {
				fmt.Fprintln(c.inv.Stdout, f.String())
			}
		}
		return &cliError{
			code:     ExitError,
			object:   fmt.Sprintf("%d files", len(targets)),
			msg:      fmt.Sprintf("%d findings (rule %s)", len(findings), strings.Join(secretscan.Rules(findings), ", ")),
			next:     "remove the values or move them to config",
			findings: findings,
		}
	}
	if c.json {
		if err := c.emitJSON(lintResult{Schema: "chimera.lint/v1", Check: "tenant-leak", Files: len(targets), Terms: scanner.TermCount(), Findings: findings}); err != nil {
			return err
		}
	}
	c.info("lint tenant-leak: %s  %d files, %d terms, 0 findings", c.status("PASS"), len(targets), scanner.TermCount())
	return nil
}

func trackedTargets(c *ctx) ([]target, error) {
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return nil, &cliError{code: ExitError, object: "tracked files", msg: lower(err.Error()), next: "pass paths explicitly outside a git work tree"}
	}
	files, err := gitx.LsFiles(c, root)
	if err != nil {
		return nil, &cliError{code: ExitError, object: "tracked files", msg: lower(err.Error()), next: "nothing scanned"}
	}
	out := make([]target, 0, len(files))
	for _, f := range files {
		f := f
		abs := filepath.Join(root, filepath.FromSlash(f))
		out = append(out, target{shown: f, read: func() ([]byte, error) {
			data, err := readEntry(abs)
			if errors.Is(err, fs.ErrNotExist) {
				// Deleted in the work tree but still tracked: scan the index blob.
				return gitx.Run(c, root, "cat-file", "blob", ":"+f)
			}
			return data, err
		}})
	}
	return out, nil
}

func pathTargets(c *ctx) ([]target, error) {
	var out []target
	for _, arg := range c.args {
		abs := arg
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(c.inv.Dir, arg)
		}
		shown := filepath.ToSlash(filepath.Clean(arg))
		st, err := os.Lstat(abs)
		if err != nil {
			out = append(out, target{shown: shown, read: func() ([]byte, error) { return nil, err }})
			continue
		}
		if !st.IsDir() {
			p := abs
			out = append(out, target{shown: shown, read: func() ([]byte, error) { return readEntry(p) }})
			continue
		}
		walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			rel, _ := filepath.Rel(abs, p)
			name := filepath.ToSlash(filepath.Join(shown, rel))
			if err != nil {
				out = append(out, target{shown: name, read: func() ([]byte, error) { return nil, err }})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return fs.SkipDir
				}
				return nil
			}
			out = append(out, target{shown: name, read: func() ([]byte, error) { return readEntry(p) }})
			return nil
		})
		if walkErr != nil {
			return nil, &cliError{code: ExitError, object: shown, msg: "cannot walk directory", next: "nothing scanned"}
		}
	}
	return out, nil
}

// readEntry reads a regular file, or a symlink's target text (links are not followed).
func readEntry(p string) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		t, err := os.Readlink(p)
		return []byte(t), err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	return os.ReadFile(p)
}
