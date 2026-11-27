package cli

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"chimera/pkg/gitx"
)

// LockPath is the Ring-0 lock, relative to the repository root.
const LockPath = ".chimera/ring0.lock"

const lockHeader = "# chimera ring0.lock v1"

type ring0Lock struct {
	globs  []string
	hashes map[string]string // path → sha256 hex
}

type ring0Change struct {
	Path  string `json:"path"`
	State string `json:"state"` // modified | added | missing | glob-added | glob-removed
}

type ring0Result struct {
	Schema  string        `json:"schema"`
	Lock    string        `json:"lock"`
	Files   int           `json:"files"`
	Changes []ring0Change `json:"changes"`
}

func normGlobs(gs []string) []string {
	set := map[string]bool{}
	for _, g := range gs {
		if g = strings.TrimSpace(g); g != "" {
			set[filepath.ToSlash(g)] = true
		}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// ring0Files hashes every tracked or untracked, non-ignored file under root
// matching any glob, excluding the lock itself.
func ring0Files(c *ctx, root string, globs []string) (map[string]string, error) {
	files, err := gitx.LsFilesWithUntracked(c, root)
	if err != nil {
		return nil, &cliError{code: ExitError, object: "ring0 files", msg: lower(err.Error()), next: "nothing verified"}
	}
	out := map[string]string{}
	for _, f := range files {
		if f == LockPath || !matchAny(globs, f) {
			continue
		}
		data, err := readEntry(filepath.Join(root, filepath.FromSlash(f)))
		if errors.Is(err, fs.ErrNotExist) {
			continue // tracked but deleted: absent from the tree
		}
		if err != nil {
			return nil, &cliError{code: ExitError, object: f, msg: "unreadable", next: "refusing to decide"}
		}
		sum := sha256.Sum256(data)
		out[f] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

func matchAny(globs []string, f string) bool {
	for _, g := range globs {
		if matchGlob(g, f) {
			return true
		}
	}
	return false
}

func renderLock(l ring0Lock) []byte {
	var b bytes.Buffer
	b.WriteString(lockHeader + "\n")
	for _, g := range l.globs {
		fmt.Fprintf(&b, "# glob %s\n", g)
	}
	paths := make([]string, 0, len(l.hashes))
	for p := range l.hashes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintf(&b, "%s  %s\n", l.hashes[p], p)
	}
	return b.Bytes()
}

func parseLock(data []byte) (ring0Lock, error) {
	l := ring0Lock{hashes: map[string]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	first := true
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if first {
			if line != lockHeader {
				return l, fmt.Errorf("line 1: not a ring0 lock v1")
			}
			first = false
			continue
		}
		if g, ok := strings.CutPrefix(line, "# glob "); ok {
			l.globs = append(l.globs, g)
			continue
		}
		sum, p, ok := strings.Cut(line, "  ")
		if b, err := hex.DecodeString(sum); !ok || err != nil || len(b) != sha256.Size || p == "" {
			return l, fmt.Errorf("line %d: malformed entry", n)
		}
		l.hashes[p] = sum
	}
	if first {
		return l, fmt.Errorf("empty lock")
	}
	l.globs = normGlobs(l.globs)
	return l, sc.Err()
}

func ring0Root(c *ctx) (string, error) {
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return "", &cliError{code: ExitError, object: "repository", msg: lower(err.Error()), next: "run inside a git work tree"}
	}
	return root, nil
}

func runRing0Lock(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	globs := normGlobs(cfg.Ring0.Paths)
	if len(globs) == 0 {
		return usageErr("ring0.paths", "not configured", "set ring0.paths in chimera.yaml or CHIMERA_RING0_PATHS")
	}
	root, err := ring0Root(c)
	if err != nil {
		return err
	}
	hashes, err := ring0Files(c, root, globs)
	if err != nil {
		return err
	}
	lockAbs := filepath.Join(root, filepath.FromSlash(LockPath))
	if err := os.MkdirAll(filepath.Dir(lockAbs), 0o755); err != nil {
		return &cliError{code: ExitError, object: LockPath, msg: "cannot create directory", next: "lock not written"}
	}
	tmp := lockAbs + ".tmp"
	if err := os.WriteFile(tmp, renderLock(ring0Lock{globs: globs, hashes: hashes}), 0o644); err != nil {
		return &cliError{code: ExitError, object: LockPath, msg: "cannot write", next: "lock not written"}
	}
	if err := os.Rename(tmp, lockAbs); err != nil {
		os.Remove(tmp)
		return &cliError{code: ExitError, object: LockPath, msg: "cannot write", next: "lock not written"}
	}
	c.info("ring0 lock: wrote %s  %d files, %d globs; commit it with owner approval", LockPath, len(hashes), len(globs))
	return nil
}

func runRing0Verify(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	root, err := ring0Root(c)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(LockPath)))
	if errors.Is(err, fs.ErrNotExist) {
		return &cliError{code: ExitError, object: LockPath, msg: "lock missing", next: "run 'chimera ring0 lock' with owner approval"}
	}
	if err != nil {
		return &cliError{code: ExitError, object: LockPath, msg: "unreadable", next: "refusing to decide"}
	}
	lock, err := parseLock(data)
	if err != nil {
		return &cliError{code: ExitError, object: LockPath, msg: err.Error(), next: "refusing to decide"}
	}
	cfgGlobs := normGlobs(cfg.Ring0.Paths)
	if len(lock.globs) == 0 && len(cfgGlobs) == 0 {
		return usageErr("ring0.paths", "not configured and the lock names no globs", "set ring0.paths")
	}

	changes := []ring0Change{}
	union := lock.globs
	if len(cfgGlobs) > 0 {
		union = normGlobs(append(append([]string{}, lock.globs...), cfgGlobs...))
		changes = append(changes, globDiff(lock.globs, cfgGlobs)...)
	}
	current, err := ring0Files(c, root, union)
	if err != nil {
		return err
	}
	for p, sum := range current {
		old, ok := lock.hashes[p]
		switch {
		case !ok:
			changes = append(changes, ring0Change{Path: p, State: "added"})
		case old != sum:
			changes = append(changes, ring0Change{Path: p, State: "modified"})
		}
	}
	for p := range lock.hashes {
		if _, ok := current[p]; !ok {
			changes = append(changes, ring0Change{Path: p, State: "missing"})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].State < changes[j].State
	})

	if len(changes) > 0 {
		if !c.json {
			rows := [][2]string{{"STATE", "PATH"}}
			for _, ch := range changes {
				rows = append(rows, [2]string{ch.State, ch.Path})
			}
			fmt.Fprint(c.inv.Stdout, table("", rows))
		}
		return &cliError{
			code: ExitError, object: LockPath,
			msg:      fmt.Sprintf("%d changes since lock", len(changes)),
			next:     "ring-0 changes land only with owner approval",
			findings: changes,
		}
	}
	if c.json {
		if err := c.emitJSON(ring0Result{Schema: "chimera.ring0/v1", Lock: LockPath, Files: len(current), Changes: changes}); err != nil {
			return err
		}
	}
	c.info("ring0 verify: %s  %d files match %s", c.status("PASS"), len(current), LockPath)
	return nil
}

func globDiff(locked, configured []string) []ring0Change {
	in := func(gs []string, g string) bool {
		for _, x := range gs {
			if x == g {
				return true
			}
		}
		return false
	}
	var out []ring0Change
	for _, g := range configured {
		if !in(locked, g) {
			out = append(out, ring0Change{Path: g, State: "glob-added"})
		}
	}
	for _, g := range locked {
		if !in(configured, g) {
			out = append(out, ring0Change{Path: g, State: "glob-removed"})
		}
	}
	return out
}
