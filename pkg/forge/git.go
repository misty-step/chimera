package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"chimera/pkg/gitx"
)

// Git is a forge that is a Git repository on this machine, bare or not. It
// is the development adapter and the one the CLI can drive end to end
// without a hosted forge: refs are read and moved with the git binary, and
// Push is `git update-ref <ref> <new> <old>`, a true compare-and-swap.
//
// A bare repository has no place to show a check or deliver a message, so
// Report and Notify append one JSON line each to <git-dir>/chimera/forge.jsonl.
// That file is neither a ref nor a tracked file: nothing is written into Git.
type Git struct {
	Dir string           // the repository (work tree or bare)
	Log string           // JSONL file for reports and notifications; "" means <git-dir>/chimera/forge.jsonl
	Now func() time.Time // nil means time.Now
}

// GitEvent is one line of the Git forge's log.
type GitEvent struct {
	Kind   string  `json:"kind"` // "report" | "notify"
	At     string  `json:"at"`
	SHA    SHA     `json:"sha,omitempty"`
	Check  *Check  `json:"check,omitempty"`
	Change *Change `json:"change,omitempty"`
	Msg    string  `json:"msg,omitempty"`
}

// gitLogMu serializes appends from this process; O_APPEND keeps lines from
// other processes whole.
var gitLogMu sync.Mutex

// refs lists every ref under prefix with its object name.
func (g *Git) refs(ctx context.Context, prefix string) (map[string]SHA, error) {
	out, err := gitx.Run(ctx, g.Dir, "for-each-ref", "--format=%(refname)%00%(objectname)", prefix)
	if err != nil {
		return nil, err
	}
	refs := map[string]SHA{}
	for _, line := range strings.Split(string(out), "\n") {
		name, sha, ok := strings.Cut(line, "\x00")
		if ok && name != "" {
			refs[name] = SHA(sha)
		}
	}
	return refs, nil
}

func (g *Git) current(ctx context.Context, ref string) (SHA, error) {
	refs, err := g.refs(ctx, ref)
	if err != nil {
		return Zero, err
	}
	return refs[ref], nil // for-each-ref also lists refs below ref; only the exact name counts
}

// Head implements Forge.
func (g *Git) Head(ctx context.Context, ref string) (SHA, error) {
	sha, err := g.current(ctx, RefName(ref))
	if err != nil {
		return Zero, err
	}
	if sha.IsZero() {
		return Zero, ErrNotFound
	}
	return sha, nil
}

// lockRetries bounds how long Push waits out another writer's ref lock:
// each try lets git itself wait lockWait for the lock.
const lockRetries = 10

// lockWait pins git's own lock timeouts, so the wait does not depend on
// ambient config.
var lockWait = []string{"-c", "core.filesRefLockTimeout=100", "-c", "core.packedRefsTimeout=100"}

// Push implements Forge with git update-ref, which takes the ref's lock,
// compares it with old, and moves it only on a match: create with old Zero,
// delete with new Zero. A refusal is ErrStale only when the ref really is
// somewhere other than old. A lock another writer holds is waited out
// briefly; a lock that never goes away (a crashed writer's leftover) is
// reported as the error it is, never as "stale", so a caller cannot mistake
// an unmoved ref for a moved one.
func (g *Git) Push(ctx context.Context, ref string, old, new SHA) error {
	ref = RefName(ref)
	if old.IsZero() && new.IsZero() {
		return fmt.Errorf("push %s: nothing to do", ref)
	}
	width := len(new)
	if new.IsZero() {
		width = len(old)
	}
	if old.IsZero() {
		old = SHA(strings.Repeat("0", width))
	}
	var err error
	for attempt := 0; ; attempt++ {
		if new.IsZero() {
			_, err = gitx.Run(ctx, g.Dir, append(append([]string{}, lockWait...), "update-ref", "-d", ref, string(old))...)
		} else {
			_, err = gitx.Run(ctx, g.Dir, append(append([]string{}, lockWait...), "update-ref", ref, string(new), string(old))...)
		}
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		cur, rerr := g.current(ctx, ref)
		if rerr == nil && !Same(cur, old) {
			return ErrStale
		}
		if rerr != nil || attempt >= lockRetries || !strings.Contains(err.Error(), ".lock") {
			break
		}
	}
	return fmt.Errorf("push %s: %s", ref, strings.TrimPrefix(err.Error(), "git -c: "))
}

// Queue implements Forge.
func (g *Git) Queue(ctx context.Context, target string) ([]Change, error) {
	refs, err := g.refs(ctx, strings.TrimSuffix(QueueRefPrefix(target), "/"))
	if err != nil {
		return nil, err
	}
	return QueueFromRefs(target, refs), nil
}

// Report implements Forge by appending to the forge log.
func (g *Git) Report(ctx context.Context, sha SHA, check Check) error {
	return g.append(ctx, GitEvent{Kind: "report", SHA: sha, Check: &check})
}

// Notify implements Forge by appending to the forge log.
func (g *Git) Notify(ctx context.Context, c Change, msg string) error {
	return g.append(ctx, GitEvent{Kind: "notify", Change: &c, Msg: msg})
}

func (g *Git) logPath(ctx context.Context) (string, error) {
	if g.Log != "" {
		return g.Log, nil
	}
	out, err := gitx.Run(ctx, g.Dir, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}
	return filepath.Join(strings.TrimSpace(string(out)), "chimera", "forge.jsonl"), nil
}

func (g *Git) append(ctx context.Context, e GitEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := g.logPath(ctx)
	if err != nil {
		return err
	}
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	e.At = now().UTC().Format(time.RFC3339)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return err
	}
	gitLogMu.Lock()
	defer gitLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("forge log: cannot create directory")
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("forge log: cannot open")
	}
	_, werr := f.Write(buf.Bytes())
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("forge log: write failed")
	}
	return nil
}

// Events reads the forge log back, oldest first.
func (g *Git) Events(ctx context.Context) ([]GitEvent, error) {
	p, err := g.logPath(ctx)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("forge log: unreadable")
	}
	var events []GitEvent
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e GitEvent
		if json.Unmarshal(line, &e) != nil {
			return nil, fmt.Errorf("forge log: malformed line")
		}
		events = append(events, e)
	}
	return events, nil
}
