package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/objstore"
)

var (
	flagIntent     = flagSpec{Long: "intent", Arg: "id", Help: "Intent ID: folio:<sha256> or task:<sha256>"}
	flagCheckpoint = flagSpec{Long: "checkpoint", Arg: "id", Help: "checkpoint ID: ckpt_<ULID>"}
	flagRepo       = flagSpec{Long: "repo", Arg: "name", Help: "repository the Capsule is about"}
	flagBaseSHA    = flagSpec{Long: "base-sha", Arg: "sha", Help: "commit the work started from"}
	flagTag        = flagSpec{Long: "tag", Arg: "tag", Multi: true, Help: "tag to record (repeatable)"}
	flagOut        = flagSpec{Long: "out", Arg: "dir", Help: "write the verified members to this directory"}
)

func (c *ctx) packMeta() capsule.Meta {
	return capsule.Meta{
		Intent: c.flags["intent"], Checkpoint: c.flags["checkpoint"], Repo: c.flags["repo"],
		BaseSHA: c.flags["base-sha"], Tags: c.list("tag"),
	}
}

func (c *ctx) capsuleDir() (string, error) {
	dir := c.abs(c.args[0])
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", usageErr(c.args[0], "not a directory", "pass the directory holding the capsule members")
	}
	return dir, nil
}

func runCapsulePack(c *ctx) error {
	dir, err := c.capsuleDir()
	if err != nil {
		return err
	}
	if c.flags["intent"] == "" || c.flags["checkpoint"] == "" {
		return usageErr("", "--intent and --checkpoint are required", "nothing packed")
	}
	addr, err := capsule.Pack(dir, c.packMeta())
	if err != nil {
		return failed(c.args[0], err, "nothing packed")
	}
	fmt.Fprintln(c.inv.Stdout, addr)
	return nil
}

func (c *ctx) push(dir string) (capsule.PushResult, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return capsule.PushResult{}, err
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return capsule.PushResult{}, err
	}
	scanner, err := c.gate(cfg)
	if err != nil {
		return capsule.PushResult{}, err
	}
	res, err := capsule.Push(c, store, dir, scanner)
	var ge *capsule.GateError
	var ie *capsule.IntegrityError
	switch {
	case errors.As(err, &ge):
		if !c.json {
			for _, f := range ge.Findings {
				fmt.Fprintln(c.inv.Stdout, f.String())
			}
		}
		return res, &cliError{code: ExitError, msg: ge.Error(), next: "nothing uploaded", findings: ge.Findings}
	case errors.As(err, &ie):
		return res, &cliError{code: ExitError, object: "member " + ie.Member, msg: "readback hash mismatch", next: "integrity error; the capsule is not committed"}
	case errors.Is(err, capsule.ErrNotPacked):
		return res, usageErr(c.args[0], err.Error(), "nothing uploaded")
	case err != nil:
		return res, failed("", err, "upload unconfirmed")
	}
	return res, nil
}

func runCapsulePush(c *ctx) error {
	dir, err := c.capsuleDir()
	if err != nil {
		return err
	}
	res, err := c.push(dir)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.inv.Stdout, res.Address)
	c.info("capsule push: %s  %s  %d uploaded, %d already present; every object read back and verified",
		c.status("PASS"), short(string(res.Address)), res.Uploaded, res.Existing)
	return nil
}

// runCapsuleWrite is pack followed by push.
func runCapsuleWrite(c *ctx) error {
	dir, err := c.capsuleDir()
	if err != nil {
		return err
	}
	if c.flags["intent"] == "" {
		return usageErr("", "--intent is required", "nothing written")
	}
	meta := c.packMeta()
	if meta.Checkpoint == "" {
		if meta.Checkpoint, err = capsule.NewCheckpoint(time.Now()); err != nil {
			return failed("", err, "nothing written")
		}
	}
	if _, err := capsule.Pack(dir, meta); err != nil {
		return failed(c.args[0], err, "nothing written")
	}
	res, err := c.push(dir)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.inv.Stdout, res.Address)
	c.info("capsule write: %s  %s  %d uploaded, %d already present; every object read back and verified",
		c.status("PASS"), short(string(res.Address)), res.Uploaded, res.Existing)
	return nil
}

type capsuleJSON struct {
	Schema   string           `json:"schema"`
	Address  string           `json:"address"`
	Verified bool             `json:"verified"`
	Source   string           `json:"source"` // store | directory
	Out      string           `json:"out,omitempty"`
	Manifest capsule.Manifest `json:"manifest"`
}

func (c *ctx) fetch(arg string) (*capsule.Local, error) {
	addr, err := capsule.ParseAddress(arg)
	if err != nil {
		return nil, usageErr(arg, err.Error(), "nothing fetched")
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return nil, err
	}
	return fetchCapsule(c, store, addr)
}

func fetchCapsule(c *ctx, store objstore.Store, addr capsule.Address) (*capsule.Local, error) {
	l, err := capsule.Get(c, store, addr)
	var ie *capsule.IntegrityError
	switch {
	case errors.As(err, &ie):
		return nil, &cliError{code: ExitError, object: short(string(addr)), msg: "member " + ie.Member + ": hash mismatch", next: "integrity error; nothing written"}
	case errors.Is(err, capsule.ErrNotInStore):
		return nil, &cliError{code: ExitError, object: short(string(addr)), msg: "capsule not in store", next: "check the address and store.endpoint"}
	case err != nil:
		return nil, failed(short(string(addr)), err, "nothing written")
	}
	return l, nil
}

func (c *ctx) printCapsule(l *capsule.Local, source, out string) error {
	if c.json {
		return c.emitJSON(capsuleJSON{Schema: "chimera.capsule/v1", Address: string(l.Address), Verified: true, Source: source, Out: out, Manifest: l.Manifest})
	}
	m := l.Manifest
	rows := [][]string{
		{"CAPSULE", short(string(l.Address))},
		{"INTENT", short(m.Intent)},
		{"CHECKPOINT", m.Checkpoint},
		{"REPO", dash(m.Repo)},
		{"BASE", dash(abbrev(m.BaseSHA))},
		{"LANE", laneLine(m.Lane)},
		{"STARTED", dash(m.StartedAt)},
		{"ENDED", dash(m.EndedAt)},
		{"TAGS", dash(strings.Join(m.Tags, " "))},
	}
	fmt.Fprint(c.inv.Stdout, grid(rows))
	members := [][]string{{"MEMBER", "SIZE", "SHA256"}}
	for _, mem := range m.Members {
		members = append(members, []string{mem.Path, strconv.FormatInt(mem.Size, 10), abbrev(mem.SHA256)})
	}
	fmt.Fprint(c.inv.Stdout, "\n"+grid(members))
	return nil
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func laneLine(l capsule.LaneConfig) string {
	var parts []string
	add := func(label, v string) {
		if v != "" {
			parts = append(parts, strings.TrimSpace(label+" "+v))
		}
	}
	add("", l.Runner)
	add("", l.Model)
	add("", l.Harness)
	add("skill", l.Skill)
	add("effort", l.Effort)
	add("context", l.ContextPolicy)
	return dash(strings.Join(parts, " · "))
}

func runCapsuleGet(c *ctx) error {
	l, err := c.fetch(c.args[0])
	if err != nil {
		return err
	}
	out := c.abs(c.flags["out"])
	if out != "" {
		if err := l.WriteDir(out); err != nil {
			return failed(c.flags["out"], err, "output directory may be incomplete")
		}
	}
	if err := c.printCapsule(l, "store", c.flags["out"]); err != nil {
		return err
	}
	c.info("capsule %s: %s  %s  %d members verified against capsule.json", c.cmd.Path[1], c.status("PASS"), short(string(l.Address)), len(l.Manifest.Members))
	return nil
}

// runCapsuleVerify checks a Capsule without writing anything: a directory is
// checked against its own capsule.json; an address is fetched and every
// member hash compared.
func runCapsuleVerify(c *ctx) error {
	if st, err := os.Stat(c.abs(c.args[0])); err == nil && st.IsDir() {
		l, err := capsule.Load(c.abs(c.args[0]))
		if errors.Is(err, capsule.ErrNotPacked) {
			return usageErr(c.args[0], err.Error(), "nothing verified")
		}
		if err != nil {
			return failed(c.args[0], err, "verification failed")
		}
		if err := c.printCapsule(l, "directory", ""); err != nil {
			return err
		}
		c.info("capsule verify: %s  %s  %d members match capsule.json", c.status("PASS"), short(string(l.Address)), len(l.Manifest.Members))
		return nil
	}
	l, err := c.fetch(c.args[0])
	if err != nil {
		return err
	}
	if err := c.printCapsule(l, "store", ""); err != nil {
		return err
	}
	c.info("capsule verify: %s  %s  %d members verified against capsule.json", c.status("PASS"), short(string(l.Address)), len(l.Manifest.Members))
	return nil
}

func runCapsuleAttach(c *ctx) error {
	addr, err := capsule.ParseAddress(c.args[1])
	if err != nil {
		return usageErr(c.args[1], err.Error(), "nothing attached")
	}
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return failed("repository", err, "run inside a git work tree")
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	l, err := fetchCapsule(c, store, addr)
	if err != nil {
		var ce *cliError
		if errors.As(err, &ce) {
			ce.next = "refusing to attach; history unchanged"
		}
		return err
	}
	intent := c.flags["intent"]
	if intent == "" {
		intent = l.Manifest.Intent
	}
	if intent != l.Manifest.Intent {
		return &cliError{code: ExitError, object: short(string(addr)), msg: "capsule records a different intent (" + short(l.Manifest.Intent) + ")", next: "refusing to attach; history unchanged"}
	}
	newSHA, err := attachTrailers(c, root, c.args[0], intent, string(addr))
	if err != nil {
		return failed(c.args[0], err, "history unchanged")
	}
	fmt.Fprintln(c.inv.Stdout, newSHA)
	c.info("capsule attach: %s  commit %s now carries %s and %s", c.status("PASS"), abbrev(newSHA), short(intent), short(string(addr)))
	return nil
}

// attachTrailers rewrites commit (and the linear chain above it up to HEAD)
// so that it carries both trailers. It refuses a commit that is already on a
// remote-tracking branch or a chain that contains merges. Trees are reused,
// so the index and work tree are untouched.
func attachTrailers(c *ctx, root, rev, intent, addr string) (string, error) {
	target, err := gitx.RevParse(c, root, rev+"^{commit}")
	if err != nil {
		return "", err
	}
	head, err := gitx.RevParse(c, root, "HEAD^{commit}")
	if err != nil {
		return "", err
	}
	if _, err := gitx.Run(c, root, "merge-base", "--is-ancestor", target, head); err != nil {
		return "", fmt.Errorf("commit is not an ancestor of HEAD")
	}
	remote, err := gitx.Run(c, root, "for-each-ref", "--contains", target, "--format=%(refname)", "refs/remotes")
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(remote)) > 0 {
		return "", fmt.Errorf("commit is already pushed; chimera does not rewrite published history")
	}
	out, err := gitx.Run(c, root, "rev-list", "--reverse", "--ancestry-path", target+".."+head)
	if err != nil {
		return "", err
	}
	chain := append([]string{target}, strings.Fields(string(out))...)
	prevOld, prevNew := "", ""
	for i, sha := range chain {
		raw, err := gitx.Run(c, root, "cat-file", "commit", sha)
		if err != nil {
			return "", err
		}
		header, msg, _ := strings.Cut(string(raw), "\n\n")
		var kept []string
		parents := 0
		skipping := false
		for _, line := range strings.Split(header, "\n") {
			switch {
			case strings.HasPrefix(line, " ") && skipping:
				continue // continuation of a dropped signature
			case strings.HasPrefix(line, "gpgsig"):
				skipping = true // a rewritten commit cannot keep its signature
				continue
			case strings.HasPrefix(line, "parent "):
				parents++
				if i > 0 {
					if strings.TrimPrefix(line, "parent ") != prevOld {
						return "", fmt.Errorf("history above the commit is not linear")
					}
					line = "parent " + prevNew
				}
			}
			skipping = false
			kept = append(kept, line)
		}
		if parents > 1 {
			return "", fmt.Errorf("merge commits cannot be rewritten")
		}
		if i == 0 {
			if msg, err = gitx.WithTrailers(c, root, msg, intent, addr); err != nil {
				return "", err
			}
		}
		obj, err := gitx.RunInput(c, root, []byte(strings.Join(kept, "\n")+"\n\n"+msg), nil, "hash-object", "-t", "commit", "-w", "--stdin")
		if err != nil {
			return "", err
		}
		prevOld, prevNew = sha, strings.TrimSpace(string(obj))
	}
	newTarget := prevNew
	if len(chain) > 1 {
		// Recover the rewritten target: it is the root of the new chain.
		out, err := gitx.Run(c, root, "rev-list", "--reverse", "-n", strconv.Itoa(len(chain)), prevNew)
		if err != nil {
			return "", err
		}
		newTarget = strings.Fields(string(out))[0]
	}
	if _, err := gitx.Run(c, root, "update-ref", "-m", "chimera capsule attach", "HEAD", prevNew, head); err != nil {
		return "", err
	}
	return newTarget, nil
}

type whyProof struct {
	Intent     string             `json:"intent"`
	Capsule    string             `json:"capsule"`
	Checkpoint string             `json:"checkpoint"`
	Lane       capsule.LaneConfig `json:"lane"`
	Covers     bool               `json:"covers"`
	Verdicts   []capsule.Verdict  `json:"verdicts"`
}

type whyAnchor struct {
	Commit string `json:"commit"`
	Ref    string `json:"ref"`   // HEAD or HEAD-N: commits between the anchor and HEAD
	Drift  int    `json:"drift"` // commits that touched the file since the anchor
	State  string `json:"state"` // fresh | drift
}

type whyResult struct {
	Schema  string     `json:"schema"`
	File    string     `json:"file"`
	Line    int        `json:"line"`
	Commit  string     `json:"commit"`
	Subject string     `json:"subject"`
	Anchor  whyAnchor  `json:"anchor"`
	Proofs  []whyProof `json:"proofs"`
}

func runWhy(c *ctx) error {
	file, line := c.args[0], 0
	if i := strings.LastIndexByte(file, ':'); i > 0 {
		if n, err := strconv.Atoi(file[i+1:]); err == nil {
			if n < 1 {
				return usageErr(c.args[0], "line numbers start at 1", "nothing resolved")
			}
			file, line = file[:i], n
		}
	}
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return failed("repository", err, "run inside a git work tree")
	}
	// Resolve symlinks on both sides so a path under a linked temp dir matches.
	absFile, _ := filepath.EvalSymlinks(c.abs(file))
	if absFile == "" {
		absFile = c.abs(file)
	}
	realRoot, _ := filepath.EvalSymlinks(root)
	rel, err := filepath.Rel(realRoot, absFile)
	if err != nil || strings.HasPrefix(rel, "..") {
		return usageErr(file, "outside the repository", "nothing resolved")
	}
	rel = filepath.ToSlash(rel)
	var commit string
	if line > 0 {
		commit, err = gitx.BlameLine(c, root, rel, line)
	} else {
		commit, err = gitx.LastCommit(c, root, rel)
	}
	if err != nil {
		return failed(c.args[0], err, "nothing resolved")
	}
	tr, err := gitx.ReadTrailers(c, root, commit)
	if err != nil {
		return failed(c.args[0], err, "nothing resolved")
	}
	if tr.Empty() {
		return &cliError{code: ExitError, object: c.args[0], msg: "commit " + abbrev(commit) + " carries no Chimera-Capsule trailer", next: "missing proof"}
	}
	subject, _ := gitx.Run(c, root, "log", "-1", "--format=%s", commit)
	dist, err := gitx.CountSince(c, root, commit, "")
	if err != nil {
		return failed(c.args[0], err, "nothing resolved")
	}
	drift, err := gitx.CountSince(c, root, commit, rel)
	if err != nil {
		return failed(c.args[0], err, "nothing resolved")
	}
	res := whyResult{Schema: "chimera.why/v1", File: rel, Line: line, Commit: commit, Subject: strings.TrimSpace(string(subject)),
		Anchor: whyAnchor{Commit: commit, Ref: "HEAD", Drift: drift, State: "fresh"}}
	if dist > 0 {
		res.Anchor.Ref = fmt.Sprintf("HEAD-%d", dist)
	}
	if drift > 0 {
		res.Anchor.State = "drift"
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	for i, capAddr := range tr.Capsules {
		addr, err := capsule.ParseAddress(capAddr)
		if err != nil {
			return &cliError{code: ExitError, object: c.args[0], msg: "commit " + abbrev(commit) + " carries a malformed Chimera-Capsule trailer", next: "missing proof"}
		}
		l, err := fetchCapsule(c, store, addr)
		if err != nil {
			return err
		}
		vs, err := l.Verdicts()
		if err != nil {
			return failed(short(capAddr), err, "capsule unreadable")
		}
		p := whyProof{Intent: l.Manifest.Intent, Capsule: capAddr, Checkpoint: l.Manifest.Checkpoint, Lane: l.Manifest.Lane, Verdicts: []capsule.Verdict{}}
		if i < len(tr.Intents) {
			p.Intent = tr.Intents[i]
		}
		diff, hasDiff := l.Members[capsule.MemberDiff]
		for _, t := range capsule.TouchedPaths(diff) {
			p.Covers = p.Covers || t.Path == rel
		}
		for _, v := range vs {
			// Without a diff the Capsule cannot be narrowed to files, so every
			// verdict is shown; with one, verdicts cover the files it touches.
			if p.Covers || !hasDiff || strings.Contains(v.Evidence, rel) || strings.Contains(v.Criterion, rel) {
				p.Verdicts = append(p.Verdicts, v)
			}
		}
		res.Proofs = append(res.Proofs, p)
	}
	if c.json {
		return c.emitJSON(res)
	}
	loc := rel
	if line > 0 {
		loc = fmt.Sprintf("%s:%d", rel, line)
	}
	anchor := res.Anchor.Ref + "  fresh"
	if drift > 0 {
		anchor = fmt.Sprintf("%s  drift=%d", res.Anchor.Ref, drift)
	}
	rows := [][]string{{"FILE", loc}, {"COMMIT", abbrev(commit) + "  " + res.Subject}, {"ANCHOR", anchor}}
	for _, p := range res.Proofs {
		rows = append(rows, []string{"INTENT", short(p.Intent)}, []string{"CAPSULE", short(p.Capsule)},
			[]string{"CHECKPOINT", p.Checkpoint}, []string{"LANE", laneLine(p.Lane)})
	}
	fmt.Fprint(c.inv.Stdout, grid(rows))
	for _, p := range res.Proofs {
		vr := [][]string{{"ID", "STATE", "CRITERION", "EVIDENCE"}}
		for _, v := range p.Verdicts {
			vr = append(vr, []string{v.ID, passWord(v.Pass), v.Criterion, dash(oneLine(v.Evidence, 60))})
		}
		if len(vr) == 1 {
			fmt.Fprintf(c.inv.Stdout, "\nVERDICTS  none cover %s\n", rel)
			continue
		}
		fmt.Fprint(c.inv.Stdout, "\n"+grid(vr))
	}
	return nil
}

// oneLine collapses whitespace and truncates to max runes.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
