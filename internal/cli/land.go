package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/land"
)

var (
	flagTarget = flagSpec{Long: "target", Arg: "ref", Help: "ref changes land on (default: land.target)"}
	flagSquash = flagSpec{Long: "squash", Help: "land each change as one commit carrying the trailer union"}
	flagOnce   = flagSpec{Long: "once", Help: "process at most one queued change"}
)

// maxStatusOutcomes bounds the outcomes a human sees; --json carries all.
const maxStatusOutcomes = 20

var fullHashRE = regexp.MustCompile(`\b(sha256|folio|task):([0-9a-f]{12})[0-9a-f]{52}\b`)

// humanHashes abbreviates content addresses inside prose to 12 hex
// characters (DESIGN.md §1.2); JSON keeps them whole.
func humanHashes(s string) string { return fullHashRE.ReplaceAllString(s, "$1:$2") }

// landTarget resolves the ref changes land on: --target, then land.target.
func (c *ctx) landTarget(cfg *config.Config) (string, error) {
	target := c.flags["target"]
	if target == "" {
		target = cfg.Land.Target
	}
	if target = forge.Branch(strings.TrimSpace(target)); target == "" {
		return "", usageErr("--target", "not given and land.target is not configured", "nothing was attempted")
	}
	return target, nil
}

// landRepo names the repository whose landing state (epochs, push intents,
// outcomes) this lander shares with every other lander of the same forge
// repository: --repo, then forge.repo, then the single tenant.repos entry.
// It is never guessed from a directory name: two clones of one repository
// must fence each other.
func (c *ctx) landRepo(cfg *config.Config) (string, error) {
	if r := strings.TrimSpace(c.flags["repo"]); r != "" {
		return r, nil
	}
	if r := strings.Trim(cfg.Forge.Repo, "/"); r != "" {
		return r, nil
	}
	if len(cfg.Tenant.Repos) == 1 && cfg.Tenant.Repos[0] != "" {
		return cfg.Tenant.Repos[0], nil
	}
	return "", usageErr("--repo", "repository name not configured", "set forge.repo or pass --repo")
}

type enqueueResult struct {
	Schema   string       `json:"schema"`
	Change   forge.Change `json:"change"`
	Position int          `json:"position"`
	Created  bool         `json:"created"`
}

func runLandEnqueue(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	root, _ := gitx.Toplevel(c, c.inv.Dir)
	f, err := c.openForge(cfg, root)
	if err != nil {
		return err
	}
	target, err := c.landTarget(cfg)
	if err != nil {
		return err
	}
	branch := forge.Branch(c.args[0])
	change, pos, created, err := land.Enqueue(c, f, target, branch)
	if errors.Is(err, forge.ErrNotFound) {
		return &cliError{code: ExitError, object: branch, msg: "branch not found on the forge", next: "nothing queued; push the branch first"}
	}
	if err != nil {
		return remoteErr(branch, err, "nothing queued")
	}
	if c.json {
		if err := c.emitJSON(enqueueResult{Schema: "chimera.land.enqueue/v1", Change: change, Position: pos, Created: created}); err != nil {
			return err
		}
	} else {
		fmt.Fprint(c.inv.Stdout, grid([][]string{
			{"POS", "SEQ", "BRANCH", "HEAD", "TARGET", "STATE"},
			{strconv.Itoa(pos), strconv.Itoa(change.Seq), change.Branch, change.Head.Short(), change.Target, land.Pending},
		}))
	}
	if created {
		c.info("land enqueue: %s pinned at %s, position %d for %s; 'chimera land run' lands it", change.Branch, change.Head.Short(), pos, target)
	} else {
		c.info("land enqueue: %s at %s is already queued, position %d for %s", change.Branch, change.Head.Short(), pos, target)
	}
	return nil
}

func queueRows(queue []forge.Change) [][]string {
	rows := [][]string{{"POS", "SEQ", "BRANCH", "HEAD", "STATE"}}
	for i, q := range queue {
		rows = append(rows, []string{strconv.Itoa(i + 1), strconv.Itoa(q.Seq), q.Branch, q.Head.Short(), land.Pending})
	}
	return rows
}

func outcomeRows(outcomes []land.Outcome) [][]string {
	rows := [][]string{{"STATE", "BRANCH", "HEAD", "LANDED", "EPOCH", "AT", "DETAIL"}}
	for _, o := range outcomes {
		detail := o.Reason
		if o.State == land.Landed && o.Capsule != "" {
			detail = strings.TrimSpace(short(o.Capsule) + "  " + o.Reason)
		}
		rows = append(rows, []string{o.State, o.Change.Branch, o.Change.Head.Short(), dash(o.Landed.Short()), strconv.Itoa(o.Epoch), o.At, dash(oneLine(humanHashes(detail), 120))})
	}
	return rows
}

func runLandStatus(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	root, _ := gitx.Toplevel(c, c.inv.Dir)
	f, err := c.openForge(cfg, root)
	if err != nil {
		return err
	}
	target, err := c.landTarget(cfg)
	if err != nil {
		return err
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	repo, err := c.landRepo(cfg)
	if err != nil {
		return err
	}
	st, err := land.Status(c, f, store, repo, target)
	if err != nil {
		return remoteErr("", err, "status unknown")
	}
	if len(c.args) == 1 {
		return c.landBranchStatus(st, forge.Branch(c.args[0]))
	}
	if c.json {
		return c.emitJSON(st)
	}
	epoch := []string{"EPOCH", strconv.Itoa(st.Epoch), dash(st.Holder), dash(st.AcquiredAt)}
	fmt.Fprint(c.inv.Stdout, grid([][]string{{"REPO", st.Repo}, {"TARGET", st.Target, dash(st.Head.Short())}, epoch}))
	fmt.Fprint(c.inv.Stdout, "\n"+grid(queueRows(st.Queue)))
	shown := st.Outcomes
	if len(shown) > maxStatusOutcomes {
		shown = shown[:maxStatusOutcomes]
	}
	fmt.Fprint(c.inv.Stdout, "\n"+grid(outcomeRows(shown)))
	c.info("land status: %d queued, %d outcomes recorded (%d shown)", len(st.Queue), len(st.Outcomes), len(shown))
	return nil
}

// landBranchStatus answers for one branch: 0 once it LANDED, 1 if it was
// EVICTED or is unknown, 3 while it is PENDING in the queue.
func (c *ctx) landBranchStatus(st land.StatusReport, branch string) error {
	for i, q := range st.Queue {
		if q.Branch != branch {
			continue
		}
		if !c.json {
			fmt.Fprint(c.inv.Stdout, grid([][]string{queueRows(nil)[0], queueRows(st.Queue)[i+1]}))
		}
		return &cliError{code: ExitPending, object: branch, msg: fmt.Sprintf("%s at position %d of %d for %s", strings.ToLower(land.Pending), i+1, len(st.Queue), st.Target),
			next: "run 'chimera land run', or retry later", findings: []forge.Change{q}}
	}
	for _, o := range st.Outcomes { // newest first
		if o.Change.Branch != branch {
			continue
		}
		one := st
		one.Queue, one.Outcomes = []forge.Change{}, []land.Outcome{o}
		if o.State != land.Landed {
			if !c.json {
				fmt.Fprint(c.inv.Stdout, grid(outcomeRows(one.Outcomes)))
			}
			return &cliError{code: ExitError, object: branch, msg: strings.ToLower(o.State) + ": " + oneLine(humanHashes(o.Reason), 300), next: "fix the branch and enqueue it again", findings: one.Outcomes}
		}
		if c.json {
			return c.emitJSON(one)
		}
		fmt.Fprint(c.inv.Stdout, grid(outcomeRows(one.Outcomes)))
		return nil
	}
	return &cliError{code: ExitError, object: branch, msg: "not queued and no outcome recorded for " + st.Target, next: "run 'chimera land enqueue " + branch + "'"}
}

type landRunResult struct {
	Schema  string        `json:"schema"`
	Repo    string        `json:"repo"`
	Target  string        `json:"target"`
	Epoch   int           `json:"epoch"`
	Results []land.Result `json:"results"`
}

func runLandRun(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	target, err := c.landTarget(cfg)
	if err != nil {
		return err
	}
	repo, err := c.landRepo(cfg)
	if err != nil {
		return err
	}
	verifierName := c.flags["verifier"]
	if verifierName == "" {
		verifierName = cfg.Land.Verifier
	}
	if verifierName == "" {
		verifierName = "default"
	}
	verifier, err := verifierCommand(cfg, verifierName)
	if err != nil {
		return err
	}
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return failed("repository", err, "run the lander inside its own git clone")
	}
	f, err := c.openForge(cfg, root)
	if err != nil {
		return err
	}
	if g, ok := f.(*forge.Git); ok {
		// Moving a checked-out branch underneath a work tree would leave that
		// checkout disagreeing with its HEAD. Refuse, as git itself does for a
		// push — whichever work tree of the forge repository holds it.
		if where, err := checkedOut(c, g.Dir, target); err != nil {
			return failed("forge.dir", err, "nothing was attempted")
		} else if where != "" {
			return usageErr("--target", target+" is checked out in "+where, "check out another branch there, or point forge.dir at a bare repository")
		}
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	deps, err := c.laneDeps(cfg, store, root, repo)
	if err != nil {
		return err
	}
	deps.Progress = nil // the train reports its own progress
	host, _ := os.Hostname()
	tr := &land.Train{
		Forge: f, Store: store, Repo: repo, Target: target,
		Git:    &land.GitWorkspace{Dir: root, Remote: cfg.Land.Remote},
		Squash: c.flags["squash"] == "true" || cfg.Land.Strategy == "squash",
		Holder: fmt.Sprintf("pid-%d@%s", os.Getpid(), host),
		Log:    func(format string, a ...any) { c.progress("land: "+format, a...) },
	}
	// "A change touching Ring-0 or the lock lands only with explicit owner
	// approval": the lock is guarded even when no glob names it.
	globs := normGlobs(cfg.Ring0.Paths)
	tr.Ring0 = func(p string) bool { return p == LockPath || matchAny(globs, p) }
	tr.Approved = ownerSigned(root, cfg.Tenant.OwnerEmails, tr.Ring0)
	tr.Verify = land.LaneVerifier{RepoDir: root, Repo: repo, Target: target, Verifier: verifier, Runner: cfg.Land.Runner, Deps: deps, Epoch: tr.Epoch}.Verify

	sum, runErr := tr.Run(c, c.flags["once"] == "true")
	c.clearProgress()
	landed, evicted, pending := sum.Count(land.Landed), sum.Count(land.Evicted), sum.Count(land.Pending)
	if !c.json {
		rows := [][]string{{"STATE", "BRANCH", "HEAD", "LANDED", "DETAIL"}}
		for _, r := range sum.Results {
			detail := r.Reason
			if r.State == land.Landed && r.Capsule != "" {
				detail = strings.TrimSpace(short(r.Capsule) + "  " + r.Reason)
			}
			landedSHA := dash(r.Landed.Short())
			if r.State != land.Landed {
				landedSHA = "—"
			}
			rows = append(rows, []string{r.State, r.Change.Branch, r.Change.Head.Short(), landedSHA, dash(oneLine(humanHashes(detail), 160))})
		}
		fmt.Fprint(c.inv.Stdout, grid(rows))
	}
	results := sum.Results
	if results == nil {
		results = []land.Result{}
	}
	// A notification, check, or record that failed changes no outcome, but it
	// must not go unseen: one stderr line each, TTY or not, -q or not.
	untold := 0
	for _, r := range sum.Results {
		for _, w := range r.Warnings {
			fmt.Fprintln(c.inv.Stderr, "chimera: land run: warning: "+r.Change.Branch+": "+oneLine(humanHashes(lower(w)), 300))
			if strings.HasPrefix(w, "notify ") {
				untold++
			}
		}
	}
	told := "each owner was told the reason"
	if untold > 0 {
		told = fmt.Sprintf("%d of %d owners could not be told the reason; see the warnings", untold, evicted)
	}
	switch {
	case errors.Is(runErr, land.ErrFenced):
		return &cliError{code: ExitError, object: "epoch " + strconv.Itoa(sum.Epoch), msg: "fenced by a higher epoch", next: fmt.Sprintf("another lander has taken over; %d landed before that, nothing more was pushed", landed), findings: results}
	case runErr != nil:
		ce := remoteErr("", runErr, fmt.Sprintf("%d landed; changes not yet processed stay queued", landed))
		ce.findings = results
		return ce
	case evicted > 0:
		var first land.Result
		for _, r := range sum.Results {
			if r.State == land.Evicted {
				first = r
				break
			}
		}
		return &cliError{code: ExitError, msg: fmt.Sprintf("%d of %d changes evicted (%s: %s)", evicted, len(sum.Results), first.Change.Branch, oneLine(humanHashes(first.Reason), 200)),
			next: fmt.Sprintf("%d landed on %s; %s", landed, target, told), findings: results}
	case pending > 0:
		last := sum.Results[len(sum.Results)-1]
		return &cliError{code: ExitPending, object: last.Change.Branch, msg: oneLine(humanHashes(last.Reason), 200), next: fmt.Sprintf("%d landed; run the command again", landed), findings: results}
	}
	if c.json {
		if err := c.emitJSON(landRunResult{Schema: "chimera.land.run/v1", Repo: repo, Target: target, Epoch: sum.Epoch, Results: results}); err != nil {
			return err
		}
	}
	if len(sum.Results) == 0 {
		c.info("land run: epoch %d, queue for %s is empty", sum.Epoch, target)
	} else {
		c.info("land run: epoch %d, %s  %d landed on %s, each verified after its rebase", sum.Epoch, c.status("PASS"), landed, target)
	}
	return nil
}

// checkedOut reports the work tree of the repository at dir that has
// target checked out, or "" when none has (a bare repository never does).
func checkedOut(ctx context.Context, dir, target string) (string, error) {
	out, err := gitx.Run(ctx, dir, "worktree", "list", "--porcelain")
	if err != nil {
		return "", err
	}
	where := ""
	for _, line := range strings.Split(string(out), "\n") {
		if p, ok := strings.CutPrefix(line, "worktree "); ok {
			where = p
		}
		if b, ok := strings.CutPrefix(line, "branch "); ok && b == forge.RefName(target) {
			return where, nil
		}
	}
	return "", nil
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// signerAddress extracts the address a verified signature belongs to from
// git's %GS: an SSH signature gives the allowed-signers principal as it is,
// an OpenPGP signature gives a user ID "Name <address>".
func signerAddress(signer string) string {
	signer = strings.TrimSpace(signer)
	if i := strings.LastIndexByte(signer, '<'); i >= 0 && strings.HasSuffix(signer, ">") {
		signer = signer[i+1 : len(signer)-1]
	}
	return asciiLower(signer)
}

// ownerSigned is explicit owner approval read from Git itself (PRODUCT.md,
// Ring-0 policy: "an owner-signed commit"): every commit of the change that
// touches a Ring-0 path must carry a good signature whose VERIFIED SIGNER is
// an address in tenant.owner_emails. The committer and author headers are
// claims anyone can write and are never consulted. Anything else — no
// owners configured, an unsigned commit, a signature Git cannot verify, a
// good signature by someone who is not an owner — is not approval.
func ownerSigned(root string, ownerEmails []string, ring0 func(string) bool) func(context.Context, forge.Change, land.Rebased, []string) bool {
	owners := map[string]bool{}
	for _, e := range ownerEmails {
		if e = asciiLower(strings.TrimSpace(e)); e != "" {
			owners[e] = true
		}
	}
	return func(ctx context.Context, _ forge.Change, rb land.Rebased, _ []string) bool {
		if len(owners) == 0 {
			return false
		}
		approved := false
		for _, src := range rb.Sources {
			out, err := gitx.Run(ctx, root, "-c", "core.quotePath=false", "diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-m", "--no-renames", "-z", src.SHA)
			if err != nil {
				return false
			}
			touches := false
			for _, p := range strings.Split(string(out), "\x00") {
				if p != "" && ring0(p) {
					touches = true
				}
			}
			if !touches {
				continue
			}
			sig, err := gitx.Run(ctx, root, "log", "-1", "--format=%G?%x00%GS", src.SHA)
			if err != nil {
				return false
			}
			status, signer, _ := strings.Cut(strings.TrimRight(string(sig), "\n"), "\x00")
			if status != "G" || !owners[signerAddress(signer)] {
				return false
			}
			approved = true
		}
		return approved
	}
}
