package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/config"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/ledger"
	"chimera/pkg/objstore"
)

var (
	flagLane     = flagSpec{Long: "lane", Arg: "name", Help: "lane from the config's lanes"}
	flagVerifier = flagSpec{Long: "verifier", Arg: "name", Help: "verifier from the config's verifiers (default: default)"}
	flagBrief    = flagSpec{Long: "brief", Arg: "text", Help: "task brief appended to the lane's prompt"}
	flagBase     = flagSpec{Long: "base", Arg: "rev", Help: "commit the lane starts from (default HEAD)"}
	flagApply    = flagSpec{Long: "apply", Help: "apply the diff and commit it with both trailers"}
	flagMessage  = flagSpec{Long: "message", Arg: "text", Help: "commit subject for --apply"}
	flagMatrix   = flagSpec{Long: "matrix", Arg: "file", Help: "bench file: fixtures and LaneConfig axes"}
	flagK        = flagSpec{Long: "k", Short: 'K', Arg: "n", Help: "lanes per cell (default: the matrix's k, else 1)"}
	flagHTML     = flagSpec{Long: "html", Arg: "dir", Help: "also write the static report bundle to this directory"}
)

func duration(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d
	}
	return def
}

// laneDeps wires the Bench engine to the store, the gate, and the Ledger.
func (c *ctx) laneDeps(cfg *config.Config, store objstore.Store, root, repo string) (lane.Deps, error) {
	scanner, err := c.gate(cfg)
	if err != nil {
		return lane.Deps{}, err
	}
	ledgerPath, lerr := c.ledgerPath(cfg)
	globs := normGlobs(cfg.Ring0.Paths)
	deps := lane.Deps{
		Runner: func(name string) (lane.Runner, error) {
			switch name {
			case "", "local":
				return lane.Local{}, nil
			case "boat":
				// A remote sandbox costs money: it runs only when configured.
				rc, ok := cfg.Runners["boat"]
				if !ok {
					return nil, fmt.Errorf("runner boat is not configured (runners.boat)")
				}
				cmd, _ := rc["command"].(string)
				return lane.Boat{Command: cmd}, nil
			}
			return nil, fmt.Errorf("unknown runner %q", name)
		},
		Push: func(ctx context.Context, dir string) error {
			_, err := capsule.Push(ctx, store, dir, scanner)
			var ge *capsule.GateError
			if errors.As(err, &ge) {
				locs := make([]string, len(ge.Findings))
				for i, f := range ge.Findings {
					locs[i] = f.String()
				}
				return fmt.Errorf("%s at %s; nothing uploaded", ge.Error(), strings.Join(locs, ", "))
			}
			return err
		},
		Progress: func(cell lane.Cell, k, total int) {
			c.info("lane: cell %s  %s  k=%d/%d", cell.Hash(), laneLine(cell.Lane), k, total)
		},
	}
	if len(globs) > 0 {
		deps.Ring0 = func(p string) bool { return matchAny(globs, p) }
	}
	if lerr == nil {
		deps.Env = []string{"CHIMERA_LEDGER_PATH=" + ledgerPath}
		deps.Index = func(ctx context.Context) error {
			l, err := ledger.Open(ctx, ledgerPath)
			if err != nil {
				return err
			}
			defer l.Close()
			_, err = l.Index(ctx, ledger.Source{Repo: repo, RepoDir: root, Store: store})
			return err
		}
		deps.Scent = func(ctx context.Context, cell lane.Cell) string {
			if _, err := os.Stat(ledgerPath); errors.Is(err, fs.ErrNotExist) {
				return ""
			}
			l, err := ledger.Open(ctx, ledgerPath)
			if err != nil {
				return ""
			}
			defer l.Close()
			fresh, _ := ledger.NewFreshness(ctx, cell.Fixture.RepoDir)
			sc, err := l.Preflight(ctx, cell.Fixture.Repo, []string{"."}, "", fresh)
			if err != nil {
				return ""
			}
			return sc.Text()
		}
	}
	return deps, nil
}

func price(cfg *config.Config, model string) *lane.Price {
	p, ok := cfg.Prices[model]
	if !ok {
		return nil
	}
	return &lane.Price{InputPerMTok: p.InputPerMTok, OutputPerMTok: p.OutputPerMTok}
}

func harnessCommand(cfg *config.Config, name string) (lane.Command, error) {
	h, ok := cfg.Harnesses[name]
	if !ok || len(h.Command) == 0 {
		return lane.Command{}, usageErr("harness "+strconv.Quote(name), "not configured", "add it under harnesses in chimera.yaml")
	}
	return lane.Command{Argv: h.Command, Timeout: duration(h.Timeout, lane.DefaultHarnessTimeout)}, nil
}

func verifierCommand(cfg *config.Config, name string) (lane.Command, error) {
	v, ok := cfg.Verifiers[name]
	if !ok || len(v.Command) == 0 {
		return lane.Command{}, usageErr("verifier "+strconv.Quote(name), "not configured", "add it under verifiers in chimera.yaml")
	}
	return lane.Command{Argv: v.Command, Timeout: duration(v.Timeout, lane.DefaultVerifierTimeout)}, nil
}

type runResult struct {
	Schema     string             `json:"schema"`
	Capsule    string             `json:"capsule"`
	Intent     string             `json:"intent"`
	Checkpoint string             `json:"checkpoint"`
	Repo       string             `json:"repo"`
	BaseSHA    string             `json:"base_sha"`
	Tree       string             `json:"tree"`
	Lane       capsule.LaneConfig `json:"lane"`
	WallMS     int64              `json:"wall_ms"`
	CostUSD    *float64           `json:"cost_usd"`
	Pass       bool               `json:"pass"`
	Verdicts   []capsule.Verdict  `json:"verdicts"`
	Trailers   map[string]string  `json:"trailers"`
	Commit     string             `json:"commit"` // "" unless --apply committed
}

func runRun(c *ctx) error {
	name := c.flags["lane"]
	if c.flags["intent"] == "" || name == "" {
		return usageErr("", "--intent and --lane are required", "nothing ran")
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	lc, ok := cfg.Lanes[name]
	if !ok {
		return usageErr("lane "+strconv.Quote(name), "not configured", "add it under lanes in chimera.yaml")
	}
	harness, err := harnessCommand(cfg, lc.Harness)
	if err != nil {
		return err
	}
	verifierName := c.flags["verifier"]
	if verifierName == "" {
		verifierName = "default"
	}
	verifier, err := verifierCommand(cfg, verifierName)
	if err != nil {
		return err
	}
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return failed("repository", err, "run inside a git work tree")
	}
	baseRev := c.flags["base"]
	if baseRev == "" {
		baseRev = "HEAD"
	}
	base, err := gitx.RevParse(c, root, baseRev+"^{commit}")
	if err != nil {
		return usageErr("--base", err.Error(), "nothing ran")
	}
	intent := c.flags["intent"]
	if intent == "folio" {
		// Shorthand: the folio Intent of the commit the lane starts from.
		if intent, err = gitx.FolioIntent(c, root, base); err != nil {
			return failed("--intent folio", err, "nothing ran")
		}
	}
	if !capsule.ValidIntent(intent) {
		return usageErr("--intent", "must be folio, folio:<64 hex>, or task:<64 hex>", "nothing ran")
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	repo := c.repoName(cfg, root)
	deps, err := c.laneDeps(cfg, store, root, repo)
	if err != nil {
		return err
	}
	policy := lc.ContextPolicy
	if policy == "" {
		policy = "none"
	}
	runner := lc.Runner
	if runner == "" {
		runner = "local"
	}
	plan := lane.Plan{K: 1, Tags: []string{"lane:" + name}, Cells: []lane.Cell{{
		Fixture: lane.Fixture{Name: name, Repo: repo, RepoDir: root, BaseSHA: base, Brief: c.flags["brief"], Verifier: verifier, Intent: intent},
		Lane: capsule.LaneConfig{Model: lc.Model, Harness: lc.Harness, Skill: lc.Skill, Prompt: lc.Prompt, Effort: lc.Effort,
			ContextPolicy: policy, Runner: runner},
		Harness: harness, Price: price(cfg, lc.Model),
	}}}
	rep, err := lane.Run(c, plan, deps)
	if err != nil && (rep == nil || len(rep.Cells) == 0) {
		return failed("lane "+name, err, "no capsule recorded")
	}
	indexErr := err
	lr := rep.Cells[0].Lanes[0]
	if lr.Capsule == "" {
		return &cliError{code: ExitError, object: "lane " + name, msg: lower(lr.Error), next: "no capsule recorded"}
	}
	res := runResult{Schema: "chimera.run/v1", Capsule: lr.Capsule, Intent: intent, Checkpoint: lr.Checkpoint, Repo: repo, BaseSHA: base,
		Tree: lr.Tree, Lane: plan.Cells[0].Lane, WallMS: lr.WallMS, CostUSD: lr.CostUSD, Pass: lr.Pass, Verdicts: lr.Verdicts,
		Trailers: map[string]string{gitx.TrailerIntent: intent, gitx.TrailerCapsule: lr.Capsule}}

	var applyErr error
	if c.flags["apply"] == "true" && lr.Pass {
		msg := c.flags["message"]
		if msg == "" {
			msg = "lane: apply " + name + " result"
		}
		res.Commit, applyErr = applyDiff(c, root, lr.Diff, msg, intent, lr.Capsule)
	}

	passed, failing := 0, []capsule.Verdict{}
	for _, v := range lr.Verdicts {
		if v.Pass {
			passed++
		} else {
			failing = append(failing, v)
		}
	}
	if c.json {
		if lr.Pass && applyErr == nil {
			if err := c.emitJSON(res); err != nil {
				return err
			}
		}
	} else {
		rows := [][]string{
			{"CAPSULE", short(res.Capsule)}, {"INTENT", short(intent)}, {"CHECKPOINT", lr.Checkpoint}, {"REPO", dash(repo)},
			{"BASE", abbrev(base)}, {"LANE", laneLine(res.Lane)}, {"WALL", lane.FormatDuration(lr.WallMS)}, {"COST", lane.FormatCost(lr.CostUSD)},
			{"VERDICT", fmt.Sprintf("%s  %d/%d criteria", passWord(lr.Pass), passed, len(lr.Verdicts))},
		}
		if res.Commit != "" {
			rows = append(rows, []string{"COMMIT", abbrev(res.Commit)})
		}
		fmt.Fprint(c.inv.Stdout, grid(rows))
		vr := [][]string{{"ID", "STATE", "CRITERION", "EVIDENCE"}}
		for _, v := range lr.Verdicts {
			vr = append(vr, []string{v.ID, passWord(v.Pass), v.Criterion, dash(oneLine(v.Evidence, 60))})
		}
		fmt.Fprint(c.inv.Stdout, "\n"+grid(vr))
		fmt.Fprintf(c.inv.Stdout, "\n%s: %s\n%s: %s\n", gitx.TrailerIntent, intent, gitx.TrailerCapsule, lr.Capsule)
	}
	switch {
	case !lr.Pass:
		next := "capsule " + lr.Capsule + " recorded"
		if c.flags["apply"] == "true" {
			next += "; not applied"
		}
		return &cliError{code: ExitError, object: "lane " + name, msg: fmt.Sprintf("verifier failed (%d of %d criteria)", len(failing), len(lr.Verdicts)), next: next, findings: failing}
	case applyErr != nil:
		return &cliError{code: ExitError, object: "--apply", msg: lower(applyErr.Error()), next: "capsule " + lr.Capsule + " recorded; history unchanged"}
	case indexErr != nil:
		return failed("ledger", indexErr, "capsule "+lr.Capsule+" recorded but not indexed; run 'chimera ledger index'")
	}
	if res.Commit != "" {
		c.info("run: %s  committed %s with both trailers", c.status("PASS"), abbrev(res.Commit))
	} else {
		c.info("run: %s  %s; git history untouched (use --apply to commit the diff)", c.status("PASS"), short(lr.Capsule))
	}
	return nil
}

// applyDiff applies a lane's diff to a clean work tree and commits it with
// both trailers. On any failure the tree is put back as it was.
func applyDiff(c *ctx, root string, diff []byte, subject, intent, addr string) (string, error) {
	if len(diff) == 0 {
		return "", fmt.Errorf("lane produced no changes to commit")
	}
	status, err := gitx.Run(c, root, "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return "", err
	}
	if len(strings.TrimSpace(string(status))) > 0 {
		return "", fmt.Errorf("work tree has uncommitted changes")
	}
	if _, err := gitx.RunInput(c, root, diff, nil, "apply", "--index", "--binary", "-"); err != nil {
		return "", fmt.Errorf("diff does not apply to HEAD")
	}
	msg, err := gitx.WithTrailers(c, root, subject+"\n", intent, addr)
	if err == nil {
		_, err = gitx.RunInput(c, root, []byte(msg), nil, "commit", "--quiet", "-F", "-")
	}
	if err != nil {
		gitx.Run(c, root, "reset", "--quiet", "--hard", "HEAD") // the tree was clean before the apply
		return "", err
	}
	return gitx.RevParse(c, root, "HEAD")
}

func runBench(c *ctx) error {
	file := c.flags["matrix"]
	if file == "" {
		return usageErr("", "--matrix is required", "nothing ran")
	}
	data, err := os.ReadFile(c.abs(file))
	if err != nil {
		return usageErr(file, "cannot read matrix", "nothing ran")
	}
	m, err := lane.ParseMatrix(data)
	if err != nil {
		return usageErr(file, err.Error(), "nothing ran")
	}
	k := m.K
	if v := c.flags["k"]; v != "" {
		if k, err = strconv.Atoi(v); err != nil || k < 1 {
			return usageErr("-K", "must be a positive integer", "nothing ran")
		}
	}
	if k < 1 {
		k = 1
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	matrixDir := filepath.Dir(c.abs(file))
	plan := lane.Plan{ID: m.ID, K: k}
	var fixtures []lane.Fixture
	for i, mf := range m.Fixtures {
		dir := mf.Repo
		if dir == "" {
			dir = "."
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(matrixDir, dir)
		}
		root, err := gitx.Toplevel(c, dir)
		if err != nil {
			return usageErr(file, fmt.Sprintf("fixture %d: repo is not a git work tree", i+1), "nothing ran")
		}
		rev := mf.BaseSHA
		if rev == "" {
			rev = "HEAD"
		}
		base, err := gitx.RevParse(c, root, rev+"^{commit}")
		if err != nil {
			return usageErr(file, fmt.Sprintf("fixture %d: %s", i+1, err.Error()), "nothing ran")
		}
		var verifier lane.Command
		if mf.Verifier.Name != "" {
			if verifier, err = verifierCommand(cfg, mf.Verifier.Name); err != nil {
				return err
			}
		} else {
			if len(mf.Verifier.Command) == 0 {
				return usageErr(file, fmt.Sprintf("fixture %d: no verifier", i+1), "nothing ran")
			}
			verifier = lane.Command{Argv: mf.Verifier.Command, Timeout: duration(mf.Verifier.Timeout, lane.DefaultVerifierTimeout)}
		}
		f := lane.Fixture{Name: mf.Name, Repo: c.repoName(cfg, root), RepoDir: root, BaseSHA: base, Brief: mf.TaskBrief, Verifier: verifier}
		if f.Name == "" {
			f.Name = fmt.Sprintf("fixture-%d", i+1)
		}
		f.Intent = lane.TaskIntent(f)
		fixtures = append(fixtures, f)
	}
	for _, f := range fixtures {
		for _, lc := range m.Axes.LaneConfigs() {
			harness, err := harnessCommand(cfg, lc.Harness)
			if err != nil {
				return err
			}
			plan.Cells = append(plan.Cells, lane.Cell{Fixture: f, Lane: lc, Harness: harness, Price: price(cfg, lc.Model)})
		}
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	root, _ := gitx.Toplevel(c, c.inv.Dir)
	deps, err := c.laneDeps(cfg, store, root, c.repoName(cfg, root))
	if err != nil {
		return err
	}
	rep, runErr := lane.Run(c, plan, deps)
	if rep == nil || (runErr != nil && c.Err() != nil) {
		return failed("bench "+m.ID, runErr, "bench incomplete")
	}
	if dir := c.flags["html"]; dir != "" {
		if err := lane.WritePage(c.abs(dir), rep); err != nil {
			return failed("--html", err, "report not written")
		}
		c.info("bench: wrote %s", filepath.Join(dir, "index.html"))
	}
	if n := rep.Failed(); n > 0 {
		var reasons []string
		for _, cell := range rep.Cells {
			for _, l := range cell.Lanes {
				if l.Capsule == "" {
					reasons = append(reasons, l.Error)
				}
			}
		}
		return &cliError{code: ExitError, object: "bench " + m.ID, msg: fmt.Sprintf("%d lanes produced no capsule (%s)", n, oneLine(reasons[0], 120)), next: "missing proof", findings: reasons}
	}
	if c.json {
		if err := c.emitJSON(rep); err != nil {
			return err
		}
	} else {
		rows := [][]string{{"FIXTURE", "CELL", "MODEL", "HARNESS", "EFFORT", "CONTEXT", "PASS RATE", "X/K", "WALL P50", "WALL P90", "COST"}}
		for _, cell := range rep.Cells {
			rows = append(rows, []string{cell.Fixture, cell.Cell, dash(cell.Lane.Model), dash(cell.Lane.Harness), dash(cell.Lane.Effort), dash(cell.Lane.ContextPolicy),
				fmt.Sprintf("%.2f", cell.PassRate), fmt.Sprintf("%d/%d", cell.AllPass, cell.K),
				lane.FormatDuration(cell.WallP50MS), lane.FormatDuration(cell.WallP90MS), lane.FormatCost(cell.CostUSD)})
		}
		fmt.Fprint(c.inv.Stdout, grid(rows))
	}
	if runErr != nil {
		return failed("ledger", runErr, "capsules recorded but not indexed; run 'chimera ledger index'")
	}
	c.info("bench %s: %d cells × K=%d, %d capsules tagged bench:%s and indexed", m.ID, len(rep.Cells), k, len(rep.Cells)*k, m.ID)
	return nil
}
