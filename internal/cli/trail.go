package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/gitx"
	"chimera/pkg/objstore"
	"chimera/pkg/trail"
)

var flagCheck = flagSpec{Long: "check", Help: "print the forge check summary; exit 1 on FAIL, 3 on PENDING"}

// riskGlob builds the config risk-glob classifier: the highest class whose
// glob matches wins, so a path under both an r2 and an r3 glob is R3.
func riskGlob(cfg *config.Config) func(string) (string, string) {
	classes := []struct {
		class string
		globs []string
	}{{"R3", normGlobs(cfg.Risk.R3)}, {"R2", normGlobs(cfg.Risk.R2)}, {"R1", normGlobs(cfg.Risk.R1)}}
	return func(p string) (string, string) {
		for _, c := range classes {
			for _, g := range c.globs {
				if matchGlob(g, p) {
					return c.class, g
				}
			}
		}
		return "", ""
	}
}

// trailFinding is one item behind a check that did not pass.
type trailFinding struct {
	Kind      string `json:"kind"` // missing_proof | verdict | open_risk | unmet_intent
	Commit    string `json:"commit,omitempty"`
	ID        string `json:"id,omitempty"`
	Criterion string `json:"criterion,omitempty"`
	Class     string `json:"class,omitempty"`
	Path      string `json:"path,omitempty"`
	Reason    string `json:"reason,omitempty"`
	State     string `json:"state,omitempty"`
	Capsule   string `json:"capsule,omitempty"`
}

func trailFindings(rep *trail.Report) []trailFinding {
	out := []trailFinding{}
	for _, m := range rep.Missing {
		out = append(out, trailFinding{Kind: "missing_proof", Commit: m.Commit, Reason: strings.Join(m.Reasons, "; ")})
	}
	for _, v := range rep.Verdicts {
		if v.State == trail.StateFail && v.SupersededBy == "" {
			out = append(out, trailFinding{Kind: "verdict", ID: v.ID, Criterion: v.Criterion, State: v.State, Capsule: v.Capsule, Commit: v.Commit})
		}
	}
	for _, it := range rep.OpenRisk {
		out = append(out, trailFinding{Kind: "open_risk", Class: it.Class, Path: it.Path, Reason: it.Reason})
	}
	for _, u := range rep.Unmet {
		out = append(out, trailFinding{Kind: "unmet_intent", ID: u.ID, Criterion: u.Criterion, State: u.State})
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func verdictCounts(rep *trail.Report) string {
	pass, fail, stale, superseded := rep.Counts()
	s := fmt.Sprintf("%d  (%d pass, %d fail", len(rep.Verdicts), pass, fail)
	if stale > 0 {
		s += fmt.Sprintf(", %d stale", stale)
	}
	if superseded > 0 {
		s += fmt.Sprintf(", %d superseded", superseded)
	}
	return s + ")"
}

func trailIntent(rep *trail.Report) string {
	switch len(rep.Intents) {
	case 0:
		return "—"
	case 1:
		return short(rep.Intents[0])
	}
	return fmt.Sprintf("%d intents", len(rep.Intents))
}

// sourceText names where a row's evidence is, for humans.
func sourceText(s trail.Source) string {
	switch {
	case s.Capsule != "" && s.Line > 0:
		return fmt.Sprintf("%s:%d", short(s.Capsule), s.Line)
	case s.Capsule != "":
		return short(s.Capsule)
	case s.Commit != "":
		return abbrev(s.Commit)
	}
	return "—"
}

func runTrail(c *ctx) error {
	spec := c.args[0]
	baseRev, headRev, ok := strings.Cut(spec, "..")
	if !ok || baseRev == "" || headRev == "" || strings.HasPrefix(headRev, ".") {
		return usageErr(spec, "range must be <base>..<head>", "nothing was attempted")
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return failed("repository", err, "run inside a git work tree")
	}
	for _, rev := range []string{baseRev, headRev} {
		if _, err := gitx.RevParse(c, root, rev+"^{commit}"); err != nil {
			return usageErr(spec, err.Error(), "nothing was attempted")
		}
	}
	store, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	opts := trail.Options{RepoDir: root, Repo: c.repoName(cfg, root), Base: baseRev, Head: headRev, Store: store, RiskGlob: riskGlob(cfg)}
	if globs := normGlobs(cfg.Ring0.Paths); len(globs) > 0 {
		opts.Ring0 = func(p string) bool { return matchAny(globs, p) }
	}
	rep, err := trail.Build(c, opts)
	if errors.Is(err, objstore.ErrUnavailable) {
		// The store did not answer: whether the proof exists is not known.
		return &cliError{code: ExitPending, object: spec, msg: lower(err.Error()), next: "evidence unconfirmed; run the command again"}
	}
	if err != nil {
		return failed(spec, err, "no trail")
	}
	rangeText := abbrev(rep.Base) + ".." + abbrev(rep.Head)
	if dir := c.flags["html"]; dir != "" {
		if err := trail.WriteBundle(c.abs(dir), rep); err != nil {
			return failed("--html", err, "trail page not written")
		}
		c.info("trail: wrote %s", filepath.Join(dir, "index.html"))
	}

	if c.flags["check"] == "true" {
		passed := rep.Check.State == trail.StatePass
		switch {
		case c.json && passed:
			if err := c.emitJSON(rep); err != nil {
				return err
			}
		case !c.json:
			fmt.Fprint(c.inv.Stdout, grid([][]string{
				{"CHECK", rep.Check.State}, {"RANGE", strings.TrimSpace(rep.Repo + " " + rangeText)}, {"INTENT", trailIntent(rep)}, {"RISK", rep.Risk},
				{"OPEN RISK", fmt.Sprint(len(rep.OpenRisk))}, {"UNMET INTENT", fmt.Sprint(len(rep.Unmet))},
				{"MISSING PROOF", fmt.Sprint(len(rep.Missing))}, {"VERDICTS", verdictCounts(rep)},
			}))
		}
		_, fail, _, _ := rep.Counts()
		switch rep.Check.State {
		case trail.StateFail:
			var why []string
			if n := len(rep.Missing); n > 0 {
				why = append(why, plural(n, "commit with missing proof", "commits with missing proof"))
			}
			if fail > 0 {
				why = append(why, plural(fail, "failing verdict", "failing verdicts"))
			}
			return &cliError{code: ExitError, object: rangeText, msg: "check FAIL: " + strings.Join(why, ", "), next: "the range does not pass review", findings: trailFindings(rep)}
		case trail.StatePending:
			var why []string
			if n := len(rep.OpenRisk); n > 0 {
				why = append(why, fmt.Sprintf("%d open risk", n))
			}
			if n := len(rep.Unmet); n > 0 {
				why = append(why, fmt.Sprintf("%d unmet intent", n))
			}
			return &cliError{code: ExitPending, object: rangeText, msg: "check PENDING: " + strings.Join(why, ", "), next: "owner review or more proof decides it", findings: trailFindings(rep)}
		}
		c.info("trail: %s  %s", c.status("PASS"), rangeText)
		return nil
	}

	if c.json {
		return c.emitJSON(rep)
	}
	var b strings.Builder
	b.WriteString(grid([][]string{
		{"TRAIL", strings.TrimSpace(rep.Repo + " " + rangeText)}, {"INTENT", trailIntent(rep)}, {"RISK", rep.Risk}, {"CHECK", rep.Check.State},
		{"OPEN RISK", fmt.Sprint(len(rep.OpenRisk))}, {"UNMET INTENT", fmt.Sprint(len(rep.Unmet))},
		{"MISSING PROOF", fmt.Sprint(len(rep.Missing))}, {"VERDICTS", verdictCounts(rep)},
	}))
	section := func(title string, rows [][]string) {
		b.WriteString("\n" + title + "\n")
		if len(rows) == 1 {
			b.WriteString("None.\n")
			return
		}
		b.WriteString(grid(rows))
	}
	risk := [][]string{{"CLASS", "PATH", "REASON", "SOURCE"}}
	for _, it := range rep.OpenRisk {
		risk = append(risk, []string{dash(it.Class), dash(it.Path), it.Reason, sourceText(it.Source)})
	}
	section("OPEN RISK", risk)
	unmet := [][]string{{"ID", "STATE", "CRITERION"}}
	for _, u := range rep.Unmet {
		unmet = append(unmet, []string{u.ID, u.State, u.Criterion})
	}
	section("UNMET INTENT", unmet)
	missing := [][]string{{"COMMIT", "MISSING", "SUBJECT"}}
	for _, m := range rep.Missing {
		missing = append(missing, []string{abbrev(m.Commit), strings.Join(m.Reasons, "; "), m.Subject})
	}
	section("MISSING PROOF", missing)
	verdicts := [][]string{{"ID", "STATE", "CRITERION", "EVIDENCE"}}
	for _, v := range rep.Verdicts {
		criterion := v.Criterion
		if v.SupersededBy != "" {
			criterion += " (superseded by " + short(v.SupersededBy) + ")"
		}
		verdicts = append(verdicts, []string{v.ID, v.State, criterion, sourceText(v.Source)})
	}
	section("VERDICTS", verdicts)
	commits := [][]string{{"COMMIT", "RISK", "CAPSULE", "INTENT", "SUBJECT"}}
	for _, cm := range rep.Commits {
		caps := make([]string, len(cm.Capsules))
		for i, a := range cm.Capsules {
			caps[i] = short(a)
		}
		ints := make([]string, len(cm.Intents))
		for i, id := range cm.Intents {
			ints[i] = short(id)
		}
		commits = append(commits, []string{abbrev(cm.SHA), cm.Risk, dash(strings.Join(caps, ",")), dash(strings.Join(ints, ",")), cm.Subject})
	}
	section("COMMITS", commits)
	fmt.Fprint(c.inv.Stdout, b.String())
	return nil
}
