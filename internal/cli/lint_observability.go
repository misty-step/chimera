package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/obslint"
)

// obsResult is the chimera.lint/v1 object for the observability check. It is
// the data on stdout under --json whatever the outcome, findings included.
type obsResult struct {
	Schema   string            `json:"schema"`
	Check    string            `json:"check"`
	Dir      string            `json:"dir"`
	Status   string            `json:"status"`
	Reason   string            `json:"reason,omitempty"`
	Strict   bool              `json:"strict"`
	Files    int               `json:"files"`
	Surfaces []obslint.Surface `json:"surfaces"`
	Findings []obslint.Finding `json:"findings"`
	Waived   int               `json:"waived"`
	Skipped  []obslint.Finding `json:"skipped"`
}

func runLintObservability(c *ctx) error {
	shown := "."
	dir := c.inv.Dir
	if len(c.args) == 1 {
		shown = filepath.ToSlash(filepath.Clean(c.args[0]))
		dir = c.abs(c.args[0])
	}
	strict := c.flags["strict"] == "true"

	// The audited repository's own chimera.yaml is discovered in <dir>.
	file := c.flags["config"]
	if file != "" {
		file = c.abs(file)
	}
	cfg, err := config.Load(config.Options{File: file, Dir: dir}, c.inv.Env)
	if err != nil {
		var le *config.LoadError
		if errors.As(err, &le) {
			return usageErr("config", lower(le.Msg), "nothing was audited")
		}
		return usageErr("config", err.Error(), "nothing was audited")
	}

	rep, err := obslint.Audit(dir, obslint.Options{Allow: cfg.Observability.Allow})
	if err != nil {
		switch {
		case errors.Is(err, obslint.ErrNotDir), errors.Is(err, fs.ErrNotExist):
			return usageErr(shown, "not a directory", "nothing was audited")
		default:
			return &cliError{code: ExitError, object: shown, msg: "cannot read directory: " + lower(pathErrText(err)), next: "nothing was audited"}
		}
	}
	if c.Err() != nil {
		return &cliError{code: ExitError, msg: "interrupted", next: "nothing reported"}
	}

	at := func(fs []obslint.Finding) []obslint.Finding {
		out := make([]obslint.Finding, len(fs))
		for i, f := range fs {
			if shown != "." {
				f.Path = under(shown, f.Path)
			}
			out[i] = f
		}
		return out
	}
	findings, skipped := at(rep.Findings), at(rep.Problems)
	surfaces := make([]obslint.Surface, len(rep.Surfaces))
	for i, s := range rep.Surfaces {
		if shown != "." {
			s.Path = under(shown, s.Path)
		}
		surfaces[i] = s
	}
	status := rep.Status
	if strict && len(skipped) > 0 {
		// Fail closed: what could not be read cannot be vouched for.
		findings = append(findings, skipped...)
		obslint.Sort(findings)
		skipped = []obslint.Finding{}
		status = obslint.StatusFail
	}
	res := obsResult{Schema: "chimera.lint/v1", Check: "observability", Dir: shown, Status: status, Reason: rep.Reason,
		Strict: strict, Files: rep.Files, Surfaces: surfaces, Findings: findings, Waived: rep.Waived, Skipped: skipped}

	if c.json {
		if err := c.emitJSON(res); err != nil {
			return err
		}
	} else if status == obslint.StatusFail {
		for _, f := range findings {
			fmt.Fprintln(c.inv.Stdout, f.String())
		}
	}
	if len(skipped) > 0 {
		c.info("lint observability: warning: %d entries not fully read (%s); --strict fails closed", len(skipped), strings.Join(ruleList(skipped), ", "))
	}
	kinds := surfaceKinds(surfaces)
	if status == obslint.StatusFail {
		return &cliError{
			code:   ExitError,
			object: shown,
			msg:    fmt.Sprintf("%d findings (rule %s)", len(findings), strings.Join(ruleList(findings), ", ")),
			next:   obsNext(findings),
			noJSON: true, // the chimera.lint/v1 object above is the data
		}
	}
	if status == obslint.StatusNotApplicable {
		c.info("lint observability: not-applicable  %d files, %s", rep.Files, rep.Reason)
		return nil
	}
	c.info("lint observability: %s  %d files, surfaces %s, 0 findings, %d waived", c.status("PASS"), rep.Files, kinds, rep.Waived)
	return nil
}

// under prefixes a path relative to the audited directory with the directory
// as the user wrote it, keeping a trailing slash that marks a directory.
func under(shown, p string) string {
	j := path.Join(shown, p)
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(j, "/") {
		j += "/"
	}
	return j
}

func ruleList(fs []obslint.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			out = append(out, f.Rule)
		}
	}
	sort.Strings(out)
	return out
}

func surfaceKinds(ss []obslint.Surface) string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s.Kind] {
			seen[s.Kind] = true
			out = append(out, s.Kind)
		}
	}
	return strings.Join(out, ", ")
}

func pathErrText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// obsNext is the error line's next action. Scan problems (--strict) cannot be
// waived in observability.allow; only unmet invariants can.
func obsNext(findings []obslint.Finding) string {
	for _, f := range findings {
		if f.Invariant != "scan" {
			return "restore the missing observability or waive the rule in observability.allow"
		}
	}
	return "make every entry readable, or run without --strict"
}
