package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/gitx"
	"chimera/pkg/ledger"
)

var (
	flagTier       = flagSpec{Long: "tier", Arg: "T0-T3", Help: "only this authority tier"}
	flagPathFilter = flagSpec{Long: "path", Arg: "path", Help: "only entries at or under this path"}
	flagSuperseded = flagSpec{Long: "include-superseded", Help: "rank superseded entries normally instead of last"}
	flagLimit      = flagSpec{Long: "limit", Arg: "n", Help: "most hits to print (default 10)"}
	flagCanonical  = flagSpec{Long: "canonical", Help: "canonical form: sorted rows, sorted keys (the only form)"}
	flagPaths      = flagSpec{Long: "paths", Arg: "path", Multi: true, Help: "target path (repeatable; positionals also accepted)"}
	flagFailure    = flagSpec{Long: "failure", Arg: "text", Help: "failure text to normalize, hash, and look up"}
)

// repoName resolves the repository name recorded on Ledger rows and
// Capsules: --repo, else the single configured tenant repo, else the work
// tree's directory name.
func (c *ctx) repoName(cfg *config.Config, root string) string {
	if r := c.flags["repo"]; r != "" {
		return r
	}
	if len(cfg.Tenant.Repos) == 1 {
		return cfg.Tenant.Repos[0]
	}
	if root != "" {
		return filepath.Base(root)
	}
	return ""
}

// ledgerSource assembles the two inputs the Ledger is derived from.
func (c *ctx) ledgerSource(cfg *config.Config) (ledger.Source, error) {
	var src ledger.Source
	if root, err := gitx.Toplevel(c, c.inv.Dir); err == nil {
		src.RepoDir = root
	}
	src.Repo = c.repoName(cfg, src.RepoDir)
	if cfg.Store.Endpoint != "" {
		store, err := c.openStore(cfg)
		if err != nil {
			return src, err
		}
		src.Store = store
	}
	if src.RepoDir == "" && src.Store == nil {
		return src, usageErr("sources", "not in a git work tree and no store configured", "nothing to index")
	}
	return src, nil
}

func (c *ctx) reportIndex(verb string, path string, src ledger.Source, st ledger.Stats) {
	if src.RepoDir == "" {
		c.info("ledger %s: not in a git work tree; T0 documents skipped", verb)
	}
	if src.Store == nil {
		c.info("ledger %s: store not configured; capsules not replayed", verb)
	}
	if st.Rejected > 0 {
		c.info("ledger %s: %d capsules failed verification and were not indexed", verb, st.Rejected)
	}
	c.info("ledger %s: %s  %d entries, %d lanes (+%d −%d T0, +%d capsules)  %s", verb, c.status("PASS"),
		st.EntryCount, st.LaneCount, st.T0Added, st.T0Removed, st.Capsules, path)
}

func runLedgerIndex(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	path, err := c.ledgerPath(cfg)
	if err != nil {
		return err
	}
	src, err := c.ledgerSource(cfg)
	if err != nil {
		return err
	}
	l, err := ledger.Open(c, path)
	if err != nil {
		return failed("ledger", err, "nothing indexed")
	}
	defer l.Close()
	st, err := l.Index(c, src)
	if err != nil {
		return failed("ledger", err, "index rolled back")
	}
	c.reportIndex("index", path, src, st)
	return nil
}

func runLedgerRebuild(c *ctx) error {
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	path, err := c.ledgerPath(cfg)
	if err != nil {
		return err
	}
	src, err := c.ledgerSource(cfg)
	if err != nil {
		return err
	}
	l, st, err := ledger.Rebuild(c, path, src)
	if err != nil {
		return failed("ledger", err, "run 'chimera ledger rebuild' again")
	}
	defer l.Close()
	c.reportIndex("rebuild", path, src, st)
	return nil
}

// openLedger opens an existing Ledger for reading. A missing database is an
// error with a next action, not an empty answer.
func (c *ctx) openLedger() (*ledger.Ledger, error) {
	cfg, err := c.loadConfig()
	if err != nil {
		return nil, err
	}
	path, err := c.ledgerPath(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, &cliError{code: ExitError, object: "ledger", msg: "no database at " + path, next: "run 'chimera ledger rebuild'"}
	}
	l, err := ledger.Open(c, path)
	if err != nil {
		return nil, failed("ledger", err, "run 'chimera ledger rebuild'")
	}
	return l, nil
}

// freshness measures drift against the current work tree, or returns nil
// outside one (every entry then reads as fresh).
func (c *ctx) freshness() *ledger.Freshness {
	root, err := gitx.Toplevel(c, c.inv.Dir)
	if err != nil {
		return nil
	}
	f, err := ledger.NewFreshness(c, root)
	if err != nil {
		return nil
	}
	return f
}

type queryHit struct {
	ID         string  `json:"id"`
	Tier       string  `json:"tier"`
	Kind       string  `json:"kind"`
	Repo       string  `json:"repo"`
	Path       string  `json:"path"`
	Anchor     string  `json:"anchor"`
	Intent     string  `json:"intent"`
	Capsule    string  `json:"capsule"`
	Supersedes string  `json:"supersedes"`
	State      string  `json:"state"`
	Drift      int     `json:"drift"`
	Superseded bool    `json:"superseded"`
	Score      float64 `json:"score"`
	Snippet    string  `json:"snippet"`
}

type queryResult struct {
	Schema string     `json:"schema"`
	Query  string     `json:"query"`
	Hits   []queryHit `json:"hits"`
}

func runLedgerQuery(c *ctx) error {
	q := ledger.Query{Text: c.args[0], Tier: c.flags["tier"], Path: c.flags["path"], IncludeSuperseded: c.flags["include-superseded"] == "true", Limit: 10}
	if q.Tier != "" && !ledger.ValidTier(q.Tier) {
		return usageErr("--tier", "must be T0, T1, T2, or T3", "nothing queried")
	}
	if v := c.flags["limit"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return usageErr("--limit", "must be a positive integer", "nothing queried")
		}
		q.Limit = n
	}
	l, err := c.openLedger()
	if err != nil {
		return err
	}
	defer l.Close()
	hits, err := l.Query(c, q, c.freshness())
	if err != nil {
		if strings.Contains(err.Error(), "no searchable words") {
			return usageErr("query", err.Error(), "nothing queried")
		}
		return failed("ledger", err, "run 'chimera ledger rebuild'")
	}
	if c.json {
		res := queryResult{Schema: "chimera.ledger.query/v1", Query: q.Text, Hits: []queryHit{}}
		for _, h := range hits {
			res.Hits = append(res.Hits, queryHit{ID: h.ID, Tier: h.Tier, Kind: h.Kind, Repo: h.Repo, Path: h.Path, Anchor: h.Anchor, Intent: h.Intent,
				Capsule: h.Capsule, Supersedes: h.Supersedes, State: h.State, Drift: h.Drift, Superseded: h.Superseded, Score: h.Score, Snippet: h.Snippet})
		}
		return c.emitJSON(res)
	}
	if len(hits) == 0 {
		c.info("ledger query: no entries match")
		return nil
	}
	rows := [][]string{{"TIER", "STATE", "KIND", "PATH", "SOURCE", "ID", "SNIPPET"}}
	for _, h := range hits {
		state := h.State
		if h.Superseded {
			state += " superseded"
		}
		source := short(h.Capsule)
		if h.Capsule == "" {
			source = "git"
		}
		rows = append(rows, []string{h.Tier, state, h.Kind, dash(h.Path), source, h.ID, h.Snippet})
	}
	fmt.Fprint(c.inv.Stdout, grid(rows))
	return nil
}

func runLedgerDump(c *ctx) error {
	l, err := c.openLedger()
	if err != nil {
		return err
	}
	defer l.Close()
	if err := l.Dump(c, c.inv.Stdout); err != nil {
		return failed("ledger", err, "dump incomplete")
	}
	return nil
}

type statusResult struct {
	Schema string `json:"schema"`
	ledger.Status
}

func runLedgerStatus(c *ctx) error {
	l, err := c.openLedger()
	if err != nil {
		return err
	}
	defer l.Close()
	st, err := l.Status(c)
	if err != nil {
		return failed("ledger", err, "run 'chimera ledger rebuild'")
	}
	if c.json {
		return c.emitJSON(statusResult{Schema: "chimera.ledger.status/v1", Status: st})
	}
	rows := [][]string{
		{"LEDGER", st.Path},
		{"ENTRIES", strconv.Itoa(st.Entries)},
		{"T0", strconv.Itoa(st.Tiers[ledger.T0])},
		{"T1", strconv.Itoa(st.Tiers[ledger.T1])},
		{"T2", strconv.Itoa(st.Tiers[ledger.T2])},
		{"T3", strconv.Itoa(st.Tiers[ledger.T3])},
		{"CAPSULES", strconv.Itoa(st.Capsules)},
		{"LANES", strconv.Itoa(st.Lanes)},
		{"DIGEST", short(st.Digest)},
	}
	fmt.Fprint(c.inv.Stdout, grid(rows))
	return nil
}

func runPreflight(c *ctx) error {
	paths := append(append([]string{}, c.args...), c.list("paths")...)
	if len(paths) == 0 && c.flags["failure"] == "" {
		return usageErr("", "no paths and no --failure", "pass target paths or a failure text")
	}
	cfg, err := c.loadConfig()
	if err != nil {
		return err
	}
	root, _ := gitx.Toplevel(c, c.inv.Dir)
	// Paths are repository-relative; ones given relative to a subdirectory are rebased.
	if root != "" {
		realRoot, _ := filepath.EvalSymlinks(root)
		realDir, _ := filepath.EvalSymlinks(c.inv.Dir)
		for i, p := range paths {
			if filepath.IsAbs(p) {
				if real, err := filepath.EvalSymlinks(p); err == nil {
					p = real
				}
			} else {
				p = filepath.Join(realDir, p)
			}
			if rel, err := filepath.Rel(realRoot, p); err == nil && !strings.HasPrefix(rel, "..") {
				paths[i] = filepath.ToSlash(rel)
			}
		}
	}
	l, err := c.openLedger()
	if err != nil {
		return err
	}
	defer l.Close()
	sc, err := l.Preflight(c, c.repoName(cfg, root), paths, c.flags["failure"], c.freshness())
	if err != nil {
		return failed("ledger", err, "run 'chimera ledger rebuild'")
	}
	if c.json {
		_, err = io.WriteString(c.inv.Stdout, sc.JSON())
		return err
	}
	_, err = io.WriteString(c.inv.Stdout, sc.Text())
	return err
}
