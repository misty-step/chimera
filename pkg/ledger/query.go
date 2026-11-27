package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"chimera/pkg/gitx"
)

// Freshness measures drift mechanically against HEAD of one work tree.
// Wall-clock age never enters.
type Freshness struct {
	dir   string
	head  map[string]string // path → blob at HEAD
	cache map[string]int
}

// NewFreshness reads HEAD's tree once.
func NewFreshness(ctx context.Context, repoDir string) (*Freshness, error) {
	tree, err := gitx.LsTree(ctx, repoDir, "HEAD")
	if err != nil {
		return nil, err
	}
	f := &Freshness{dir: repoDir, head: make(map[string]string, len(tree)), cache: map[string]int{}}
	for _, e := range tree {
		f.head[e.Path] = e.SHA
	}
	return f, nil
}

// Drift returns 0 when the entry is fresh — the blob at path on HEAD still
// equals its anchor — and otherwise N, the number of commits that touched
// path since the anchor. An entry with no anchor cannot drift.
func (f *Freshness) Drift(ctx context.Context, path, anchor string) int {
	if f == nil || anchor == "" {
		return 0
	}
	key := path + "\x00" + anchor
	if n, ok := f.cache[key]; ok {
		return n
	}
	n := f.drift(ctx, path, anchor)
	f.cache[key] = n
	return n
}

func (f *Freshness) drift(ctx context.Context, path, anchor string) int {
	if commitAnchorRE.MatchString(anchor) {
		n, err := gitx.CountSince(ctx, f.dir, anchor, path)
		if err != nil {
			return f.touching(ctx, path, "") // unknown commit: everything is since
		}
		return n
	}
	i := strings.LastIndexByte(anchor, '@')
	if i < 0 {
		return 0
	}
	apath, blob := anchor[:i], anchor[i+1:]
	if f.head[apath] == blob {
		return 0
	}
	return f.touching(ctx, apath, blob)
}

// touching counts the commits that touched path after the newest commit in
// which path held blob. If path never held blob, every touching commit counts.
func (f *Freshness) touching(ctx context.Context, path, blob string) int {
	args := []string{"log", "--format=%H"}
	if path != "" {
		args = append(args, "--", path)
	}
	out, err := gitx.Run(ctx, f.dir, args...)
	if err != nil {
		return 1
	}
	commits := strings.Fields(string(out))
	if blob != "" {
		for i, c := range commits {
			got, err := gitx.Run(ctx, f.dir, "rev-parse", "--verify", "--quiet", c+":"+path)
			if err == nil && strings.TrimSpace(string(got)) == blob {
				if i == 0 {
					return 1 // differs at HEAD without a touching commit: staged elsewhere
				}
				return i
			}
		}
	}
	if len(commits) == 0 {
		return 1
	}
	return len(commits)
}

// Hit is a ranked query result.
type Hit struct {
	Entry
	Drift      int     `json:"drift"`
	State      string  `json:"state"` // fresh | drift=N
	Superseded bool    `json:"superseded"`
	Score      float64 `json:"score"` // BM25; lower is better
	Snippet    string  `json:"snippet"`
}

// Query describes a search.
type Query struct {
	Text              string
	Tier              string // "" for all
	Path              string // "" for all; matches the path and everything under it
	IncludeSuperseded bool
	Limit             int
}

// ftsQuery turns free text into an FTS5 query: every word must match.
func ftsQuery(text string) (string, []string) {
	words := strings.FieldsFunc(text, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' })
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = `"` + w + `"`
	}
	return strings.Join(quoted, " "), words
}

func stateOf(drift int) string {
	if drift == 0 {
		return "fresh"
	}
	return fmt.Sprintf("drift=%d", drift)
}

func pathClause(path string) (string, []any) {
	path = strings.TrimSuffix(path, "/")
	if path == "" || path == "." {
		return "", nil
	}
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(path)
	return ` AND (e.path = ? OR e.path LIKE ? ESCAPE '\')`, []any{path, esc + "/%"}
}

func (l *Ledger) superseded(ctx context.Context) (map[string]bool, error) {
	rows, err := l.db.QueryContext(ctx, "SELECT DISTINCT supersedes FROM entries WHERE supersedes != ''")
	if err != nil {
		return nil, fmt.Errorf("ledger unreadable")
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out[s] = true
	}
	return out, rows.Err()
}

// isSuperseded: an entry is superseded when another entry names its id or
// the address of the Capsule it came from.
func isSuperseded(set map[string]bool, e Entry) bool {
	return set[e.ID] || (e.Capsule != "" && set[e.Capsule])
}

// Query ranks matches tier first, freshness second, BM25 third. Superseded
// entries rank last unless IncludeSuperseded is set.
func (l *Ledger) Query(ctx context.Context, q Query, fresh *Freshness) ([]Hit, error) {
	match, words := ftsQuery(q.Text)
	if match == "" {
		return nil, fmt.Errorf("query has no searchable words")
	}
	sqlText := `SELECT e.id,e.tier,e.kind,e.repo,e.path,e.anchor,e.intent,e.capsule,e.supersedes,e.body, bm25(entries_fts)
		FROM entries_fts JOIN entries e ON e.id = entries_fts.id WHERE entries_fts MATCH ?`
	args := []any{match}
	if q.Tier != "" {
		sqlText += " AND e.tier = ?"
		args = append(args, q.Tier)
	}
	clause, pargs := pathClause(q.Path)
	sqlText += clause
	args = append(args, pargs...)
	rows, err := l.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("ledger query failed")
	}
	defer rows.Close()
	var hits []Hit
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.ID, &h.Tier, &h.Kind, &h.Repo, &h.Path, &h.Anchor, &h.Intent, &h.Capsule, &h.Supersedes, &h.Body, &h.Score); err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	set, err := l.superseded(ctx)
	if err != nil {
		return nil, err
	}
	for i := range hits {
		h := &hits[i]
		h.Superseded = isSuperseded(set, h.Entry)
		h.Drift = fresh.Drift(ctx, h.Path, h.Anchor)
		h.State = stateOf(h.Drift)
		h.Snippet = snippet(h.Body, words)
	}
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if !q.IncludeSuperseded && a.Superseded != b.Superseded {
			return !a.Superseded
		}
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		if a.Drift != b.Drift {
			return a.Drift < b.Drift
		}
		if a.Score != b.Score {
			return a.Score < b.Score
		}
		return a.ID < b.ID
	})
	if q.Limit > 0 && len(hits) > q.Limit {
		hits = hits[:q.Limit]
	}
	return hits, nil
}

// snippet returns the first body line containing a query word, else the
// first non-empty line, collapsed and cut to 96 runes.
func snippet(body string, words []string) string {
	lines := strings.Split(body, "\n")
	pick := ""
	for _, line := range lines {
		low := strings.ToLower(line)
		for _, w := range words {
			if strings.Contains(low, strings.ToLower(w)) {
				pick = line
				break
			}
		}
		if pick != "" {
			break
		}
	}
	if pick == "" {
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				pick = line
				break
			}
		}
	}
	pick = oneLine(pick)
	if r := []rune(pick); len(r) > 96 {
		pick = string(r[:95]) + "…"
	}
	return pick
}

// MaxScent is the most pre-flight ever emits, in bytes.
const MaxScent = 2048

// ScentEntry is one line of scent.
type ScentEntry struct {
	Tier    string `json:"tier"`
	State   string `json:"state"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Source  string `json:"source"` // Capsule address, or the T0 anchor
	Scent   string `json:"scent"`
	Warning string `json:"warning,omitempty"`
	Why     string `json:"why,omitempty"` // command that resolves the provenance
}

// Scent is a pre-flight result.
type Scent struct {
	Schema    string       `json:"schema"`
	Repo      string       `json:"repo"`
	Paths     []string     `json:"paths"`
	Signature string       `json:"failure_signature,omitempty"`
	Total     int          `json:"total"` // entries that matched before the byte cap
	Entries   []ScentEntry `json:"entries"`
}

// Preflight gathers the highest-authority, freshest non-superseded entries
// for the target paths, plus any entry recording the same normalized failure
// signature. The same inputs and the same Ledger give the same Scent.
func (l *Ledger) Preflight(ctx context.Context, repo string, paths []string, failure string, fresh *Freshness) (*Scent, error) {
	clean := make([]string, 0, len(paths))
	for _, p := range paths {
		if p = strings.TrimSuffix(strings.TrimSpace(p), "/"); p != "" {
			clean = append(clean, p)
		}
	}
	sort.Strings(clean)
	sc := &Scent{Schema: "chimera.preflight/v1", Repo: repo, Paths: clean, Entries: []ScentEntry{}}
	if strings.TrimSpace(failure) != "" {
		sc.Signature = "sig:" + FailureSignature(failure)
	}
	set, err := l.superseded(ctx)
	if err != nil {
		return nil, err
	}
	type cand struct {
		Entry
		drift   int
		failure bool
	}
	seen := map[string]*cand{}
	collect := func(where string, args []any, isFailure bool) error {
		sqlText := "SELECT e.id,e.tier,e.kind,e.repo,e.path,e.anchor,e.intent,e.capsule,e.supersedes,e.body FROM entries e WHERE 1=1" + where
		if repo != "" {
			sqlText += " AND e.repo = ?"
			args = append(args, repo)
		}
		rows, err := l.db.QueryContext(ctx, sqlText, args...)
		if err != nil {
			return fmt.Errorf("ledger query failed")
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			if err := rows.Scan(&e.ID, &e.Tier, &e.Kind, &e.Repo, &e.Path, &e.Anchor, &e.Intent, &e.Capsule, &e.Supersedes, &e.Body); err != nil {
				return err
			}
			if isSuperseded(set, e) {
				continue
			}
			c, ok := seen[e.ID]
			if !ok {
				c = &cand{Entry: e}
				seen[e.ID] = c
			}
			c.failure = c.failure || isFailure
		}
		return rows.Err()
	}
	for _, p := range clean {
		clause, args := pathClause(p)
		if clause == "" {
			clause = " AND e.path != ''"
		}
		if err := collect(clause, args, false); err != nil {
			return nil, err
		}
	}
	if sc.Signature != "" {
		if err := collect(" AND instr(e.body, ?) > 0", []any{"failsig:" + strings.TrimPrefix(sc.Signature, "sig:")}, true); err != nil {
			return nil, err
		}
	}
	cands := make([]*cand, 0, len(seen))
	for _, c := range seen {
		c.drift = fresh.Drift(ctx, c.Path, c.Anchor)
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		if a.drift != b.drift {
			return a.drift < b.drift
		}
		if a.failure != b.failure {
			return a.failure
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.ID < b.ID
	})
	sc.Total = len(cands)
	for _, c := range cands {
		se := ScentEntry{Tier: c.Tier, State: stateOf(c.drift), Kind: c.Kind, Path: c.Path, Scent: scentLine(c.Entry)}
		if c.Capsule != "" {
			se.Source = c.Capsule
			fails := strings.Count(c.Body, " FAIL ")
			switch {
			case c.failure:
				se.Warning = "same failure signature recorded"
			case fails > 0:
				se.Warning = fmt.Sprintf("%d prior failing verdict(s)", fails)
			}
			if c.Path != "" {
				se.Why = "chimera why " + c.Path
			}
		} else {
			se.Source = c.Anchor
		}
		sc.Entries = append(sc.Entries, se)
	}
	return sc, nil
}

// scentLine picks the most useful single line of an entry: a failing verdict
// if the Capsule recorded one, else the first non-empty line.
func scentLine(e Entry) string {
	if e.Capsule != "" {
		for _, line := range strings.Split(e.Body, "\n") {
			if strings.Contains(line, " FAIL ") {
				return snippet(line, nil)
			}
		}
	}
	return snippet(e.Body, nil)
}

// Text renders the scent as aligned plain text of at most MaxScent bytes,
// dropping the lowest-ranked entries until it fits.
func (s *Scent) Text() string {
	return fit(s, func(c *Scent) []byte {
		var b strings.Builder
		fmt.Fprintf(&b, "PREFLIGHT  repo=%s  paths=%d  entries=%d/%d", orDash(c.Repo), len(c.Paths), len(c.Entries), c.Total)
		if c.Signature != "" {
			fmt.Fprintf(&b, "  failure=%s", c.Signature)
		}
		b.WriteString("\n")
		if len(c.Entries) == 0 {
			return []byte(b.String())
		}
		rows := [][]string{{"TIER", "STATE", "KIND", "PATH", "SOURCE", "SCENT"}}
		for _, e := range c.Entries {
			rows = append(rows, []string{e.Tier, e.State, e.Kind, orDash(e.Path), abbrevSource(e.Source), e.Scent})
		}
		b.WriteString(grid(rows))
		for _, e := range c.Entries {
			if e.Warning != "" {
				fmt.Fprintf(&b, "WARN  %s: %s in %s", orDash(e.Path), e.Warning, abbrevSource(e.Source))
				if e.Why != "" {
					fmt.Fprintf(&b, "; %s", e.Why)
				}
				b.WriteString("\n")
			}
		}
		return []byte(b.String())
	})
}

// JSON renders the scent as one JSON object of at most MaxScent bytes.
func (s *Scent) JSON() string {
	return fit(s, func(c *Scent) []byte {
		var b strings.Builder
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.Encode(c)
		return []byte(b.String())
	})
}

func fit(s *Scent, render func(*Scent) []byte) string {
	c := *s
	for {
		out := render(&c)
		if len(out) <= MaxScent || len(c.Entries) == 0 {
			if len(out) > MaxScent { // a pathological header: cut hard, stay valid UTF-8
				out = []byte(strings.ToValidUTF8(string(out[:MaxScent-1]), "") + "\n")
			}
			return string(out)
		}
		c.Entries = c.Entries[:len(c.Entries)-1]
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// abbrevSource shortens hashes to 12 hex characters for humans.
func abbrevSource(s string) string {
	if k, v, ok := strings.Cut(s, ":"); ok && k == "sha256" && len(v) > 12 {
		return k + ":" + v[:12]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 && len(s)-i-1 > 12 {
		return s[:i+13]
	}
	if commitAnchorRE.MatchString(s) {
		return s[:12]
	}
	return s
}

func grid(rows [][]string) string {
	var w []int
	for _, r := range rows {
		for i, cell := range r {
			if i >= len(w) {
				w = append(w, 0)
			}
			if n := len([]rune(cell)); n > w[i] {
				w[i] = n
			}
		}
	}
	var b strings.Builder
	for _, r := range rows {
		for i, cell := range r {
			if i == len(r)-1 {
				b.WriteString(cell)
				break
			}
			b.WriteString(cell + strings.Repeat(" ", w[i]-len([]rune(cell))) + "  ")
		}
		b.WriteString("\n")
	}
	return b.String()
}
