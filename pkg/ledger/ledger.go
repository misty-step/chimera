// Package ledger is Chimera's disposable index over the object store
// (PRODUCT.md §2.3): a SQLite database with FTS5, derived from exactly two
// sources — the Git tree (T0) and Capsule manifests (everything else) — and
// rebuildable from them at any time. It is never committed to Git.
package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite with FTS5

	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/objstore"
)

// Authority tiers. A lower tier never outranks a higher one; T0 is highest.
const (
	T0 = "T0" // live code, the Folio, owner rulings at HEAD
	T1 = "T1" // verified evidence: Capsules with verdicts, Bench results
	T2 = "T2" // distilled claims citing a T0 or T1 source
	T3 = "T3" // external or unverified material
)

// ValidTier reports whether s names a tier.
func ValidTier(s string) bool { return s == T0 || s == T1 || s == T2 || s == T3 }

// Entry is one row of the entries table.
type Entry struct {
	ID         string `json:"id"`
	Tier       string `json:"tier"`
	Kind       string `json:"kind"`
	Repo       string `json:"repo"`
	Path       string `json:"path"`
	Anchor     string `json:"anchor"` // "path@blob" or "<commit>"
	Intent     string `json:"intent"`
	Capsule    string `json:"capsule"`
	Supersedes string `json:"supersedes"`
	Body       string `json:"body"`
}

// Lane is one row of the lanes table: what one lane measured.
type Lane struct {
	Capsule       string   `json:"capsule"`
	Bench         string   `json:"bench"`
	Cell          string   `json:"cell"`
	K             int      `json:"k"`
	Model         string   `json:"model"`
	Harness       string   `json:"harness"`
	Effort        string   `json:"effort"`
	ContextPolicy string   `json:"context_policy"`
	PassRate      float64  `json:"pass_rate"`
	WallMS        int64    `json:"wall_ms"`
	CostUSD       *float64 `json:"cost_usd"`
}

// Claim is one row of a Capsule's claims.json: distilled or external
// material that rides in a Capsule so the Ledger stays rebuildable.
type Claim struct {
	Tier       string `json:"tier"` // T2 or T3
	Path       string `json:"path"`
	Anchor     string `json:"anchor"`
	Body       string `json:"body"`
	Cites      string `json:"cites"`
	Supersedes string `json:"supersedes"`
}

const schemaVersion = 1

const schemaSQL = `
CREATE TABLE entries(
  id TEXT PRIMARY KEY, tier TEXT NOT NULL, kind TEXT NOT NULL, repo TEXT NOT NULL, path TEXT NOT NULL,
  anchor TEXT NOT NULL, intent TEXT NOT NULL, capsule TEXT NOT NULL, supersedes TEXT NOT NULL, body TEXT NOT NULL);
CREATE INDEX entries_path ON entries(path);
CREATE INDEX entries_capsule ON entries(capsule);
CREATE VIRTUAL TABLE entries_fts USING fts5(body, path, id UNINDEXED, tokenize='unicode61');
CREATE TABLE lanes(
  capsule TEXT PRIMARY KEY, bench TEXT NOT NULL, cell TEXT NOT NULL, k INTEGER NOT NULL, model TEXT NOT NULL,
  harness TEXT NOT NULL, effort TEXT NOT NULL, context_policy TEXT NOT NULL, pass_rate REAL NOT NULL,
  wall_ms INTEGER NOT NULL, cost_usd REAL);
PRAGMA user_version = 1;
`

// Ledger is an open database.
type Ledger struct {
	db   *sql.DB
	path string
}

// Open opens the database at path, creating it and its schema if absent.
func Open(ctx context.Context, path string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("cannot create ledger directory")
	}
	// synchronous(OFF): the Ledger is derived and disposable, so durability
	// across a crash is worth nothing; a damaged file is rebuilt.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=synchronous(OFF)")
	if err != nil {
		return nil, fmt.Errorf("cannot open ledger")
	}
	db.SetMaxOpenConns(1)
	l := &Ledger{db: db, path: path}
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("not a ledger database; run 'chimera ledger rebuild'")
	}
	switch version {
	case 0:
		if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
			db.Close()
			return nil, fmt.Errorf("cannot create ledger schema; run 'chimera ledger rebuild'")
		}
	case schemaVersion:
	default:
		db.Close()
		return nil, fmt.Errorf("ledger schema v%d is not supported; run 'chimera ledger rebuild'", version)
	}
	return l, nil
}

// Close releases the database.
func (l *Ledger) Close() error { return l.db.Close() }

// Path returns the database file.
func (l *Ledger) Path() string { return l.path }

// Drop deletes the database file and its journals. The Ledger is derived:
// losing it costs compute, never knowledge.
func Drop(path string) error {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm"} {
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("cannot remove ledger")
		}
	}
	return nil
}

// Source names the two inputs the Ledger is derived from.
type Source struct {
	Repo    string         // name recorded on T0 entries
	RepoDir string         // Git work tree; "" skips T0
	Store   objstore.Store // nil skips Capsules
}

// Stats reports what an index pass did.
type Stats struct {
	T0Added    int `json:"t0_added"`
	T0Removed  int `json:"t0_removed"`
	Capsules   int `json:"capsules_added"`
	Rejected   int `json:"capsules_rejected"` // failed verification; not indexed
	EntryCount int `json:"entries"`
	LaneCount  int `json:"lanes"`
}

// Rebuild drops the database and replays both sources.
func Rebuild(ctx context.Context, path string, src Source) (*Ledger, Stats, error) {
	if err := Drop(path); err != nil {
		return nil, Stats{}, err
	}
	l, err := Open(ctx, path)
	if err != nil {
		return nil, Stats{}, err
	}
	st, err := l.Index(ctx, src)
	if err != nil {
		l.Close()
		return nil, st, err
	}
	return l, st, nil
}

// Index brings the T0 entries in line with HEAD and adds any Capsule in the
// store that is not yet indexed. Running it repeatedly converges on exactly
// what Rebuild would produce.
func (l *Ledger) Index(ctx context.Context, src Source) (Stats, error) {
	var st Stats
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return st, fmt.Errorf("ledger busy")
	}
	defer tx.Rollback()
	if src.RepoDir != "" {
		if err := indexTree(ctx, tx, src, &st); err != nil {
			return st, err
		}
	}
	if src.Store != nil {
		if err := indexCapsules(ctx, tx, src.Store, &st); err != nil {
			return st, err
		}
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM entries").Scan(&st.EntryCount); err != nil {
		return st, err
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM lanes").Scan(&st.LaneCount); err != nil {
		return st, err
	}
	if err := tx.Commit(); err != nil {
		return st, fmt.Errorf("ledger commit failed")
	}
	return st, nil
}

const maxDocBytes = 1 << 20

func shortHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

func t0Kind(path string) string {
	switch {
	case strings.HasPrefix(path, "folio/rulings/") && strings.HasSuffix(path, ".md"):
		return "ruling"
	case gitx.IsFolioPath(path):
		return "folio"
	}
	return "code"
}

func indexTree(ctx context.Context, tx *sql.Tx, src Source, st *Stats) error {
	tree, err := gitx.LsTree(ctx, src.RepoDir, "HEAD")
	if err != nil {
		return err
	}
	intent, _ := gitx.FolioIntent(ctx, src.RepoDir, "HEAD") // "" when the repo has no Folio
	// have maps id → anchor plus the recorded intent, so a Folio entry is
	// replaced when its own blob is unchanged but the Folio's identity moved.
	have := map[string]string{}
	rows, err := tx.QueryContext(ctx, "SELECT id, anchor, intent FROM entries WHERE tier = ? AND repo = ?", T0, src.Repo)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id, anchor, in string
		if err := rows.Scan(&id, &anchor, &in); err != nil {
			rows.Close()
			return err
		}
		have[id] = anchor + "\x00" + in
	}
	rows.Close()

	type doc struct {
		gitx.TreeEntry
		kind, intent, key string
	}
	want := map[string]doc{}
	var fetch []string
	for _, e := range tree {
		d := doc{TreeEntry: e, kind: t0Kind(e.Path)}
		if d.kind == "folio" {
			d.intent = intent
		}
		d.key = e.Path + "@" + e.SHA + "\x00" + d.intent
		id := "t0:" + shortHash(src.Repo, e.Path)
		want[id] = d
		if have[id] != d.key {
			fetch = append(fetch, e.SHA)
		}
	}
	for id, key := range have {
		if d, ok := want[id]; !ok || key != d.key {
			if err := deleteEntry(ctx, tx, id); err != nil {
				return err
			}
			delete(have, id)
			st.T0Removed++
		}
	}
	if len(fetch) == 0 {
		return nil
	}
	blobs, err := gitx.CatBlobs(ctx, src.RepoDir, fetch)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := want[id]
		if _, ok := have[id]; ok {
			continue
		}
		data, ok := blobs[d.SHA]
		if !ok || len(data) > maxDocBytes || bytes.IndexByte(data, 0) >= 0 {
			continue // binary or oversized blobs carry no searchable text
		}
		entry := Entry{ID: id, Tier: T0, Kind: d.kind, Repo: src.Repo, Path: d.Path, Anchor: d.Path + "@" + d.SHA, Intent: d.intent, Body: string(data)}
		if err := insertEntry(ctx, tx, entry); err != nil {
			return err
		}
		st.T0Added++
	}
	return nil
}

func insertEntry(ctx context.Context, tx *sql.Tx, e Entry) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO entries(id,tier,kind,repo,path,anchor,intent,capsule,supersedes,body) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		e.ID, e.Tier, e.Kind, e.Repo, e.Path, e.Anchor, e.Intent, e.Capsule, e.Supersedes, e.Body); err != nil {
		return fmt.Errorf("ledger insert failed")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO entries_fts(body, path, id) VALUES(?,?,?)`, e.Body, e.Path, e.ID); err != nil {
		return fmt.Errorf("ledger insert failed")
	}
	return nil
}

func deleteEntry(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM entries WHERE id = ?", id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM entries_fts WHERE id = ?", id)
	return err
}

func indexCapsules(ctx context.Context, tx *sql.Tx, store objstore.Store, st *Stats) error {
	addrs, err := capsule.List(ctx, store)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	rows, err := tx.QueryContext(ctx, "SELECT capsule FROM entries WHERE capsule != '' UNION SELECT capsule FROM lanes")
	if err != nil {
		return err
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			rows.Close()
			return err
		}
		known[c] = true
	}
	rows.Close()
	for _, addr := range addrs {
		if known[string(addr)] {
			continue
		}
		l, err := capsule.Get(ctx, store, addr)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			st.Rejected++ // a Capsule that does not verify is not evidence
			continue
		}
		entries, lane, err := Derive(l)
		if err != nil {
			st.Rejected++
			continue
		}
		for _, e := range entries {
			if err := insertEntry(ctx, tx, e); err != nil {
				return err
			}
		}
		if lane != nil {
			if _, err := tx.ExecContext(ctx, `INSERT INTO lanes(capsule,bench,cell,k,model,harness,effort,context_policy,pass_rate,wall_ms,cost_usd) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
				lane.Capsule, lane.Bench, lane.Cell, lane.K, lane.Model, lane.Harness, lane.Effort, lane.ContextPolicy, lane.PassRate, lane.WallMS, lane.CostUSD); err != nil {
				return fmt.Errorf("ledger insert failed")
			}
		}
		st.Capsules++
	}
	return nil
}

var (
	blobAnchorRE   = regexp.MustCompile(`^.+@[0-9a-f]{40}$`)
	commitAnchorRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	citeRE         = regexp.MustCompile(`^(sha256:[0-9a-f]{64}|folio:[0-9a-f]{64}|.+@[0-9a-f]{40})$`)
)

// Derive maps one verified Capsule to its Ledger rows. It depends on the
// Capsule alone, so replaying Capsules in any order yields the same Ledger.
func Derive(l *capsule.Local) ([]Entry, *Lane, error) {
	m := l.Manifest
	addr := string(l.Address)
	verdicts, err := l.Verdicts()
	if err != nil {
		return nil, nil, err
	}
	tier, kind := T3, "capsule"
	if len(verdicts) > 0 {
		tier = T1
	}
	if m.Tag("bench") != "" {
		kind = "bench"
	}
	var body strings.Builder
	passed := 0
	for _, v := range verdicts {
		state := "FAIL"
		if v.Pass {
			state = "PASS"
			passed++
		}
		fmt.Fprintf(&body, "%s %s %s", v.ID, state, oneLine(v.Criterion))
		if ev := oneLine(v.Evidence); ev != "" {
			fmt.Fprintf(&body, " — %s", ev)
		}
		body.WriteString("\n")
		if !v.Pass {
			// The signature is of the failure text itself (the evidence), so a
			// later pre-flight with the same failure finds this Capsule.
			text := v.Evidence
			if strings.TrimSpace(text) == "" {
				text = v.Criterion
			}
			fmt.Fprintf(&body, "failsig:%s\n", FailureSignature(text))
		}
	}
	lc := m.Lane
	if lc != (capsule.LaneConfig{}) {
		fmt.Fprintf(&body, "lane %s\n", strings.Join(nonEmpty(lc.Runner, lc.Model, lc.Harness, lc.Skill, lc.Effort, lc.ContextPolicy), " "))
	}
	if len(m.Tags) > 0 {
		fmt.Fprintf(&body, "tags %s\n", strings.Join(m.Tags, " "))
	}
	base := Entry{Tier: tier, Kind: kind, Repo: m.Repo, Intent: m.Intent, Capsule: addr, Supersedes: m.Tag("supersedes"), Body: body.String()}

	var entries []Entry
	touched := capsule.TouchedPaths(l.Members[capsule.MemberDiff])
	if len(touched) == 0 {
		e := base
		e.ID = "cap:" + shortHash(addr, "")
		if commitAnchorRE.MatchString(m.BaseSHA) {
			e.Anchor = m.BaseSHA
		}
		entries = append(entries, e)
	}
	for _, t := range touched {
		e := base
		e.ID = "cap:" + shortHash(addr, t.Path)
		e.Path = t.Path
		switch {
		case t.Blob != "":
			e.Anchor = t.Path + "@" + t.Blob
		case commitAnchorRE.MatchString(m.BaseSHA):
			e.Anchor = m.BaseSHA
		}
		entries = append(entries, e)
	}
	if raw, ok := l.Members[capsule.MemberClaims]; ok {
		var claims []Claim
		if err := json.Unmarshal(raw, &claims); err != nil {
			return nil, nil, fmt.Errorf("claims.json: malformed")
		}
		for i, c := range claims {
			e := Entry{ID: "claim:" + shortHash(addr, strconv.Itoa(i)), Tier: T3, Kind: "claim", Repo: m.Repo, Path: c.Path,
				Intent: m.Intent, Capsule: addr, Supersedes: c.Supersedes, Body: strings.TrimSpace(c.Body) + "\n"}
			if blobAnchorRE.MatchString(c.Anchor) || commitAnchorRE.MatchString(c.Anchor) {
				e.Anchor = c.Anchor
			}
			// A distilled claim must cite a T0 or T1 source; one that does
			// not is unverified material and stays T3.
			if c.Tier == T2 && citeRE.MatchString(c.Cites) {
				e.Tier = T2
			}
			if c.Cites != "" {
				e.Body += "cites " + c.Cites + "\n"
			}
			entries = append(entries, e)
		}
	}

	var lane *Lane
	metrics, hasMetrics := l.Metrics()
	if lc != (capsule.LaneConfig{}) || hasMetrics || m.Tag("bench") != "" {
		lane = &Lane{Capsule: addr, Bench: m.Tag("bench"), Cell: m.Tag("cell"), Model: lc.Model, Harness: lc.Harness,
			Effort: lc.Effort, ContextPolicy: lc.ContextPolicy}
		lane.K, _ = strconv.Atoi(m.Tag("k"))
		if len(verdicts) > 0 {
			lane.PassRate = float64(passed) / float64(len(verdicts))
		}
		if hasMetrics {
			lane.WallMS, lane.CostUSD = metrics.WallMS, metrics.CostUSD
		} else if a, errA := time.Parse(time.RFC3339, m.StartedAt); errA == nil {
			if b, errB := time.Parse(time.RFC3339, m.EndedAt); errB == nil {
				lane.WallMS = b.Sub(a).Milliseconds()
			}
		}
	}
	return entries, lane, nil
}

func nonEmpty(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

var (
	sigTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?|\b\d{2}:\d{2}:\d{2}(\.\d+)?\b`)
	sigTempPath  = regexp.MustCompile(`(/private)?/(tmp|var/tmp|var/folders)/[^\s:"')\]]*`)
	sigHex       = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b|\b[0-9a-f]{7,}\b`)
	sigDigits    = regexp.MustCompile(`\d+`)
)

// FailureSignature normalizes a failure text — timestamps, temp paths, hex
// runs, and digits stripped, whitespace collapsed — and hashes it, so the
// same failure seen on another run or machine has the same signature.
func FailureSignature(text string) string {
	s := sigTimestamp.ReplaceAllString(text, "")
	s = sigTempPath.ReplaceAllString(s, "")
	s = sigHex.ReplaceAllString(s, "")
	s = sigDigits.ReplaceAllString(s, "")
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// Dump writes the canonical dump: one canonical JSON object per line, every
// entry sorted by id, then every lane sorted by capsule. Two Ledgers with
// the same dump hold the same knowledge.
func (l *Ledger) Dump(ctx context.Context, w io.Writer) error {
	rows, err := l.db.QueryContext(ctx, "SELECT id,tier,kind,repo,path,anchor,intent,capsule,supersedes,body FROM entries ORDER BY id")
	if err != nil {
		return fmt.Errorf("ledger unreadable")
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Tier, &e.Kind, &e.Repo, &e.Path, &e.Anchor, &e.Intent, &e.Capsule, &e.Supersedes, &e.Body); err != nil {
			return err
		}
		if err := dumpLine(w, "entries", e); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	lanes, err := l.Lanes(ctx)
	if err != nil {
		return err
	}
	for _, ln := range lanes {
		if err := dumpLine(w, "lanes", ln); err != nil {
			return err
		}
	}
	return nil
}

func dumpLine(w io.Writer, table string, row any) error {
	raw, err := capsule.Canonical(map[string]any{"table": table, "row": row})
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// Lanes returns every lane row, sorted by capsule.
func (l *Ledger) Lanes(ctx context.Context) ([]Lane, error) {
	rows, err := l.db.QueryContext(ctx, "SELECT capsule,bench,cell,k,model,harness,effort,context_policy,pass_rate,wall_ms,cost_usd FROM lanes ORDER BY capsule")
	if err != nil {
		return nil, fmt.Errorf("ledger unreadable")
	}
	defer rows.Close()
	var out []Lane
	for rows.Next() {
		var ln Lane
		var cost sql.NullFloat64
		if err := rows.Scan(&ln.Capsule, &ln.Bench, &ln.Cell, &ln.K, &ln.Model, &ln.Harness, &ln.Effort, &ln.ContextPolicy, &ln.PassRate, &ln.WallMS, &cost); err != nil {
			return nil, err
		}
		if cost.Valid {
			ln.CostUSD = &cost.Float64
		}
		out = append(out, ln)
	}
	return out, rows.Err()
}

// Status summarizes the database.
type Status struct {
	Path     string         `json:"path"`
	Entries  int            `json:"entries"`
	Tiers    map[string]int `json:"tiers"`
	Capsules int            `json:"capsules"`
	Lanes    int            `json:"lanes"`
	Digest   string         `json:"digest"` // sha256 of the canonical dump
}

// Status counts rows per tier and hashes the canonical dump.
func (l *Ledger) Status(ctx context.Context) (Status, error) {
	st := Status{Path: l.path, Tiers: map[string]int{T0: 0, T1: 0, T2: 0, T3: 0}}
	rows, err := l.db.QueryContext(ctx, "SELECT tier, count(*) FROM entries GROUP BY tier")
	if err != nil {
		return st, fmt.Errorf("ledger unreadable")
	}
	for rows.Next() {
		var tier string
		var n int
		if err := rows.Scan(&tier, &n); err != nil {
			rows.Close()
			return st, err
		}
		st.Tiers[tier] = n
		st.Entries += n
	}
	rows.Close()
	if err := l.db.QueryRowContext(ctx, "SELECT count(DISTINCT capsule) FROM entries WHERE capsule != ''").Scan(&st.Capsules); err != nil {
		return st, err
	}
	if err := l.db.QueryRowContext(ctx, "SELECT count(*) FROM lanes").Scan(&st.Lanes); err != nil {
		return st, err
	}
	h := sha256.New()
	if err := l.Dump(ctx, h); err != nil {
		return st, err
	}
	st.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return st, nil
}
