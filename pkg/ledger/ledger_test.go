package ledger

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

const testIntent = "folio:9c1e000000000000000000000000000000000000000000000000000000000000"

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=Example", "-c", "user.email=dev@example.com"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", msg)
	return git(t, dir, "rev-parse", "HEAD")
}

func repo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	for name, body := range files {
		write(t, dir, name, body)
	}
	commit(t, dir, "fixture")
	return dir
}

type capSpec struct {
	verdicts []capsule.Verdict
	diff     string
	tags     []string
	claims   []Claim
	lane     capsule.LaneConfig
	metrics  *capsule.Metrics
	seq      int
}

// diffFor builds a git-format diff header naming the blob path holds in dir.
func diffFor(t *testing.T, dir string, paths ...string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range paths {
		blob := git(t, dir, "rev-parse", "HEAD:"+p)
		fmt.Fprintf(&b, "diff --git a/%s b/%s\nindex %s..%s 100644\n--- a/%s\n+++ b/%s\n", p, p, strings.Repeat("1", 40), blob, p, p)
	}
	return b.String()
}

func push(t *testing.T, store objstore.Store, s capSpec) capsule.Address {
	t.Helper()
	dir := t.TempDir()
	if s.verdicts != nil {
		raw, _ := json.Marshal(s.verdicts)
		write(t, dir, capsule.MemberVerdicts, string(raw))
	}
	if s.diff != "" {
		write(t, dir, capsule.MemberDiff, s.diff)
	}
	if s.claims != nil {
		raw, _ := json.Marshal(s.claims)
		write(t, dir, capsule.MemberClaims, string(raw))
	}
	if s.metrics != nil {
		raw, _ := json.Marshal(s.metrics)
		write(t, dir, capsule.MemberMetrics, string(raw))
	}
	ckpt, err := capsule.NewCheckpoint(time.UnixMilli(1700000000000 + int64(s.seq)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capsule.Pack(dir, capsule.Meta{Intent: testIntent, Checkpoint: ckpt, Repo: "acme/widget", Lane: s.lane, Tags: s.tags}); err != nil {
		t.Fatal(err)
	}
	res, err := capsule.Push(context.Background(), store, dir, secretscan.New(nil))
	if err != nil {
		t.Fatal(err)
	}
	return res.Address
}

func open(t *testing.T, src Source) *Ledger {
	t.Helper()
	l, _, err := Rebuild(context.Background(), filepath.Join(t.TempDir(), "ledger.db"), src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func fresh(t *testing.T, dir string) *Freshness {
	t.Helper()
	f, err := NewFreshness(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dumpSHA(t *testing.T, l *Ledger) string {
	t.Helper()
	h := sha256.New()
	if err := l.Dump(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestM1_3_TierOrderingHoldsAgainstBetterBM25(t *testing.T) {
	ctx := context.Background()
	// The T0 document mentions the word once in a long body (weak BM25); the
	// T1 and T3 entries are short and saturated with it (strong BM25).
	long := strings.Repeat("unrelated prose about widgets and gears.\n", 200) + "one mention of readback here.\n"
	dir := repo(t, map[string]string{"docs/long.md": long, "pkg/a.go": "package a\n"})
	store := objstore.NewDir(t.TempDir())
	strong := "readback readback readback readback"
	t1 := push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-2]", Criterion: strong, Pass: true, Evidence: strong}}, diff: diffFor(t, dir, "pkg/a.go"), seq: 1})
	t3 := push(t, store, capSpec{claims: []Claim{{Tier: T3, Path: "pkg/a.go", Body: strong + " " + strong}}, tags: []string{"note:" + strong}, seq: 2})
	t2 := push(t, store, capSpec{claims: []Claim{{Tier: T2, Path: "pkg/a.go", Body: strong, Cites: string(t1)}, {Tier: T2, Path: "pkg/a.go", Body: strong + " uncited"}}, seq: 3})
	l := open(t, Source{Repo: "acme/widget", RepoDir: dir, Store: store})

	hits, err := l.Query(ctx, Query{Text: "readback"}, fresh(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	var tiers []string
	for _, h := range hits {
		tiers = append(tiers, h.Tier)
	}
	// t3's capsule yields a T3 capsule entry and a T3 claim; t2's yields a T3
	// capsule entry (no searchable body), one cited T2 claim, one uncited → T3.
	if got := strings.Join(tiers, " "); got != "T0 T1 T2 T3 T3 T3" {
		t.Fatalf("tiers=%s", got)
	}
	if hits[0].Path != "docs/long.md" || hits[1].Capsule != string(t1) || hits[2].Capsule != string(t2) {
		t.Fatalf("%+v", hits[:3])
	}
	if !(hits[0].Score > hits[1].Score) {
		t.Fatalf("fixture is wrong: the T0 hit must have the worse BM25 (%.3f vs %.3f)", hits[0].Score, hits[1].Score)
	}
	_ = t3
	only, _ := l.Query(ctx, Query{Text: "readback", Tier: T1}, fresh(t, dir))
	if len(only) != 1 || only[0].Tier != T1 {
		t.Fatalf("--tier: %+v", only)
	}
	byPath, _ := l.Query(ctx, Query{Text: "readback", Path: "docs"}, fresh(t, dir))
	if len(byPath) != 1 || byPath[0].Path != "docs/long.md" {
		t.Fatalf("--path: %+v", byPath)
	}
	if _, err := l.Query(ctx, Query{Text: `"" -- *`}, nil); err == nil {
		t.Fatal("wordless query accepted")
	}
	// User text is data, never FTS5 syntax: operators and quotes are just words.
	if hits, err := l.Query(ctx, Query{Text: `readback" OR path:x NEAR(`}, nil); err != nil || len(hits) != 0 {
		t.Fatalf("FTS syntax leaked from user text: %v %d", err, len(hits))
	}
	if hits, err := l.Query(ctx, Query{Text: `"readback" *`}, nil); err != nil || len(hits) != 6 {
		t.Fatalf("quoted query: %v %d", err, len(hits))
	}
}

func TestM1_3_EditingAnchoredFileMarksDrift1(t *testing.T) {
	ctx := context.Background()
	dir := repo(t, map[string]string{"pkg/a.go": "package a\n", "pkg/b.go": "package b\n"})
	store := objstore.NewDir(t.TempDir())
	addr := push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "anchor holds", Pass: true}}, diff: diffFor(t, dir, "pkg/a.go", "pkg/b.go"), seq: 1})
	l := open(t, Source{Repo: "acme/widget", RepoDir: dir, Store: store})

	state := func() map[string]string {
		hits, err := l.Query(ctx, Query{Text: "anchor"}, fresh(t, dir))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, h := range hits {
			if h.Capsule == string(addr) {
				out[h.Path] = h.State
			}
		}
		return out
	}
	if got := state(); got["pkg/a.go"] != "fresh" || got["pkg/b.go"] != "fresh" {
		t.Fatalf("before edit: %v", got)
	}
	write(t, dir, "pkg/a.go", "package a\n\nvar X = 1\n")
	commit(t, dir, "edit a")
	if got := state(); got["pkg/a.go"] != "drift=1" || got["pkg/b.go"] != "fresh" {
		t.Fatalf("after one edit: %v", got)
	}
	write(t, dir, "pkg/a.go", "package a\n\nvar X = 2\n")
	commit(t, dir, "edit a again")
	write(t, dir, "README.md", "unrelated\n")
	commit(t, dir, "unrelated commit does not count")
	if got := state(); got["pkg/a.go"] != "drift=2" || got["pkg/b.go"] != "fresh" {
		t.Fatalf("after two edits: %v", got)
	}
	// The stale T0 row for the edited file drifts too until index runs.
	hits, _ := l.Query(ctx, Query{Text: "package", Path: "pkg/a.go", Tier: T0}, fresh(t, dir))
	if len(hits) != 1 || hits[0].State != "drift=2" {
		t.Fatalf("stale T0: %+v", hits)
	}
	if _, err := l.Index(ctx, Source{Repo: "acme/widget", RepoDir: dir, Store: store}); err != nil {
		t.Fatal(err)
	}
	hits, _ = l.Query(ctx, Query{Text: "package", Path: "pkg/a.go", Tier: T0}, fresh(t, dir))
	if len(hits) != 1 || hits[0].State != "fresh" {
		t.Fatalf("reindexed T0: %+v", hits)
	}
	// Fresh outranks drifted within a tier.
	ranked, _ := l.Query(ctx, Query{Text: "anchor", Tier: T1}, fresh(t, dir))
	if len(ranked) != 2 || ranked[0].Path != "pkg/b.go" || ranked[1].Path != "pkg/a.go" {
		t.Fatalf("freshness order: %+v", ranked)
	}
}

func TestM1_3_SupersededExcludedFromPreflightAndRankedLast(t *testing.T) {
	ctx := context.Background()
	dir := repo(t, map[string]string{"pkg/a.go": "package a\n"})
	store := objstore.NewDir(t.TempDir())
	old := push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "retry budget is three", Pass: true}}, diff: diffFor(t, dir, "pkg/a.go"), seq: 1})
	newer := push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "retry budget is five", Pass: true}}, diff: diffFor(t, dir, "pkg/a.go"),
		tags: []string{"supersedes:" + string(old)}, seq: 2})
	l := open(t, Source{Repo: "acme/widget", RepoDir: dir, Store: store})
	f := fresh(t, dir)

	sc, err := l.Preflight(ctx, "acme/widget", []string{"pkg/a.go"}, "", f)
	if err != nil {
		t.Fatal(err)
	}
	text := sc.Text()
	if strings.Contains(text, "three") || !strings.Contains(text, "five") || strings.Contains(text, old.Hex()[:12]) {
		t.Fatalf("superseded entry in pre-flight:\n%s", text)
	}
	hits, _ := l.Query(ctx, Query{Text: "retry budget"}, f)
	if len(hits) != 2 || hits[0].Capsule != string(newer) || !hits[1].Superseded || hits[1].Capsule != string(old) {
		t.Fatalf("%+v", hits)
	}
	// With --include-superseded the flag no longer demotes: ties fall to BM25/id.
	all, _ := l.Query(ctx, Query{Text: "retry budget three", IncludeSuperseded: true}, f)
	if len(all) != 1 || !all[0].Superseded {
		t.Fatalf("%+v", all)
	}
}

func TestM1_3_PreflightIsBoundedAndByteStable(t *testing.T) {
	ctx := context.Background()
	files := map[string]string{}
	var paths []string
	for i := 0; i < 60; i++ {
		p := fmt.Sprintf("pkg/mod%02d/a_rather_long_file_name_for_width_%02d.go", i, i)
		files[p] = fmt.Sprintf("package mod%02d\n", i)
		paths = append(paths, p)
	}
	dir := repo(t, files)
	store := objstore.NewDir(t.TempDir())
	failure := "panic at 2026-11-26T19:04:11Z in /tmp/lane-8841/x.go:42: bad hash 0xdeadbeef41 after 17 retries"
	push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "lane completes", Pass: false,
		Evidence: "panic at 2025-01-02T03:04:05Z in /tmp/lane-17/x.go:9: bad hash 0xabc123 after 3 retries"}}, diff: diffFor(t, dir, paths...), seq: 1})
	src := Source{Repo: "acme/widget", RepoDir: dir, Store: store}
	l := open(t, src)

	sc, err := l.Preflight(ctx, "acme/widget", []string{"pkg"}, failure, fresh(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	text, js := sc.Text(), sc.JSON()
	if len(text) > MaxScent || len(js) > MaxScent {
		t.Fatalf("scent is %d / %d bytes", len(text), len(js))
	}
	if sc.Total != 120 || !strings.Contains(text, "entries=") || !strings.Contains(text, "/120") {
		t.Fatalf("total=%d\n%s", sc.Total, text)
	}
	if !strings.HasPrefix(text, "PREFLIGHT  repo=acme/widget  paths=1  ") || !strings.Contains(text, "failure=sig:") {
		t.Fatalf("header:\n%s", text)
	}
	var decoded Scent
	if err := json.Unmarshal([]byte(js), &decoded); err != nil || decoded.Schema != "chimera.preflight/v1" || len(decoded.Entries) == 0 {
		t.Fatalf("json: %v %s", err, js)
	}
	// T0 outranks the T1 capsule rows, so the capped text is all T0 here.
	if !strings.Contains(text, "\nT0    fresh  code") {
		t.Fatalf("highest authority first:\n%s", text)
	}
	// Byte-stable: a second pass, and a rebuilt Ledger, emit identical bytes.
	again, _ := l.Preflight(ctx, "acme/widget", []string{"pkg"}, failure, fresh(t, dir))
	rebuilt := open(t, src)
	third, _ := rebuilt.Preflight(ctx, "acme/widget", []string{"pkg/"}, failure, fresh(t, dir))
	if again.Text() != text || third.Text() != text || again.JSON() != js || third.JSON() != js {
		t.Fatal("pre-flight output is not byte-stable")
	}
	// The failure signature finds the prior Capsule even with no path overlap,
	// and warns with a why pointer.
	bySig, _ := l.Preflight(ctx, "acme/widget", nil, failure, fresh(t, dir))
	out := bySig.Text()
	if bySig.Total != 60 || !strings.Contains(out, "WARN  ") || !strings.Contains(out, "same failure signature recorded") || !strings.Contains(out, "; chimera why pkg/mod00/") {
		t.Fatalf("failure-signature scent:\n%s", out)
	}
	if len(out) > MaxScent {
		t.Fatalf("%d bytes", len(out))
	}
	none, _ := l.Preflight(ctx, "acme/other", []string{"pkg"}, "", fresh(t, dir))
	if none.Total != 0 || none.Text() != "PREFLIGHT  repo=acme/other  paths=1  entries=0/0\n" {
		t.Fatalf("%q", none.Text())
	}
}

func TestM1_3_FailureSignatureStripsVolatileParts(t *testing.T) {
	a := FailureSignature("FAIL 2026-11-26T19:04:11Z /tmp/TestX123/001/out.log:42: got 0xDEADBEEF want 7f50448c688d (attempt 3)")
	b := FailureSignature("fail   2024-01-01 00:00:00  /var/folders/zz/abc/T/out.log:7: got 0x1 want abcdef0123456789 (attempt 12)")
	if a != b || len(a) != 16 {
		t.Fatalf("%s vs %s", a, b)
	}
	if FailureSignature("got 0x1 want true") == FailureSignature("got 0x1 want false") {
		t.Fatal("different failures share a signature")
	}
}

func TestM1_3_DropAndRebuildEquivalence(t *testing.T) {
	ctx := context.Background()
	dir := repo(t, map[string]string{"PRODUCT.md": "# product\n", "DESIGN.md": "# design\n", "pkg/a.go": "package a\n",
		"folio/rulings/001.md": "ruling: retries are capped\n", "logo.bin": "\x00\x01binary"})
	store := objstore.NewDir(t.TempDir())
	src := Source{Repo: "acme/widget", RepoDir: dir, Store: store}
	cost := 0.0125
	push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "first", Pass: true}}, diff: diffFor(t, dir, "pkg/a.go"), seq: 1,
		lane: capsule.LaneConfig{Model: "example-model", Harness: "example-agent", Effort: "high", ContextPolicy: "push", Runner: "local"},
		tags: []string{"bench:demo", "cell:abc123", "k:2"}, metrics: &capsule.Metrics{WallMS: 1420, CostUSD: &cost}})

	path := filepath.Join(t.TempDir(), "incremental.db")
	inc, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer inc.Close()
	st, err := inc.Index(ctx, src)
	if err != nil || st.T0Added != 4 || st.Capsules != 1 || st.LaneCount != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	// History moves: an edit, a deletion, an addition, and two more Capsules
	// (one failing, one with claims), indexed incrementally in two passes.
	write(t, dir, "pkg/a.go", "package a\n\nfunc A() {}\n")
	os.Remove(filepath.Join(dir, "DESIGN.md"))
	write(t, dir, "pkg/c.go", "package c\n")
	commit(t, dir, "move")
	push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "second", Pass: false, Evidence: "exit 1"}}, diff: diffFor(t, dir, "pkg/a.go", "pkg/c.go"), seq: 2})
	if st, err = inc.Index(ctx, src); err != nil || st.T0Added != 3 || st.T0Removed != 3 || st.Capsules != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	push(t, store, capSpec{claims: []Claim{{Tier: T2, Path: "pkg/a.go", Body: "A is exported", Cites: "pkg/a.go@" + git(t, dir, "rev-parse", "HEAD:pkg/a.go")}}, seq: 3})
	if _, err = inc.Index(ctx, src); err != nil {
		t.Fatal(err)
	}
	if st, _ = inc.Index(ctx, src); st.T0Added+st.T0Removed+st.Capsules != 0 {
		t.Fatalf("index is not idempotent: %+v", st)
	}

	rebuilt, rst, err := Rebuild(ctx, filepath.Join(t.TempDir(), "rebuilt.db"), src)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.Close()
	a, b := dumpSHA(t, inc), dumpSHA(t, rebuilt)
	if a != b {
		var da, db bytes.Buffer
		inc.Dump(ctx, &da)
		rebuilt.Dump(ctx, &db)
		t.Fatalf("incremental %s != rebuilt %s\n--- incremental\n%s--- rebuilt\n%s", a, b, da.String(), db.String())
	}
	if rst.EntryCount != st.EntryCount || rst.LaneCount != 1 || rst.Capsules != 3 {
		t.Fatalf("rebuilt %+v incremental %+v", rst, st)
	}
	// Rebuilding over an existing database drops it first.
	again, _, err := Rebuild(ctx, path, src)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if dumpSHA(t, again) != a {
		t.Fatal("rebuild in place differs")
	}
	status, err := again.Status(ctx)
	if err != nil || status.Digest != "sha256:"+a || status.Tiers[T0] != 4 || status.Tiers[T1] != 3 || status.Tiers[T2] != 1 || status.Tiers[T3] != 1 || status.Capsules != 3 {
		t.Fatalf("%+v %v", status, err)
	}
	lanes, _ := again.Lanes(ctx)
	if len(lanes) != 1 || lanes[0].Bench != "demo" || lanes[0].Cell != "abc123" || lanes[0].K != 2 || lanes[0].PassRate != 1 || lanes[0].WallMS != 1420 || lanes[0].CostUSD == nil || *lanes[0].CostUSD != cost {
		t.Fatalf("%+v", lanes)
	}
}

func TestM1_3_CorruptCapsuleIsNotIndexed(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := objstore.NewDir(root)
	addr := push(t, store, capSpec{verdicts: []capsule.Verdict{{ID: "[M1-3]", Criterion: "ok", Pass: true}}, seq: 1})
	p := filepath.Join(root, filepath.FromSlash(addr.Key(capsule.MemberVerdicts)))
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte("[]"), 0o644)
	l, st, err := Rebuild(ctx, filepath.Join(t.TempDir(), "l.db"), Source{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if st.Rejected != 1 || st.Capsules != 0 || st.EntryCount != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestM1_3_OpenRefusesForeignFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-ledger.db")
	os.WriteFile(p, []byte("this is not sqlite"), 0o644)
	if _, err := Open(context.Background(), p); err == nil {
		t.Fatal("opened a non-database")
	}
}
