package trail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
	"chimera/pkg/trail/trailtest"
)

var update = flag.Bool("update", false, "rewrite testdata/golden from the current rendering")

func build(t *testing.T, f *trailtest.Fixture, base, head string, mod ...func(*Options)) *Report {
	t.Helper()
	o := Options{RepoDir: f.Dir, Repo: trailtest.Repo, Base: base, Head: head, Store: f.Store, Ring0: trailtest.Ring0, RiskGlob: trailtest.RiskGlob}
	for _, m := range mod {
		m(&o)
	}
	r, err := Build(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func reference(t *testing.T) (*trailtest.Reference, *Report) {
	t.Helper()
	ref := trailtest.NewReference(t)
	return ref, build(t, ref.Fixture, ref.Base, "HEAD")
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The fixture history is pinned: identity, dates, checkpoints, and times are
// fixed, so its commit SHAs and Capsule addresses are the same on every
// machine. The golden page depends on that.
func TestM2_1_FixtureHistoryIsDeterministic(t *testing.T) {
	a, b := trailtest.NewReference(t), trailtest.NewReference(t)
	if a.Head() != b.Head() || a.LintCapsule != b.LintCapsule || a.PushCapsule != b.PushCapsule || a.VerifyCapsule != b.VerifyCapsule || a.Intent != b.Intent {
		t.Fatalf("fixture differs between builds:\n%+v\n%+v", a, b)
	}
}

// TestM2_1_GoldenHTMLForFixtureHistory: the page rendered for the reference
// history is byte-identical to testdata/golden/index.html, obeys the
// platform rules of DESIGN.md §2.6, and every in-page link resolves.
func TestM2_1_GoldenHTMLForFixtureHistory(t *testing.T) {
	_, rep := reference(t)
	page, err := RenderHTML(rep)
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "golden", "index.html")
	if *update {
		if err := os.WriteFile(golden, page, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(page, want) {
		t.Fatalf("page differs from %s (run go test ./pkg/trail -run GoldenHTML -update after an intended change)\n%s", golden, firstDiff(string(want), string(page)))
	}
	html := string(page)

	// Platform rules: strict CSP, nothing inline, no script, nothing third-party, no narrator.
	for _, banned := range []string{"<style", "<script", " style=", "http://", "https://", "onclick", "javascript:", "Great news", "Here's", "Inter"} {
		if strings.Contains(html, banned) {
			t.Errorf("page contains %q", banned)
		}
	}
	for _, want := range []string{
		`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`,
		`<link rel="stylesheet" href="trail.css">`, `<link rel="icon" href="favicon.svg" type="image/svg+xml">`,
		`<p class="wordmark">chimera / trail</p>`,
		`<h1>acme/widget <span class="mono">` + rep.Base[:12] + `..` + rep.Head[:12] + `</span></h1>`,
		`<div><dt>Risk class</dt><dd><span class="risk risk-high">R3</span></dd></div>`,
		`<div><dt>Open risk</dt><dd class="num">4</dd></div>`, `<div><dt>Unmet intent</dt><dd class="num">2</dd></div>`,
		`<div><dt>Missing proof</dt><dd class="num">1</dd></div>`,
		`<div><dt>Verdicts</dt><dd class="num">6 <span class="muted">(4 pass, 1 fail, 1 stale)</span></dd></div>`,
		`<td class="mono">pkg/<wbr>objstore/<wbr>sigv4.go</td>`, `<td>Chimera-Intent, Chimera-Capsule</td>`,
		`<span class="state">FAIL</span>`, `<span class="state">STALE</span>`, `<span class="state">PENDING</span>`,
		`<video controls preload="metadata" width="640" height="360" src="media/`,
		`width="320" height="180" alt="Proof w-1-lint.png from capsule `,
		`<figcaption><span class="mono">w-2-push.mp4</span> · <span class="mono">[W-2]</span></figcaption>`,
		`<th scope="col">Commit</th><th scope="col">Subject</th><th scope="col">Capsule</th><th scope="col">Intent</th>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Failures first: the section order is fixed.
	pos := -1
	for _, id := range []string{"risk", "unmet", "missing", "verdicts", "media", "commits"} {
		i := strings.Index(html, `<section id="`+id+`"`)
		if i <= pos {
			t.Fatalf("section %s missing or out of order", id)
		}
		pos = i
	}
	if strings.Count(html, "<h1>") != 1 || strings.Count(html, "<h2 ") != 6 || strings.Count(html, "<details id=") != 3 {
		t.Error("headings or drill-downs")
	}
	// A Capsule's SVG is a document that can carry script: it is not rendered.
	if strings.Contains(html, "capsule-write.svg") {
		t.Error("a capsule SVG is on the page")
	}
	// One click: every fragment link lands on an element of the page, and
	// every verdict and risk row links to a transcript line or a capsule.
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		if ids[m[1]] {
			t.Errorf("duplicate id %q", m[1])
		}
		ids[m[1]] = true
	}
	links := regexp.MustCompile(` href="#([^"]+)"`).FindAllStringSubmatch(html, -1)
	if len(links) < 20 {
		t.Fatalf("%d fragment links", len(links))
	}
	for _, m := range links {
		if !ids[m[1]] {
			t.Errorf("link #%s resolves to nothing", m[1])
		}
	}
	verdicts := html[strings.Index(html, `<section id="verdicts"`):strings.Index(html, `<section id="media"`)]
	if n := strings.Count(verdicts, `<a href="#t-`); n != 6 {
		t.Errorf("%d of 6 verdicts link to a transcript line", n)
	}
	if strings.Index(verdicts, "FAIL") > strings.Index(verdicts, "STALE") || strings.Index(verdicts, "STALE") > strings.Index(verdicts, "PASS") {
		t.Error("verdicts are not ordered FAIL, STALE, PASS")
	}
	// Rendering is deterministic.
	if again, _ := RenderHTML(rep); !bytes.Equal(again, page) {
		t.Fatal("page is not deterministic")
	}
}

func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) && i < len(gl); i++ {
		if wl[i] != gl[i] {
			return fmt.Sprintf("line %d:\n- %s\n+ %s", i+1, wl[i], gl[i])
		}
	}
	return fmt.Sprintf("length: want %d lines, got %d", len(wl), len(gl))
}

// TestM2_1_CommitWithoutTrailersIsMissingProof: an untrailered commit is
// listed under missing proof, and so is a commit whose Capsule is not in the
// store, fails verification, or is bound to another Intent.
func TestM2_1_CommitWithoutTrailersIsMissingProof(t *testing.T) {
	ref, rep := reference(t)
	if len(rep.Missing) != 1 || rep.Missing[0].Commit != ref.Docs || rep.Missing[0].Subject != "docs: fix typo in push help" ||
		strings.Join(rep.Missing[0].Reasons, "|") != "Chimera-Intent, Chimera-Capsule" {
		t.Fatalf("missing proof: %+v", rep.Missing)
	}
	for _, c := range rep.Commits {
		if c.Missing != (c.SHA == ref.Docs) {
			t.Errorf("commit %s missing_proof=%v", c.SHA[:12], c.Missing)
		}
	}
	if rep.Check.State != StateFail {
		t.Fatalf("check %+v", rep.Check)
	}

	// A Capsule that never reached the store, an Intent trailer alone, a
	// malformed address, and a Capsule bound to a different Intent.
	f := ref.Fixture
	base := f.Head()
	ghost := f.Capsule(trailtest.CapsuleSpec{Intent: ref.Intent, BaseSHA: base, NoPush: true})
	c1 := f.Commit("a: cite a capsule that was never pushed", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(ref.Intent, ghost)...)
	c2 := f.Commit("a: intent only", map[string]string{"a.txt": "2\n"}, gitx.Trailer{Key: gitx.TrailerIntent, Value: ref.Intent})
	c3 := f.Commit("a: malformed address", map[string]string{"a.txt": "3\n"}, trailtest.Trailers(ref.Intent, "sha256:nothex")...)
	other := "task:" + strings.Repeat("ab", 32)
	c4 := f.Commit("a: capsule of another intent", map[string]string{"a.txt": "4\n"}, trailtest.Trailers(other, ref.LintCapsule)...)
	got := build(t, f, base, "HEAD")
	want := map[string]string{
		c1: "capsule sha256:" + ghost[7:19] + " not in store",
		c2: "Chimera-Capsule",
		c3: "Chimera-Capsule is not a capsule address",
		c4: "capsule sha256:" + ref.LintCapsule[7:19] + " is bound to intent " + ref.Intent[:18] + ", not to this commit's",
	}
	if len(got.Missing) != 4 {
		t.Fatalf("%+v", got.Missing)
	}
	for _, m := range got.Missing {
		if strings.Join(m.Reasons, "|") != want[m.Commit] {
			t.Errorf("%s: %q, want %q", m.Subject, m.Reasons, want[m.Commit])
		}
	}
	// The unknown task Intent has no manifest: spec drift cannot be decided, and says so.
	found := false
	for _, it := range got.OpenRisk {
		found = found || (it.Kind == "intent" && strings.Contains(it.Reason, "has no manifest in the store; spec drift cannot be decided"))
	}
	if !found {
		t.Errorf("no open-risk row for the unresolvable intent: %+v", got.OpenRisk)
	}
	page, err := RenderHTML(got)
	if err != nil || !strings.Contains(string(page), `<td class="mono">`+ghost[7:19]+`</td>`) || strings.Contains(string(page), `href="#cap-`+ghost[7:19]) {
		t.Errorf("a capsule that is not in the store must render unlinked (%v)", err)
	}

	// A stored member that no longer matches its hash: the Capsule is not proof.
	if n := f.Corrupt("/" + capsule.MemberVerdicts); n == 0 {
		t.Fatal("nothing corrupted")
	}
	bad := build(t, ref.Fixture, ref.Base, ref.Verify)
	if len(bad.Missing) != 4 || len(bad.Verdicts) != 0 || len(bad.Capsules) != 0 {
		t.Fatalf("tampered store: %d missing, %d verdicts", len(bad.Missing), len(bad.Verdicts))
	}
	for _, m := range bad.Missing {
		if m.Commit != ref.Docs && !strings.HasSuffix(m.Reasons[0], "failed verification (member verdicts.json)") {
			t.Errorf("%+v", m)
		}
	}
}

type downStore struct{ objstore.Store }

func (downStore) Get(context.Context, string) ([]byte, error) {
	return nil, &objstore.UnavailableError{Op: "GET", Key: "cas"}
}

// A store that does not answer is not "missing proof": the Trail cannot be
// decided, and Build says so with ErrUnavailable.
func TestM2_1_UnavailableStoreIsAnErrorNotAVerdict(t *testing.T) {
	ref := trailtest.NewReference(t)
	_, err := Build(context.Background(), Options{RepoDir: ref.Dir, Base: ref.Base, Head: "HEAD", Store: downStore{ref.Store}})
	if !errors.Is(err, objstore.ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Build(context.Background(), Options{RepoDir: ref.Dir, Base: "nope", Head: "HEAD", Store: ref.Store}); err == nil {
		t.Fatal("unknown revision accepted")
	}
	if _, err := Build(context.Background(), Options{RepoDir: ref.Dir, Base: ref.Base, Head: "HEAD"}); err == nil {
		t.Fatal("nil store accepted")
	}
}

// TestM2_1_Ring0PathEscalatesToR3: a Ring-0 path is always R3; a risk glob
// gives its class; width alone gives R2; an ordinary change is R1; nothing
// is R0.
func TestM2_1_Ring0PathEscalatesToR3(t *testing.T) {
	ref, rep := reference(t)
	if rep.Risk != "R3" {
		t.Fatalf("risk %s", rep.Risk)
	}
	var ring0, glob *RiskItem
	for i, it := range rep.OpenRisk {
		switch it.Path {
		case "verify/check.sh":
			ring0 = &rep.OpenRisk[i]
		case "pkg/objstore/sigv4.go":
			glob = &rep.OpenRisk[i]
		}
	}
	if ring0 == nil || ring0.Class != "R3" || ring0.Reason != "Ring-0 path changed" || ring0.Source.Capsule != ref.VerifyCapsule {
		t.Fatalf("ring-0 row: %+v", ring0)
	}
	// The risk-glob row links to the transcript line that names the path.
	if glob == nil || glob.Class != "R2" || glob.Reason != "matches risk glob pkg/objstore/**" || glob.Source != (Source{Capsule: ref.PushCapsule, Line: 2}) {
		t.Fatalf("risk-glob row: %+v", glob)
	}
	if rep.OpenRisk[0].Path != "verify/check.sh" {
		t.Errorf("R3 is not listed first: %+v", rep.OpenRisk)
	}
	classes := map[string]string{}
	for _, c := range rep.Commits {
		classes[c.SHA] = c.Risk
	}
	if classes[ref.Lint] != "R1" || classes[ref.Push] != "R2" || classes[ref.Docs] != "R1" || classes[ref.Verify] != "R3" {
		t.Errorf("per-commit classes: %v", classes)
	}

	// Without the Ring-0 commit the range is R2 (risk glob); without the glob it is R1.
	if r := build(t, ref.Fixture, ref.Base, ref.Docs); r.Risk != "R2" {
		t.Errorf("risk-glob range is %s", r.Risk)
	}
	plain := build(t, ref.Fixture, ref.Base, ref.Docs, func(o *Options) { o.RiskGlob = nil })
	if plain.Risk != "R1" {
		t.Errorf("ordinary range is %s", plain.Risk)
	}
	for _, it := range plain.OpenRisk {
		if it.Kind == "path" || it.Kind == "wide" {
			t.Errorf("R1 change listed as open risk: %+v", it)
		}
	}
	// An r3 risk glob escalates like Ring-0; an untrailered commit can do it too.
	r3 := build(t, ref.Fixture, ref.Push, ref.Docs, func(o *Options) {
		o.Ring0 = nil
		o.RiskGlob = func(p string) (string, string) {
			if p == "README.md" {
				return "R3", "README.md"
			}
			return "", ""
		}
	})
	if r3.Risk != "R3" || len(r3.OpenRisk) != 1 || r3.OpenRisk[0].Source != (Source{Commit: ref.Docs}) {
		t.Errorf("r3 glob on an untrailered commit: %s %+v", r3.Risk, r3.OpenRisk)
	}
	// An empty range is R0.
	if r := build(t, ref.Fixture, "HEAD", "HEAD"); r.Risk != "R0" || len(r.Commits) != 0 || r.Check.State != StatePass {
		t.Errorf("empty range: %s %+v", r.Risk, r.Check)
	}

	// Width: more than WideFiles files, WidePackages packages, or WideLines lines is R2.
	f := trailtest.New(t, map[string]string{"README.md": "# widget\n"})
	files := map[string]string{}
	for i := 0; i <= WideFiles; i++ {
		files[fmt.Sprintf("f%d.txt", i)] = "x\n"
	}
	manyFiles := f.Commit("many files", files)
	afterFiles := f.Head()
	dirs := map[string]string{}
	for i := 0; i <= WidePackages; i++ {
		dirs[fmt.Sprintf("d%d/x.txt", i)] = "x\n"
	}
	f.Commit("many packages", dirs)
	afterDirs := f.Head()
	f.Commit("many lines", map[string]string{"big.txt": strings.Repeat("line\n", WideLines+1)})
	afterLines := f.Head()
	f.Commit("small", map[string]string{"small.txt": "x\n"})
	for _, tc := range []struct{ base, head, want, row string }{
		{f.Base, manyFiles, "R2", "wide change: 6 files, 1 packages, 6 lines"},
		{afterFiles, afterDirs, "R2", "wide change: 4 files, 4 packages, 4 lines"},
		{afterDirs, afterLines, "R2", "wide change: 1 files, 1 packages, 201 lines"},
		{afterLines, "HEAD", "R1", ""},
	} {
		r := build(t, f, tc.base, tc.head)
		row := ""
		for _, it := range r.OpenRisk {
			if it.Kind == "wide" {
				row = it.Reason
			}
		}
		if r.Risk != tc.want || row != tc.row {
			t.Errorf("%s..%s: risk %s row %q, want %s %q", tc.base[:7], tc.head[:7], r.Risk, row, tc.want, tc.row)
		}
	}
}

// A lane that changed a Ring-0 path recorded a failing ring0 verdict; the
// range is R3 whatever its diff says, and the row is open risk.
func TestM2_1_FailingRing0VerdictIsR3(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	intent := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base,
		Transcript: []lane.Event{trailtest.VerdictEvent("ring0", "lane leaves Ring-0 paths unchanged", false)},
		Verdicts:   []capsule.Verdict{{ID: "ring0", Criterion: "lane leaves Ring-0 paths unchanged", Pass: false, Evidence: "changed: verify/check.sh"}},
		Paths:      []string{"a.txt"}})
	f.Commit("a: small change", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, addr)...)
	r := build(t, f, f.Base, "HEAD")
	if r.Risk != "R3" || r.Check.State != StateFail {
		t.Fatalf("risk %s check %s", r.Risk, r.Check.State)
	}
	var row *RiskItem
	for i, it := range r.OpenRisk {
		if it.Kind == "verdict" {
			row = &r.OpenRisk[i]
		}
	}
	if row == nil || row.Class != "R3" || row.Reason != "lane leaves Ring-0 paths unchanged: changed: verify/check.sh" || row.Source != (Source{Capsule: addr, Line: 1}) {
		t.Fatalf("%+v", row)
	}
}

// TestM2_1_SpecDriftFindsUnmetIntentAndOrphanProof: an acceptance ID with a
// failing criterion or with no verdict at all is unmet intent; a verdict
// citing an ID the Intent does not contain is orphan proof.
func TestM2_1_SpecDriftFindsUnmetIntentAndOrphanProof(t *testing.T) {
	ref, rep := reference(t)
	if len(rep.Intents) != 1 || rep.Intents[0] != ref.Intent {
		t.Fatalf("intents %v", rep.Intents)
	}
	if len(rep.Unmet) != 2 ||
		rep.Unmet[0] != (Unmet{ID: "[W-2]", Criterion: "Corrupted member makes get fail", State: StateFail, Intent: ref.Intent, Source: Source{Capsule: ref.PushCapsule, Line: 5}}) ||
		rep.Unmet[1] != (Unmet{ID: "[W-3]", Criterion: "no verdict in this range", State: StatePending, Intent: ref.Intent}) {
		t.Fatalf("unmet intent: %+v", rep.Unmet)
	}
	if len(rep.Orphans) != 1 || rep.Orphans[0].ID != "[X-9]" || rep.Orphans[0].Capsule != ref.PushCapsule || rep.Orphans[0].Source != (Source{Capsule: ref.PushCapsule, Line: 6}) {
		t.Fatalf("orphan proof: %+v", rep.Orphans)
	}
	states := map[string]string{}
	for _, v := range rep.Verdicts {
		states[v.ID+" "+v.Criterion] = v.State
	}
	if states["[X-9] Legacy export still works"] != StateStale || states["[W-2] Corrupted member makes get fail"] != StateFail ||
		states["[W-1] Unreadable denylist fails closed"] != StatePass || states["verifier verifier exits 0"] != StatePass {
		t.Fatalf("verdict states: %v", states)
	}
	if rep.Verdicts[0].State != StateFail || rep.Verdicts[1].State != StateStale {
		t.Errorf("failures are not first: %s, %s", rep.Verdicts[0].State, rep.Verdicts[1].State)
	}
	orphanRow := false
	for _, it := range rep.OpenRisk {
		orphanRow = orphanRow || (it.Kind == "orphan" && it.Reason == "orphan proof: [X-9] is not in intent "+ref.Intent[:18])
	}
	if !orphanRow {
		t.Errorf("orphan proof is not open risk: %+v", rep.OpenRisk)
	}
	if pass, fail, stale, sup := rep.Counts(); pass != 4 || fail != 1 || stale != 1 || sup != 0 {
		t.Errorf("counts %d %d %d %d", pass, fail, stale, sup)
	}
	if rep.Check.Title != "FAIL · risk R3 · 4 open risk · 2 unmet · 1 missing · 6 verdicts (4 pass, 1 fail, 1 stale)" ||
		rep.Check.Summary != "Risk class R3\nOpen risk 4\nUnmet intent 2\nMissing proof 1\nVerdicts 6: 4 pass, 1 fail, 1 stale" {
		t.Errorf("check: %+v", rep.Check)
	}

	// The newest verdict wins: a later Capsule that judges the same ID and
	// criterion again supersedes the failure, and [W-2] is met.
	f := ref.Fixture
	base := f.Head()
	fix := f.Capsule(trailtest.CapsuleSpec{Intent: ref.Intent, BaseSHA: base,
		Verdicts: []capsule.Verdict{{ID: "[W-2]", Criterion: "Corrupted member makes get fail", Pass: true}, {ID: "[W-3]", Criterion: "Query ranks by tier", Pass: true}},
		Paths:    []string{"pkg/objstore/get.go"}})
	f.Commit("capsule: fail get on a corrupted member", map[string]string{"pkg/objstore/get.go": "package objstore\n"}, trailtest.Trailers(ref.Intent, fix)...)
	fixed := build(t, f, ref.Base, "HEAD")
	if len(fixed.Unmet) != 0 {
		t.Fatalf("unmet after the fix: %+v", fixed.Unmet)
	}
	var old *Verdict
	for i, v := range fixed.Verdicts {
		if v.Criterion == "Corrupted member makes get fail" && v.Capsule == ref.PushCapsule {
			old = &fixed.Verdicts[i]
		}
	}
	if old == nil || old.SupersededBy != fix || old.State != StateFail {
		t.Fatalf("superseded verdict: %+v", old)
	}
	if last := fixed.Verdicts[len(fixed.Verdicts)-1]; last.SupersededBy == "" {
		t.Errorf("superseded verdict is not listed last: %+v", last)
	}
	if pass, fail, stale, sup := fixed.Counts(); pass != 6 || fail != 0 || stale != 1 || sup != 1 {
		t.Errorf("counts %d %d %d %d", pass, fail, stale, sup)
	}
	page, _ := RenderHTML(fixed)
	// The superseded failure is still a FAIL row: accent rule and all (DESIGN.md §2.5).
	if !strings.Contains(string(page), `<tr class="fail"><td class="mono">[W-2]</td><td>Corrupted member makes get fail <span class="muted">superseded by `+fix[7:19]+`</span></td><td><span class="state">FAIL</span>`) {
		t.Error("page does not mark the superseded verdict as a superseded FAIL row")
	}

	// A task Intent's acceptance IDs come from its manifest in the store.
	m := capsule.TaskManifest{Brief: "Restore the focus ring.\n- [NIT-1] focus ring is 2px accent\n- [NIT-2] no outline on hover", Repo: trailtest.Repo, BaseSHA: f.Head(),
		Verifier: capsule.TaskVerifier{Command: []string{"true"}, Timeout: "1s"}, Clause: "DESIGN.md §2.6"}
	task, err := capsule.PutTask(context.Background(), f.Store, m)
	if err != nil {
		t.Fatal(err)
	}
	tb := f.Head()
	tc := f.Capsule(trailtest.CapsuleSpec{Intent: task, BaseSHA: tb,
		Verdicts: []capsule.Verdict{{ID: "[NIT-1]", Criterion: "focus ring is 2px accent", Pass: true}, {ID: "[W-1]", Criterion: "a folio id under a task intent", Pass: true}},
		Paths:    []string{"ui.css"}})
	f.Commit("ui: restore the focus ring", map[string]string{"ui.css": "a:focus{}\n"}, trailtest.Trailers(task, tc)...)
	tr := build(t, f, tb, "HEAD")
	if len(tr.Unmet) != 1 || tr.Unmet[0].ID != "[NIT-2]" || tr.Unmet[0].State != StatePending || len(tr.Orphans) != 1 || tr.Orphans[0].ID != "[W-1]" {
		t.Fatalf("task intent drift: unmet %+v orphans %+v", tr.Unmet, tr.Orphans)
	}
	if tr.Check.State != StatePending {
		t.Errorf("check %s: no failure, but open risk and unmet intent", tr.Check.State)
	}
}

// A commit made against an older Folio is flagged: its Intent is not the
// Folio at head.
func TestM2_1_StaleFolioIntentIsOpenRisk(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	old := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: old, BaseSHA: f.Base, Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "c", Pass: true}}, Paths: []string{"a.txt"}})
	f.Commit("lint: work against the old folio", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(old, addr)...)
	f.Commit("folio: add an acceptance id", map[string]string{"PRODUCT.md": trailtest.BaseFiles()["PRODUCT.md"] + "\n**[W-4] Export.** Export is stable.\n"})
	r := build(t, f, f.Base, "HEAD")
	now := f.FolioIntent("HEAD")
	want := "intent " + old[:18] + " is not the Folio at head (" + now[:18] + ")"
	found := false
	for _, it := range r.OpenRisk {
		found = found || (it.Kind == "intent" && it.Reason == want)
	}
	ids := ""
	for _, u := range r.Unmet {
		ids += u.ID
	}
	// The current Folio decides what is unmet, including the ID it just gained.
	if !found || ids != "[W-2][W-3][W-4]" {
		t.Fatalf("open risk %+v, unmet %s", r.OpenRisk, ids)
	}
}

// TestM2_1_SquashPreservesTheTrailerUnion: squashing a branch writes the
// union of every source commit's trailers, de-duplicated, in original order,
// and the squashed commit still resolves to every Capsule.
func TestM2_1_SquashPreservesTheTrailerUnion(t *testing.T) {
	ctx := context.Background()
	ref := trailtest.NewReference(t)
	f := ref.Fixture
	f.Commit("docs: signed off", map[string]string{"NOTES.md": "notes\n"}, gitx.Trailer{Key: "Signed-off-by", Value: "Example <dev@example.com>"},
		gitx.Trailer{Key: gitx.TrailerIntent, Value: ref.Intent}, gitx.Trailer{Key: gitx.TrailerCapsule, Value: ref.LintCapsule})
	head := f.Head()
	sources, err := gitx.RangeCommits(ctx, f.Dir, ref.Base, head)
	if err != nil || len(sources) != 5 {
		t.Fatalf("%v %d", err, len(sources))
	}
	msg, err := SquashMessage(ctx, f.Dir, "widget: lint, push, verify", "Squash of five commits.", sources)
	if err != nil {
		t.Fatal(err)
	}
	wantTail := "Squash of five commits.\n\n" +
		"Chimera-Intent: " + ref.Intent + "\nChimera-Capsule: " + ref.LintCapsule + "\nChimera-Capsule: " + ref.PushCapsule +
		"\nChimera-Capsule: " + ref.VerifyCapsule + "\nSigned-off-by: Example <dev@example.com>\n"
	if !strings.HasPrefix(msg, "widget: lint, push, verify\n\n") || !strings.HasSuffix(msg, wantTail) {
		t.Fatalf("squash message:\n%s", msg)
	}
	// Really squash: one commit on the base with the head's tree.
	msgFile := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msgFile, []byte(msg), 0o644); err != nil {
		t.Fatal(err)
	}
	squashed := f.Git("commit-tree", head+"^{tree}", "-p", ref.Base, "-F", msgFile)
	got, err := gitx.CommitTrailers(ctx, f.Dir, squashed)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, tr := range got {
		lines = append(lines, tr.Key+": "+tr.Value)
	}
	if strings.Join(lines, "\n")+"\n" != strings.TrimPrefix(wantTail, "Squash of five commits.\n\n") {
		t.Fatalf("git reads back:\n%s", strings.Join(lines, "\n"))
	}
	// The union is exactly gitx.UnionTrailers of the sources.
	var sets [][]gitx.Trailer
	for _, c := range sources {
		sets = append(sets, c.Trailers)
	}
	if union := gitx.UnionTrailers(sets...); len(union) != len(got) {
		t.Fatalf("union %v, commit %v", union, got)
	}
	// The Trail of the squashed commit resolves all three Capsules through one commit.
	r := build(t, f, ref.Base, squashed)
	if len(r.Commits) != 1 || len(r.Commits[0].Capsules) != 3 || len(r.Capsules) != 3 || len(r.Missing) != 0 || len(r.Verdicts) != 6 {
		t.Fatalf("squashed trail: %d commits, capsules %v, %d missing, %d verdicts", len(r.Commits), r.Commits[0].Capsules, len(r.Missing), len(r.Verdicts))
	}
	// The squash swallowed two commits no Capsule covers — the untrailered docs
	// fix and the notes file. Trailers cannot launder them: the files they
	// changed are in no cited Capsule's diff, and the row says so.
	var uncovered []RiskItem
	for _, it := range r.OpenRisk {
		if it.Kind == "uncovered" {
			uncovered = append(uncovered, it)
		}
	}
	if len(uncovered) != 1 || uncovered[0].Reason != "2 paths not in any cited capsule's diff: NOTES.md, README.md" ||
		uncovered[0].Source != (Source{Capsule: ref.LintCapsule, Commit: squashed}) {
		t.Fatalf("uncovered rows: %+v", uncovered)
	}
	page, _ := RenderHTML(r)
	for _, a := range []string{ref.LintCapsule, ref.PushCapsule, ref.VerifyCapsule} {
		if !strings.Contains(string(page), `<a href="#cap-`+a[7:19]+`">`+a[7:19]+`</a>`) {
			t.Errorf("squashed commit row lacks capsule %s", a[7:19])
		}
	}
	// No sources, no trailers: the message is just the subject.
	if plain, err := SquashMessage(ctx, f.Dir, "subject", "", nil); err != nil || plain != "subject\n" {
		t.Fatalf("%q %v", plain, err)
	}
}

// TestM2_1_BundleShipsLockedAssetsAndCapsuleMediaByteExact: the bundle is
// index.html, the reference stylesheet plus the Trail rules, the Folio's
// favicon, fonts, and reference media byte for byte, and every Capsule media
// file byte for byte. No script.
func TestM2_1_BundleShipsLockedAssetsAndCapsuleMediaByteExact(t *testing.T) {
	ref, rep := reference(t)
	out := filepath.Join(t.TempDir(), "trail")
	if err := WriteBundle(out, rep); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if got := sha(read("favicon.svg")); got != "dc98e47e34fa87a7856088769013bd5a3ec2a631fbece9190cb8d6e7e165d7d5" {
		t.Errorf("favicon.svg sha256 %s", got)
	}
	for _, name := range lane.LockedAssets() {
		src, err := os.ReadFile(filepath.Join("..", "..", "folio", "assets", "trail-reference", filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(src, read(name)) {
			t.Errorf("%s differs from the Folio asset (%v)", name, err)
		}
	}
	refCSS, _ := os.ReadFile(filepath.Join("..", "..", "folio", "assets", "trail-reference", "trail.css"))
	css := read("trail.css")
	if !bytes.HasPrefix(css, refCSS) || !bytes.Contains(css[len(refCSS):], []byte("p.none {")) {
		t.Error("trail.css is not the reference stylesheet plus the trail rules")
	}
	extra := string(css[len(refCSS):])
	for _, banned := range []string{"#", "rgb", "shadow", "gradient", "Inter", "http", "@import", "border-radius"} {
		if strings.Contains(extra, banned) {
			t.Errorf("appended rules contain %q", banned)
		}
	}
	// Capsule media: named media/<capsule12>-<name>, byte-exact, with real dimensions.
	lint12, push12 := ref.LintCapsule[7:19], ref.PushCapsule[7:19]
	want := map[string]struct {
		data []byte
		w, h int
		kind string
		id   string
	}{
		"media/" + lint12 + "-w-1-lint.png": {trailtest.PNG(), 320, 180, "image", "[W-1]"},
		"media/" + push12 + "-w-2-push.mp4": {trailtest.MP4(640, 360), 640, 360, "video", "[W-2]"},
	}
	if len(rep.Media) != len(want) {
		t.Fatalf("media: %+v", rep.Media)
	}
	for _, m := range rep.Media {
		w, ok := want[m.File]
		if !ok {
			t.Fatalf("unexpected media %s", m.File)
		}
		if !bytes.Equal(read(m.File), w.data) || m.SHA256 != sha(w.data) || m.Size != int64(len(w.data)) {
			t.Errorf("%s is not byte-exact", m.File)
		}
		if m.Width != w.w || m.Height != w.h || m.Kind != w.kind || m.ID != w.id {
			t.Errorf("%s: %dx%d %s %s", m.File, m.Width, m.Height, m.Kind, m.ID)
		}
	}
	// The Capsule's SVG stays in the Capsule; the Folio's own reference SVG ships.
	if _, err := os.Stat(filepath.Join(out, "media", lint12+"-capsule-write.svg")); err == nil {
		t.Error("a capsule SVG was copied into the bundle")
	}
	// Exactly these files: no script, nothing else.
	var names []string
	filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(out, p)
			names = append(names, filepath.ToSlash(rel))
		}
		return nil
	})
	if len(names) != 2+len(lane.LockedAssets())+2 {
		t.Errorf("bundle files: %v", names)
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".js") {
			t.Errorf("bundle ships script %s", n)
		}
	}
	golden, _ := os.ReadFile(filepath.Join("testdata", "golden", "index.html"))
	if !bytes.Equal(read("index.html"), golden) {
		t.Error("bundle index.html differs from the golden page")
	}
	// Writing over an older page removes the older page's proof files from
	// media/ — and nothing else.
	stale := filepath.Join(out, "media", "000000000000-old-proof.png")
	keep := filepath.Join(out, "notes.txt")
	os.WriteFile(stale, []byte("old"), 0o644)
	os.WriteFile(keep, []byte("mine"), 0o644)
	os.MkdirAll(filepath.Join(out, "media", "dir"), 0o755)
	if err := WriteBundle(out, rep); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Error("stale media survived a rewrite")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("a file outside media/ was removed")
	}
	if _, err := os.Stat(filepath.Join(out, "media", "dir")); err != nil {
		t.Error("a directory inside media/ was removed")
	}
	if !bytes.Equal(read("media/capsule-write.svg"), trailtest.ReferenceSVG(t)) {
		t.Error("the locked reference media did not survive a rewrite")
	}
	// A report that lost its media bytes (decoded from JSON) cannot fake a bundle.
	raw, _ := json.Marshal(rep)
	var decoded Report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := WriteBundle(t.TempDir(), &decoded); err == nil {
		t.Error("bundle written without media bytes")
	}
}

// The JSON form is chimera.trail/v1: snake_case, full hashes, empty lists
// rather than nulls, and the same bytes for the same inputs.
func TestM2_1_JSONReportIsStableAndComplete(t *testing.T) {
	ref, rep := reference(t)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := json.Marshal(build(t, ref.Fixture, ref.Base, "HEAD"))
	if !bytes.Equal(raw, again) {
		t.Fatal("report is not deterministic")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema", "repo", "base", "head", "intents", "risk", "stats", "check", "open_risk", "unmet_intent", "missing_proof",
		"orphan_proof", "verdicts", "media", "commits", "capsules"} {
		if _, ok := obj[key]; !ok {
			t.Errorf("report lacks %q", key)
		}
	}
	if !strings.HasPrefix(string(raw), `{"schema":"chimera.trail/v1","repo":"acme/widget","base":"`+ref.Base+`","head":"`+ref.Head()+`"`) {
		t.Errorf("field order or full hashes: %.160s", raw)
	}
	empty, _ := json.Marshal(build(t, ref.Fixture, "HEAD", "HEAD"))
	if strings.Contains(string(empty), "null") {
		t.Errorf("empty report has nulls: %s", empty)
	}
	if rep.Stats != (Stats{Files: 4, Packages: 4, Lines: 10}) {
		t.Errorf("stats %+v", rep.Stats)
	}
}

// A long transcript keeps its tail and every line a row links to; the rest
// stays in the Capsule behind a gap row, and control bytes never reach the page.
func TestM2_1_LongTranscriptKeepsLinkTargetsAndElidesTheRest(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	intent := f.FolioIntent("HEAD")
	var events []lane.Event
	for i := 1; i <= 1000; i++ {
		events = append(events, trailtest.Output(fmt.Sprintf("line %d \x1b[31mred\x1b[0m <b>&amp;</b>", i)))
	}
	events[9] = trailtest.Output("edit pkg/objstore/sigv4.go")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Transcript: events,
		Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "c", Pass: true, Evidence: "transcript:500"}, {ID: "[W-2]", Criterion: "d", Pass: true, Evidence: "transcript:5000"}},
		Paths:    []string{"pkg/objstore/sigv4.go"}})
	f.Commit("objstore: change signing", map[string]string{"pkg/objstore/sigv4.go": "package objstore\n"}, trailtest.Trailers(intent, addr)...)
	r := build(t, f, f.Base, "HEAD")
	c := r.Capsules[0]
	if c.TranscriptLines != 1000 || len(c.Transcript) != 200+2+3 {
		t.Fatalf("%d lines kept of %d", len(c.Transcript), c.TranscriptLines)
	}
	if c.Transcript[0] != (Line{Gap: 9}) || c.Transcript[1].N != 10 || c.Transcript[2] != (Line{Gap: 489}) || c.Transcript[3].N != 500 || c.Transcript[4] != (Line{Gap: 300}) || c.Transcript[5].N != 801 {
		t.Fatalf("kept: %+v", c.Transcript[:6])
	}
	// Evidence naming a line the transcript does not have falls back to the capsule.
	for _, v := range r.Verdicts {
		if v.ID == "[W-2]" && v.Source != (Source{Capsule: addr}) {
			t.Errorf("out-of-range line: %+v", v.Source)
		}
	}
	page, err := RenderHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if strings.ContainsRune(html, 0x1b) || strings.Contains(html, "<b>") || !strings.Contains(html, "&lt;b&gt;&amp;amp;&lt;/b&gt;") {
		t.Error("transcript text is not sanitized and escaped")
	}
	if !strings.Contains(html, `<li class="gap"><span class="ln">…</span><code>489 lines in the capsule transcript</code></li>`) ||
		!strings.Contains(html, `<li id="t-`+addr[7:19]+`-500">`) || !strings.Contains(html, `href="#t-`+addr[7:19]+`-10">Transcript `+addr[7:19]+` line 10</a>`) {
		t.Error("gap rows or link targets")
	}
}

func TestM2_1_MediaDimensionsComeFromTheFileHeader(t *testing.T) {
	gif := append([]byte("GIF89a"), 0x40, 0x01, 0xb4, 0x00, 0, 0, 0)
	jpeg := []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x00, 0x00, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0xb4, 0x01, 0x40, 0x03, 0x01, 0x22, 0x00}
	webp := append([]byte("RIFF\x00\x00\x00\x00WEBPVP8X\x0a\x00\x00\x00\x00\x00\x00\x00"), 0x3f, 0x01, 0x00, 0xb3, 0x00, 0x00)
	// EBML header, then Segment → Tracks → TrackEntry → Video → PixelWidth 854, PixelHeight 480.
	video := []byte{0xe0, 0x88, 0xb0, 0x82, 0x03, 0x56, 0xba, 0x82, 0x01, 0xe0}
	entry := append([]byte{0xae, 0x80 | byte(len(video))}, video...)
	tracks := append([]byte{0x16, 0x54, 0xae, 0x6b, 0x80 | byte(len(entry))}, entry...)
	webm := append([]byte{0x1a, 0x45, 0xdf, 0xa3, 0x84, 0x42, 0x82, 0x81, 0x00, 0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, tracks...)
	for _, tc := range []struct {
		ext  string
		data []byte
		w, h int
	}{
		{".png", trailtest.PNG(), 320, 180}, {".gif", gif, 320, 180}, {".jpg", jpeg, 320, 180}, {".jpeg", jpeg, 320, 180}, {".webp", webp, 320, 180},
		{".mp4", trailtest.MP4(1440, 900), 1440, 900}, {".webm", webm, 854, 480},
		// Unreadable headers fall back to 16:9 rather than omit the attributes.
		{".png", []byte("not a png"), 1280, 720}, {".mp4", []byte{0, 0, 0, 1}, 1280, 720}, {".webm", []byte{0xff, 0xff}, 1280, 720},
	} {
		if w, h := dimensions(tc.ext, tc.data); w != tc.w || h != tc.h {
			t.Errorf("%s: %dx%d, want %dx%d", tc.ext, w, h, tc.w, tc.h)
		}
	}
}
