package trail

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/trail/trailtest"
)

// smallFolio is a Folio that declares one acceptance ID, [W-1].
func smallFolio() map[string]string {
	return map[string]string{"PRODUCT.md": "# P\n\n**[W-1] Lint.** Clean.\n", "DESIGN.md": "# D\n", "a.txt": "0\n"}
}

func w1(pass bool) []capsule.Verdict {
	return []capsule.Verdict{{ID: "[W-1]", Criterion: "lint is clean", Pass: pass}}
}

func rows(r *Report, kind string) []RiskItem {
	var out []RiskItem
	for _, it := range r.OpenRisk {
		if it.Kind == kind {
			out = append(out, it)
		}
	}
	return out
}

func sh(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestM2_1_NoCommitCanHideFromTheTrail: a subject holding a record separator
// once split a commit out of the walk, and with it a Ring-0 change. Every
// commit of the range is on the Trail whatever bytes its subject holds, and
// those bytes never reach the report.
func TestM2_1_NoCommitCanHideFromTheTrail(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	sha := f.Commit("verify: quietly weaken\x1e", map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"})
	r := build(t, f, f.Base, "HEAD")
	if len(r.Commits) != 1 || r.Commits[0].SHA != sha || r.Risk != "R3" || r.Check.State != StateFail {
		t.Fatalf("commits %+v risk %s check %s", r.Commits, r.Risk, r.Check.State)
	}
	if len(r.Missing) != 1 || r.Missing[0].Commit != sha || r.Missing[0].Subject != "verify: quietly weaken" {
		t.Fatalf("missing proof: %+v", r.Missing)
	}
	if p := rows(r, "path"); len(p) != 1 || p[0].Path != "verify/check.sh" || p[0].Class != "R3" || p[0].Source != (Source{Commit: sha}) {
		t.Fatalf("ring-0 row: %+v", p)
	}
	page, err := RenderHTML(r)
	if err != nil || strings.ContainsAny(string(page), "\x1e\x1f\x1b") || !strings.Contains(string(page), "<td>verify: quietly weaken</td>") {
		t.Fatalf("page carries the separator or lost the subject (%v)", err)
	}
	// Alone or among other commits: still there.
	f.Commit("a\x1fb \x1e c", map[string]string{"a.txt": "1\n"})
	f.Commit("plain", map[string]string{"a.txt": "2\n"})
	if r := build(t, f, f.Base, "HEAD"); len(r.Commits) != 3 || len(r.Missing) != 3 {
		t.Fatalf("%d commits, %d missing", len(r.Commits), len(r.Missing))
	}
}

// TestM2_1_AnotherIntentsCapsuleDecidesNothingHere: a verdict answers only
// for the Intent its Capsule is bound to. A task Intent's passing [W-1]
// neither supersedes the Folio's failing [W-1] nor satisfies it — whether
// the task declares that ID or cites it as an orphan.
func TestM2_1_AnotherIntentsCapsuleDecidesNothingHere(t *testing.T) {
	for _, declares := range []bool{true, false} {
		f := trailtest.New(t, smallFolio())
		folio := f.FolioIntent("HEAD")
		fail := f.Capsule(trailtest.CapsuleSpec{Intent: folio, BaseSHA: f.Base, Verdicts: w1(false), Paths: []string{"a.txt"}})
		f.Commit("lint: not clean yet", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(folio, fail)...)
		m := capsule.TaskManifest{Brief: "Tidy.\n- [T-1] tidy", Repo: trailtest.Repo, BaseSHA: f.Head(), Verifier: capsule.TaskVerifier{Command: []string{"true"}, Timeout: "1s"}}
		if declares {
			m.Acceptance = []string{"[W-1]"}
		}
		task, err := capsule.PutTask(context.Background(), f.Store, m)
		if err != nil {
			t.Fatal(err)
		}
		other := f.Capsule(trailtest.CapsuleSpec{Intent: task, BaseSHA: f.Head(), Paths: []string{"a.txt"},
			Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "lint is clean", Pass: true}, {ID: "[T-1]", Criterion: "tidy", Pass: true}}})
		f.Commit("task: says lint is clean", map[string]string{"a.txt": "2\n"}, trailtest.Trailers(task, other)...)
		r := build(t, f, f.Base, "HEAD")
		if r.Check.State != StateFail {
			t.Fatalf("declares=%v: check %s, want FAIL", declares, r.Check.State)
		}
		for _, v := range r.Verdicts {
			if v.SupersededBy != "" {
				t.Errorf("declares=%v: %s %q of %s superseded by another intent's capsule", declares, v.ID, v.Criterion, v.Capsule[:19])
			}
		}
		if _, failN, staleN, _ := r.Counts(); failN != 1 || (staleN == 1) == declares {
			t.Errorf("declares=%v: %d fail, %d stale", declares, failN, staleN)
		}
		unmet := ""
		for _, u := range r.Unmet {
			unmet += u.ID + " " + u.State + " " + u.Intent[:5] + ";"
		}
		if !strings.HasPrefix(unmet, "[W-1] FAIL folio;") {
			t.Errorf("declares=%v: unmet %q", declares, unmet)
		}
	}
}

// TestM2_1_NewestVerdictWinsOnlyAlongAncestry: a verdict supersedes an older
// one only when its commit descends from the older one's. On two parallel
// branches both stand, so the answer cannot depend on which side was merged
// into which.
func TestM2_1_NewestVerdictWinsOnlyAlongAncestry(t *testing.T) {
	for _, order := range []string{"pass-into-fail", "fail-into-pass"} {
		f := trailtest.New(t, smallFolio())
		intent := f.FolioIntent("HEAD")
		pass := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(true), Paths: []string{"p.txt"}})
		fail := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(false), Paths: []string{"q.txt"}})
		f.Git("checkout", "-q", "-b", "p")
		f.Commit("pass side", map[string]string{"p.txt": "1\n"}, trailtest.Trailers(intent, pass)...)
		f.Git("checkout", "-q", "-b", "q", f.Base)
		f.Commit("fail side", map[string]string{"q.txt": "1\n"}, trailtest.Trailers(intent, fail)...)
		mergeCap := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: []capsule.Verdict{{ID: "verifier", Criterion: "verifier exits 0", Pass: true}}})
		msg, _ := gitx.MessageWithTrailers(context.Background(), f.Dir, "merge the two sides\n", trailtest.Trailers(intent, mergeCap))
		mf := filepath.Join(t.TempDir(), "m")
		os.WriteFile(mf, []byte(msg), 0o644)
		if order == "pass-into-fail" {
			f.Git("merge", "-q", "--no-ff", "-F", mf, "p")
		} else {
			f.Git("checkout", "-q", "p")
			f.Git("merge", "-q", "--no-ff", "-F", mf, "q")
		}
		r := build(t, f, f.Base, "HEAD")
		_, failN, _, sup := r.Counts()
		if r.Check.State != StateFail || failN != 1 || sup != 0 || len(r.Unmet) != 1 || r.Unmet[0].State != StateFail {
			t.Errorf("%s: check %s, %d fail, %d superseded, unmet %+v", order, r.Check.State, failN, sup, r.Unmet)
		}
		// A clean merge writes nothing itself: its own row is R0 and nothing is uncovered.
		if last := r.Commits[len(r.Commits)-1]; last.Risk != "R0" || last.Files != 0 || len(rows(r, "uncovered")) != 0 {
			t.Errorf("%s: merge row %+v, uncovered %+v", order, last, rows(r, "uncovered"))
		}
		// A fix on top of the merge descends from both sides and supersedes the failure.
		fix := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Head(), Verdicts: w1(true), Paths: []string{"a.txt"}})
		f.Commit("lint: clean", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, fix)...)
		fixed := build(t, f, f.Base, "HEAD")
		if _, failN, _, sup := fixed.Counts(); failN != 0 || sup != 2 || len(fixed.Unmet) != 0 || fixed.Check.State != StatePass {
			t.Errorf("%s after the fix: %d fail, %d superseded, unmet %+v, check %s", order, failN, sup, fixed.Unmet, fixed.Check.State)
		}
	}

	// Citing an old passing Capsule again does not make it newer than the
	// failure that came after it: a Capsule's place is its first citation.
	f := trailtest.New(t, smallFolio())
	intent := f.FolioIntent("HEAD")
	pass := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(true), Paths: []string{"a.txt"}})
	fail := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(false), Paths: []string{"a.txt"}})
	f.Commit("one", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, pass)...)
	f.Commit("two", map[string]string{"a.txt": "2\n"}, trailtest.Trailers(intent, fail)...)
	f.Commit("three: replay the old pass", map[string]string{"a.txt": "3\n"}, trailtest.Trailers(intent, pass)...)
	r := build(t, f, f.Base, "HEAD")
	if _, failN, _, sup := r.Counts(); r.Check.State != StateFail || failN != 1 || sup != 1 {
		t.Fatalf("replay: check %s, %d fail, %d superseded", r.Check.State, failN, sup)
	}
}

// TestM2_1_AcceptanceIDRemovedFromTheFolioIsOpenRisk: an ID deleted from the
// Folio inside the range can no longer be unmet, so the deletion itself is
// listed, linked to the commit that edited the Folio.
func TestM2_1_AcceptanceIDRemovedFromTheFolioIsOpenRisk(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	f.Write(map[string]string{"PRODUCT.md": "# Widget — PRODUCT\n\n**[W-1] Lint.** Lint output never contains the matched term.\n"})
	f.Git("add", "-A")
	tree := f.Git("write-tree")
	newIntent, err := gitx.FolioIntent(context.Background(), f.Dir, tree)
	if err != nil {
		t.Fatal(err)
	}
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: newIntent, BaseSHA: f.Base, Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "c", Pass: true}}, Paths: []string{"PRODUCT.md"}})
	sha := f.Commit("folio: tidy", nil, trailtest.Trailers(newIntent, addr)...)
	r := build(t, f, f.Base, "HEAD")
	got := rows(r, "intent")
	if len(got) != 2 || got[0].Reason != "acceptance ID [W-2] was removed from the Folio in this range" ||
		got[1].Reason != "acceptance ID [W-3] was removed from the Folio in this range" || got[0].Path != "PRODUCT.md" || got[0].Source != (Source{Capsule: addr}) {
		t.Fatalf("intent rows: %+v", got)
	}
	if len(r.Unmet) != 0 || r.Check.State != StatePending || r.Commits[0].SHA != sha {
		t.Fatalf("unmet %+v check %s", r.Unmet, r.Check.State)
	}
	// Adding an ID is not a removal.
	f.Commit("folio: add", map[string]string{"PRODUCT.md": "# P\n\n**[W-1] Lint.** x\n\n**[W-9] New.** y\n"})
	if r := build(t, f, sha, "HEAD"); len(rows(r, "intent")) != 0 {
		t.Fatalf("an added ID was reported as removed: %+v", r.OpenRisk)
	}
}

// TestM2_1_RangeIsJudgedFromTheMergeBase: what base gained on its own since
// the branch point is not the range's blast radius; unrelated histories and
// a shallow clone that cuts the range are refused outright.
func TestM2_1_RangeIsJudgedFromTheMergeBase(t *testing.T) {
	f := trailtest.New(t, trailtest.BaseFiles())
	intent := f.FolioIntent("HEAD")
	f.Git("checkout", "-q", "-b", "feature")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Paths: []string{"a.txt"},
		Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "c", Pass: true}, {ID: "[W-2]", Criterion: "c", Pass: true}, {ID: "[W-3]", Criterion: "c", Pass: true}}})
	f.Commit("feature: small", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, addr)...)
	f.Git("checkout", "-q", "main")
	files := map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"}
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("m%d/x.txt", i)] = "x\n"
	}
	f.Commit("main: an approved ring-0 change", files)
	r := build(t, f, "main", "feature")
	if r.Risk != "R1" || len(r.OpenRisk) != 0 || r.Stats != (Stats{Files: 1, Packages: 1, Lines: 1}) || r.Check.State != StatePass {
		t.Fatalf("risk %s stats %+v open risk %+v check %s", r.Risk, r.Stats, r.OpenRisk, r.Check.State)
	}

	// Two histories with no common commit.
	f.Git("checkout", "-q", "--orphan", "island")
	f.Commit("island", map[string]string{"i.txt": "1\n"})
	_, err := Build(context.Background(), Options{RepoDir: f.Dir, Base: "main", Head: "island", Store: f.Store})
	if err == nil || err.Error() != "main and island share no history" {
		t.Fatalf("unrelated histories: %v", err)
	}
}

func TestM2_1_ShallowHistoryIsRefused(t *testing.T) {
	ref := trailtest.NewReference(t)
	dst := t.TempDir()
	sh(t, ref.Dir, "git", "config", "uploadpack.allowAnySHA1InWant", "true")
	sh(t, dst, "git", "clone", "-q", "--depth", "1", "file://"+ref.Dir, "c")
	clone := filepath.Join(dst, "c")
	sh(t, clone, "git", "fetch", "-q", "--depth", "1", "origin", ref.Base)
	o := Options{RepoDir: clone, Base: ref.Base, Head: "HEAD", Store: ref.Store, Ring0: trailtest.Ring0, RiskGlob: trailtest.RiskGlob}
	r, err := Build(context.Background(), o)
	if err == nil || err.Error() != "history is shallow at "+ref.Verify[:12]+"; fetch the full range" {
		t.Fatalf("shallow clone: %v (report %+v)", err, r)
	}
	// With the whole range fetched the same clone gives the same Trail as the origin.
	sh(t, clone, "git", "fetch", "-q", "--unshallow", "origin")
	got, err := Build(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	want := build(t, ref.Fixture, ref.Base, "HEAD")
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != strings.Replace(string(b), `"repo":"acme/widget"`, `"repo":""`, 1) {
		t.Fatal("the unshallowed clone's trail differs from the origin's")
	}
}

// TestM2_1_PathsOutsideTheCitedCapsulesDiffAreOpenRisk: a Capsule is proof
// of the change its diff records. A commit that changes more than its
// Capsules' diffs cover — by hand, or by citing a Capsule made for another
// change — gets one open-risk row naming the files.
func TestM2_1_PathsOutsideTheCitedCapsulesDiffAreOpenRisk(t *testing.T) {
	f := trailtest.New(t, smallFolio())
	intent := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(true), Paths: []string{"a.txt"}})
	covered := f.Commit("covered", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, addr)...)
	if r := build(t, f, f.Base, covered); len(r.OpenRisk) != 0 || r.Check.State != StatePass {
		t.Fatalf("a covered commit: %+v %s", r.OpenRisk, r.Check.State)
	}
	// The same Capsule cited by a commit that also edits other files.
	files := map[string]string{"a.txt": "2\n"}
	for i := 1; i <= 7; i++ {
		files[fmt.Sprintf("extra%d.txt", i)] = "x\n"
	}
	wide := f.Commit("covered plus seven by hand", files, trailtest.Trailers(intent, addr)...)
	r := build(t, f, covered, wide)
	got := rows(r, "uncovered")
	if len(got) != 1 || got[0].Reason != "7 paths not in any cited capsule's diff: extra1.txt, extra2.txt, extra3.txt, extra4.txt, extra5.txt, …" ||
		got[0].Class != "" || got[0].Source != (Source{Capsule: addr, Commit: wide}) {
		t.Fatalf("uncovered: %+v", got)
	}
	if len(r.Missing) != 0 || r.Check.State != StatePending {
		t.Fatalf("uncovered paths are open risk, not missing proof: %+v %s", r.Missing, r.Check.State)
	}
	// One path, singular; and a Capsule with no diff at all covers nothing.
	bare := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Head(), Verdicts: w1(true)})
	one := f.Commit("no diff in the capsule", map[string]string{"a.txt": "3\n"}, trailtest.Trailers(intent, bare)...)
	if got := rows(build(t, f, wide, one), "uncovered"); len(got) != 1 || got[0].Reason != "1 path not in any cited capsule's diff: a.txt" {
		t.Fatalf("%+v", got)
	}
	// The row is one click from the Capsule on the page.
	page, _ := RenderHTML(build(t, f, wide, one))
	if !strings.Contains(string(page), `<td>1 path not in any cited capsule&#39;s diff: a.txt</td><td><a href="#cap-`+bare[7:19]+`">Capsule `+bare[7:19]+`</a></td>`) {
		t.Error("uncovered row does not link to the capsule")
	}
}

// TestM2_1_CapsuleWithoutVerdictsIsMissingProof: a Capsule that judged
// nothing proves nothing. No verdicts.json, a malformed one, or an empty
// list all fail closed, so a range never passes on zero verdicts.
func TestM2_1_CapsuleWithoutVerdictsIsMissingProof(t *testing.T) {
	for name, spec := range map[string]trailtest.CapsuleSpec{
		"empty":     {Verdicts: []capsule.Verdict{}},
		"absent":    {NoVerdicts: true},
		"malformed": {RawVerdicts: []byte("{not a list")},
	} {
		f := trailtest.New(t, map[string]string{"a.txt": "0\n"})
		m := capsule.TaskManifest{Brief: "No acceptance IDs at all.", Repo: trailtest.Repo, BaseSHA: f.Base, Verifier: capsule.TaskVerifier{Command: []string{"true"}, Timeout: "1s"}}
		task, err := capsule.PutTask(context.Background(), f.Store, m)
		if err != nil {
			t.Fatal(err)
		}
		spec.Intent, spec.BaseSHA, spec.Paths = task, f.Base, []string{"a.txt"}
		addr := f.Capsule(spec)
		sha := f.Commit("a: change", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(task, addr)...)
		r := build(t, f, f.Base, "HEAD")
		if len(r.Missing) != 1 || r.Missing[0].Commit != sha || strings.Join(r.Missing[0].Reasons, "|") != "capsule sha256:"+addr[7:19]+" carries no verdicts" ||
			r.Check.State != StateFail || len(r.Verdicts) != 0 {
			t.Errorf("%s: missing %+v check %s", name, r.Missing, r.Check.State)
		}
	}
}

// TestM2_1_Ring0IsR3HoweverThePathIsTouched: rename out, rename in, delete,
// a mode-only change, a change reverted inside the range, a merge that edits
// the file by hand, and a change in an untrailered commit are all R3.
func TestM2_1_Ring0IsR3HoweverThePathIsTouched(t *testing.T) {
	mk := func() *trailtest.Fixture { return trailtest.New(t, trailtest.BaseFiles()) }
	check := func(name string, f *trailtest.Fixture, path string, rangeR3 bool) *Report {
		t.Helper()
		r := build(t, f, f.Base, "HEAD")
		found := false
		for _, it := range rows(r, "path") {
			found = found || (it.Path == path && it.Class == "R3" && it.Reason == "Ring-0 path changed")
		}
		if r.Risk != "R3" || !found {
			t.Errorf("%s: risk %s, open risk %+v", name, r.Risk, r.OpenRisk)
		}
		return r
	}
	f := mk()
	sh(t, f.Dir, "chmod", "+x", "verify/check.sh")
	f.Commit("mode only", nil)
	check("mode-only", f, "verify/check.sh", true)

	f = mk()
	sh(t, f.Dir, "mkdir", "tools")
	sh(t, f.Dir, "git", "mv", "verify/check.sh", "tools/check.sh")
	f.Commit("rename out", nil)
	check("rename-out", f, "verify/check.sh", true)

	f = mk()
	sh(t, f.Dir, "git", "mv", "cmd/widget/main.go", "verify/main.go")
	f.Commit("rename in", nil)
	check("rename-in", f, "verify/main.go", true)

	f = mk()
	sh(t, f.Dir, "git", "rm", "-q", "verify/check.sh")
	f.Commit("delete", nil)
	check("delete", f, "verify/check.sh", true)

	// Touched then put back: the range diff is empty for the file, the commits are not.
	f = mk()
	f.Commit("touch", map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"})
	f.Commit("revert", map[string]string{"verify/check.sh": trailtest.BaseFiles()["verify/check.sh"]})
	r := check("touch-then-revert", f, "verify/check.sh", true)
	if r.Stats.Files != 0 || len(r.Missing) != 2 {
		t.Errorf("touch-then-revert: stats %+v, %d missing", r.Stats, len(r.Missing))
	}

	// A merge that edits the Ring-0 file by hand: its own row says R3.
	f = mk()
	f.Git("checkout", "-q", "-b", "side")
	f.Commit("side", map[string]string{"s.txt": "1\n"})
	f.Git("checkout", "-q", "main")
	f.Commit("main", map[string]string{"m.txt": "1\n"})
	f.Git("merge", "-q", "--no-ff", "--no-commit", "side")
	f.Write(map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"})
	f.Git("add", "-A")
	f.Git("commit", "-q", "-m", "Merge side")
	r = check("evil-merge", f, "verify/check.sh", true)
	if last := r.Commits[len(r.Commits)-1]; last.Risk != "R3" || last.Files != 1 {
		t.Errorf("evil merge row: %+v", last)
	}

	// Odd path names are still Ring-0, and still safe on the page.
	f = mk()
	f.Commit("odd names", map[string]string{"verify/ü \"q\" <b>.sh": "x\n"})
	r = check("odd-name", f, "verify/ü \"q\" <b>.sh", true)
	page, _ := RenderHTML(r)
	if strings.Contains(string(page), "<b>.sh") || !strings.Contains(string(page), "verify/<wbr>ü &#34;q&#34; &lt;b&gt;.sh") {
		t.Error("odd path is not escaped on the page")
	}
}

// TestM2_1_WideCommitInsideANarrowRangeIsListed: a commit that adds what a
// later one removes leaves a small range diff. The class is still R2, and a
// row says which commit made it so.
func TestM2_1_WideCommitInsideANarrowRangeIsListed(t *testing.T) {
	f := trailtest.New(t, smallFolio())
	intent := f.FolioIntent("HEAD")
	a := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: w1(true), Paths: []string{"a.txt", "big.txt"}})
	add := f.Commit("add big", map[string]string{"big.txt": strings.Repeat("l\n", 1000)}, trailtest.Trailers(intent, a)...)
	os.Remove(filepath.Join(f.Dir, "big.txt"))
	rm := f.Commit("rm big", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, a)...)
	r := build(t, f, f.Base, "HEAD")
	got := rows(r, "wide")
	if r.Risk != "R2" || r.Stats.Lines != 2 || len(got) != 2 ||
		got[0].Reason != "wide commit "+add[:12]+": 1 files, 1 packages, 1000 lines" || got[0].Class != "R2" ||
		got[1].Reason != "wide commit "+rm[:12]+": 2 files, 1 packages, 1002 lines" || r.Check.State != StatePending {
		t.Fatalf("risk %s stats %+v rows %+v check %s", r.Risk, r.Stats, got, r.Check.State)
	}
}

// TestM2_1_ControlBytesNeverReachTheReport: every string that comes from Git
// or a Capsule — subject, path, verdict ID, criterion, evidence, lane
// fields, media name, transcript — is stripped of control and escape bytes
// when the Report is built, so neither the page, the JSON, nor a terminal
// ever sees them.
func TestM2_1_ControlBytesNeverReachTheReport(t *testing.T) {
	const esc = "\x1b[31m"
	f := trailtest.New(t, smallFolio())
	intent := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base,
		Lane:       capsule.LaneConfig{Model: "mo" + esc + "del", Harness: "har\x07ness", Skill: "sk\x00ill", Prompt: "pro\x1bmpt", Effort: "hi\x7fgh", ContextPolicy: "pu\x08sh", Runner: "lo\x1bcal"},
		Transcript: []lane.Event{trailtest.Output("out" + esc + "put")},
		Verdicts: []capsule.Verdict{
			{ID: "[W-1]", Criterion: "crit" + esc + "erion", Pass: false, Evidence: "evi" + esc + "dence proof/sh\x1bot.png"},
			{ID: "[X-" + "1]\x1b", Criterion: "odd id", Pass: true},
			{ID: "ring0", Criterion: "ring" + esc, Pass: false, Evidence: "changed: " + esc},
			{ID: "[Z-1]", Criterion: "orphan" + esc, Pass: true},
		},
		Proof: map[string][]byte{"sh\x1bot.png": trailtest.PNG()},
		Paths: []string{"a.txt"},
	})
	f.Commit("sub"+esc+"ject\x07", map[string]string{"a.txt": "1\n", "pa\x1bth.txt": "x\n"}, trailtest.Trailers(intent, addr)...)
	f.Commit("no trailers"+esc, map[string]string{"a.txt": "2\n"}, gitx.Trailer{Key: gitx.TrailerIntent, Value: "folio:\x1bnope"}, gitx.Trailer{Key: gitx.TrailerCapsule, Value: "sha256:\x1bnope"})
	r := build(t, f, f.Base, "HEAD", func(o *Options) {
		o.RiskGlob = func(p string) (string, string) {
			if strings.HasPrefix(p, "pa") {
				return "R2", "pa*"
			}
			return "", ""
		}
	})
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{`\u001b`, `\u0007`, `\u0000`, `\u0008`, `\u007f`, "\x7f"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("report JSON carries %q", banned)
		}
	}
	page, err := RenderHTML(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range string(page) {
		if c != '\n' && (c < 0x20 || c == 0x7f) {
			t.Fatalf("page carries control byte %#x", c)
		}
	}
	// The text itself survives, minus the bytes.
	for _, want := range []string{"sub[31mject", "crit[31merion", "mo[31mdel", "out[31mput", "pa<wbr>"[:2] + "th.txt", "sh" + "ot.png", "no trailers[31m"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if r.Commits[0].Subject != "sub[31mject" || r.Capsules[0].Lane.Runner != "local" || r.Media[0].Name != "shot.png" || r.Media[0].ID != "[W-1]" {
		t.Errorf("sanitized fields: %q %q %+v", r.Commits[0].Subject, r.Capsules[0].Lane.Runner, r.Media[0])
	}
}

// TestM2_1_MediaAcceptanceIDNeedsTheFullMemberPath: a proof file belongs to
// the acceptance verdict whose evidence names its whole member path; a
// look-alike name or an engine verdict does not claim it.
func TestM2_1_MediaAcceptanceIDNeedsTheFullMemberPath(t *testing.T) {
	f := trailtest.New(t, smallFolio())
	intent := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Paths: []string{"a.txt"},
		Verdicts: []capsule.Verdict{
			{ID: "verifier", Criterion: "verifier exits 0", Pass: true, Evidence: "see proof/xa.png and proof/a.png"},
			{ID: "[W-1]", Criterion: "lint is clean", Pass: true, Evidence: "screenshots: proof/a.png."},
		},
		Proof: map[string][]byte{"a.png": trailtest.PNG(), "xa.png": trailtest.PNG(), "w-1-named.png": trailtest.PNG(), "z-9-unknown.png": trailtest.PNG(),
			"diagram.svg": []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(1)</script></svg>`)},
	})
	f.Commit("a: change", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, addr)...)
	r := build(t, f, f.Base, "HEAD")
	got := map[string]string{}
	for _, m := range r.Media {
		got[m.Name] = m.ID
	}
	want := map[string]string{"a.png": "[W-1]", "xa.png": "", "w-1-named.png": "[W-1]", "z-9-unknown.png": ""}
	if len(got) != len(want) {
		t.Fatalf("media: %v", got)
	}
	for name, id := range want {
		if got[name] != id {
			t.Errorf("%s: id %q, want %q", name, got[name], id)
		}
	}
	// The Capsule's SVG — script and all — is neither rendered nor copied.
	files, err := BundleFiles(r)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if strings.Contains(name, "diagram") || strings.Contains(string(data), "alert(1)") {
			t.Errorf("capsule SVG reached the bundle as %s", name)
		}
	}
	for _, tc := range []struct {
		text, path string
		want       bool
	}{
		{"proof/a.png", "proof/a.png", true}, {"see proof/a.png.", "proof/a.png", true}, {"(proof/a.png)", "proof/a.png", true},
		{"proof/xa.png", "proof/a.png", false}, {"myproof/a.png", "proof/a.png", false}, {"proof/a.png.bak", "proof/a.png", false},
		{"proof/a.pngx proof/a.png", "proof/a.png", true}, {"a.png", "proof/a.png", false}, {"", "proof/a.png", false},
	} {
		if got := namesPath(tc.text, tc.path); got != tc.want {
			t.Errorf("namesPath(%q, %q) = %v", tc.text, tc.path, got)
		}
	}
}
