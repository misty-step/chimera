package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/trail"
	"chimera/pkg/trail/trailtest"
)

func trailFixture(t *testing.T) (*trailtest.Reference, string) {
	t.Helper()
	ref := trailtest.NewReference(t)
	return ref, writeConfig(t, ref.Config())
}

// TestM2_1_TrailTextJSONAndHTML: `chimera trail <base>..<head>` prints the
// review as aligned text, as one chimera.trail/v1 object with --json, and
// writes the static page with --html. A view is not a gate: it exits 0.
func TestM2_1_TrailTextJSONAndHTML(t *testing.T) {
	ref, cfg := trailFixture(t)
	spec := ref.Base + "..HEAD"
	base12, head12 := ref.Base[:12], ref.Head()[:12]

	r := run(t, ref.Dir, nil, "trail", spec, "--config", cfg)
	if r.code != ExitOK || r.stderr != "" {
		t.Fatalf("trail: %+v", r)
	}
	for _, want := range []string{
		"TRAIL          repo " + base12 + ".." + head12 + "\n", "RISK           R3\n", "CHECK          FAIL\n", "OPEN RISK      4\n", "UNMET INTENT   2\n",
		"MISSING PROOF  1\n", "VERDICTS       6  (4 pass, 1 fail, 1 stale)\n",
		"\nOPEN RISK\nCLASS  PATH                   REASON", "R3     verify/check.sh        Ring-0 path changed",
		"R2     pkg/objstore/sigv4.go  matches risk glob pkg/objstore/**                        sha256:" + ref.PushCapsule[7:19] + ":2\n",
		"\nUNMET INTENT\nID     STATE    CRITERION\n[W-2]  FAIL     Corrupted member makes get fail\n[W-3]  PENDING  no verdict in this range\n",
		"\nMISSING PROOF\nCOMMIT        MISSING                          SUBJECT\n" + ref.Docs[:12] + "  Chimera-Intent, Chimera-Capsule  docs: fix typo in push help\n",
		"[X-9]     STALE  Legacy export still works", "\nCOMMITS\nCOMMIT        RISK  CAPSULE",
		ref.Verify[:12] + "  R3    sha256:" + ref.VerifyCapsule[7:19] + "  " + ref.Intent[:18] + "  verify: run vet before the tests\n",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("text output lacks %q\n%s", want, r.stdout)
		}
	}
	if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
		t.Error("escape byte off a TTY")
	}
	// Same inputs, same bytes.
	if again := run(t, ref.Dir, nil, "trail", spec, "--config", cfg); again != r {
		t.Error("output is not deterministic")
	}

	j := run(t, ref.Dir, nil, "trail", spec, "--config", cfg, "--json", "--repo", "acme/widget")
	var rep trail.Report
	if err := json.Unmarshal([]byte(j.stdout), &rep); err != nil || j.code != ExitOK || j.stderr != "" || strings.Count(j.stdout, "\n") != 1 {
		t.Fatalf("--json: %v %+v", err, j)
	}
	if rep.Schema != "chimera.trail/v1" || rep.Repo != "acme/widget" || rep.Base != ref.Base || rep.Head != ref.Head() || rep.Risk != "R3" ||
		len(rep.OpenRisk) != 4 || len(rep.Unmet) != 2 || len(rep.Missing) != 1 || len(rep.Orphans) != 1 || len(rep.Verdicts) != 6 ||
		len(rep.Media) != 3 || len(rep.Commits) != 4 || len(rep.Capsules) != 3 || rep.Check.State != "FAIL" || rep.Intents[0] != ref.Intent {
		t.Fatalf("report: %s", j.stdout)
	}

	// --html writes the bundle and says so on stderr; -q says nothing.
	out := filepath.Join(t.TempDir(), "page")
	h := run(t, ref.Dir, nil, "trail", spec, "--config", cfg, "--html", out, "--repo", "acme/widget")
	if h.code != ExitOK || h.stderr != "trail: wrote "+filepath.Join(out, "index.html")+"\n" {
		t.Fatalf("--html: %+v", h)
	}
	page, err := os.ReadFile(filepath.Join(out, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("..", "..", "pkg", "trail", "testdata", "golden", "index.html"))
	if err != nil || !bytes.Equal(page, golden) {
		t.Errorf("the CLI's page differs from the golden page (%v)", err)
	}
	for _, name := range []string{"trail.css", "favicon.svg", "fonts/OFL.txt", "fonts/ibm-plex-sans-latin-400-normal.woff2", "media/capsule-write.svg",
		"media/" + ref.PushCapsule[7:19] + "-w-2-push.mp4", "media/" + ref.LintCapsule[7:19] + "-w-1-lint.png"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(name))); err != nil {
			t.Errorf("bundle lacks %s", name)
		}
	}
	if _, err := os.Stat(filepath.Join(out, "trail.js")); err == nil {
		t.Error("bundle ships script")
	}
	q := run(t, ref.Dir, nil, "trail", spec, "--config", cfg, "--html", filepath.Join(t.TempDir(), "q"), "-q", "--json")
	if q.code != ExitOK || q.stderr != "" || !strings.HasPrefix(q.stdout, `{"schema":"chimera.trail/v1"`) {
		t.Fatalf("-q: %+v", q)
	}
}

// TestM2_1_TrailCheckExitCodes: --check is the gate. FAIL exits 1, PENDING
// exits 3, PASS exits 0; with --json a check that did not pass is one
// chimera.error/v1 object whose findings list what is wrong.
func TestM2_1_TrailCheckExitCodes(t *testing.T) {
	ref, cfg := trailFixture(t)
	rng := func(base, head string) string { return base[:12] + ".." + head[:12] }

	// FAIL: a commit without trailers and a failing verdict.
	spec := ref.Base + ".." + ref.Verify
	r := run(t, ref.Dir, nil, "trail", spec, "--check", "--config", cfg)
	wantErr := "chimera: trail: " + rng(ref.Base, ref.Verify) + ": check FAIL: 1 commit with missing proof, 1 failing verdict; the range does not pass review\n"
	if r.code != ExitError || r.stderr != wantErr {
		t.Fatalf("FAIL: %+v", r)
	}
	wantOut := "CHECK          FAIL\nRANGE          repo " + rng(ref.Base, ref.Verify) + "\nINTENT         " + ref.Intent[:18] + "\nRISK           R3\n" +
		"OPEN RISK      4\nUNMET INTENT   2\nMISSING PROOF  1\nVERDICTS       6  (4 pass, 1 fail, 1 stale)\n"
	if r.stdout != wantOut {
		t.Fatalf("check summary:\n%s", r.stdout)
	}
	j := run(t, ref.Dir, nil, "trail", spec, "--check", "--json", "--config", cfg)
	var env struct {
		Schema, Command, Message string
		Code                     int
		Findings                 []trailFinding
	}
	if err := json.Unmarshal([]byte(j.stdout), &env); err != nil || j.code != ExitError || strings.Count(j.stdout, "\n") != 1 {
		t.Fatalf("FAIL --json: %v %+v", err, j)
	}
	if env.Schema != "chimera.error/v1" || env.Code != 1 || env.Command != "trail" || "chimera: "+env.Message+"\n" != wantErr || len(env.Findings) != 8 {
		t.Fatalf("envelope: %s", j.stdout)
	}
	kinds := map[string]int{}
	for _, f := range env.Findings {
		kinds[f.Kind]++
	}
	if kinds["missing_proof"] != 1 || kinds["verdict"] != 1 || kinds["open_risk"] != 4 || kinds["unmet_intent"] != 2 || env.Findings[0].Commit != ref.Docs {
		t.Fatalf("findings: %+v", env.Findings)
	}

	// PENDING: nothing fails, but [W-2] and [W-3] have no verdict yet.
	p := run(t, ref.Dir, nil, "trail", ref.Base+".."+ref.Lint, "--check", "--config", cfg)
	if p.code != ExitPending || !strings.HasPrefix(p.stdout, "CHECK          PENDING\n") ||
		p.stderr != "chimera: trail: "+rng(ref.Base, ref.Lint)+": check PENDING: 2 unmet intent; owner review or more proof decides it\n" {
		t.Fatalf("PENDING: %+v", p)
	}
	pj := run(t, ref.Dir, nil, "trail", ref.Base+".."+ref.Lint, "--check", "--json", "--config", cfg)
	if pj.code != ExitPending || !strings.HasPrefix(pj.stdout, `{"schema":"chimera.error/v1","code":3,"command":"trail","message":"`) {
		t.Fatalf("PENDING --json: %+v", pj)
	}

	// PASS: every acceptance ID of the Intent proven, every commit bound, no open risk.
	f := trailtest.New(t, map[string]string{"PRODUCT.md": "# P\n\n**[W-1] Lint.** Clean.\n", "DESIGN.md": "# D\n", "a.txt": "0\n"})
	intent := f.FolioIntent("HEAD")
	addr := f.Capsule(trailtest.CapsuleSpec{Intent: intent, BaseSHA: f.Base, Verdicts: []capsule.Verdict{{ID: "[W-1]", Criterion: "lint is clean", Pass: true}}})
	f.Commit("lint: clean", map[string]string{"a.txt": "1\n"}, trailtest.Trailers(intent, addr)...)
	passCfg := writeConfig(t, "store:\n  endpoint: file://"+f.StoreDir+"\n")
	ok := run(t, f.Dir, nil, "trail", f.Base+"..HEAD", "--check", "--config", passCfg)
	if ok.code != ExitOK || !strings.HasPrefix(ok.stdout, "CHECK          PASS\n") || !strings.Contains(ok.stdout, "RISK           R1\n") ||
		ok.stderr != "trail: PASS  "+rng(f.Base, f.Head())+"\n" {
		t.Fatalf("PASS: %+v", ok)
	}
	okj := run(t, f.Dir, nil, "trail", f.Base+"..HEAD", "--check", "--json", "-q", "--config", passCfg)
	if okj.code != ExitOK || okj.stderr != "" || !strings.HasPrefix(okj.stdout, `{"schema":"chimera.trail/v1"`) || !strings.Contains(okj.stdout, `"check":{"state":"PASS"`) {
		t.Fatalf("PASS --json: %+v", okj)
	}
}

// TestM2_1_TrailUsageAndStoreErrors: a malformed range, an unknown revision,
// or no store is a usage error (exit 2, nothing attempted); a store that does
// not answer is pending (exit 3), never "missing proof".
func TestM2_1_TrailUsageAndStoreErrors(t *testing.T) {
	ref, cfg := trailFixture(t)
	for _, args := range [][]string{
		{"trail"}, {"trail", "HEAD"}, {"trail", "..HEAD"}, {"trail", "HEAD.."}, {"trail", "HEAD...HEAD"}, {"trail", "nope..HEAD"}, {"trail", "HEAD..nope"},
		{"trail", ref.Base + "..HEAD", "extra"}, {"trail", ref.Base + "..HEAD", "--bogus"}, {"trail", ref.Base + "..HEAD", "--html"},
	} {
		r := run(t, ref.Dir, nil, append(args, "--config", cfg)...)
		if r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
			continue
		}
		oneLowercaseErrorLine(t, args, r.stderr)
	}
	if r := run(t, ref.Dir, nil, "trail", "HEAD", "--config", cfg); r.stderr != "chimera: trail: HEAD: range must be <base>..<head>; nothing was attempted\n" {
		t.Errorf("%q", r.stderr)
	}
	// No store configured: usage, with the JSON envelope under --json.
	r := run(t, ref.Dir, nil, "trail", ref.Base+"..HEAD", "--json")
	if r.code != ExitUsage || !strings.HasPrefix(r.stdout, `{"schema":"chimera.error/v1","code":2,"command":"trail","message":"trail: store: `) {
		t.Fatalf("no store: %+v", r)
	}
	// Outside a repository.
	if r := run(t, t.TempDir(), nil, "trail", "a..b", "--config", cfg); r.code != ExitError || !strings.HasPrefix(r.stderr, "chimera: trail: repository: ") {
		t.Fatalf("no repository: %+v", r)
	}
	// A store that does not answer: pending.
	env := map[string]string{"CHIMERA_STORE_ENDPOINT": "http://127.0.0.1:1", "CHIMERA_STORE_BUCKET": "capsules",
		"CHIMERA_S3_ACCESS_KEY_ID": "test-access", "CHIMERA_S3_SECRET_ACCESS_KEY": "test-" + genTerm(t)}
	down := run(t, ref.Dir, env, "trail", ref.Base+"..HEAD", "--check")
	if down.code != ExitPending || down.stdout != "" || !strings.HasSuffix(down.stderr, "no answer from the store; evidence unconfirmed; run the command again\n") {
		t.Fatalf("store down: %+v", down)
	}
	assertNoTerm(t, down, env["CHIMERA_S3_SECRET_ACCESS_KEY"])
	// An empty range is a valid question with a final answer.
	if e := run(t, ref.Dir, nil, "trail", "HEAD..HEAD", "--check", "--config", cfg); e.code != ExitOK || !strings.Contains(e.stdout, "RISK           R0\n") {
		t.Fatalf("empty range: %+v", e)
	}
}
