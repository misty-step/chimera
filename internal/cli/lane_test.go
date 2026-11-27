package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/lane"
	"chimera/pkg/ledger"
	"chimera/pkg/objstore"
)

func shaOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

const greetVerifier = `#!/bin/sh
out=$(sh greet.sh)
if [ "$out" = "hello" ]; then p=true; else p=false; fi
printf '[{"id":"[M1-4]","criterion":"greet.sh prints hello","pass":%s,"evidence":"got %s"}]\n' "$p" "$out" > "$CHIMERA_OUT/verdicts.json"
`

// laneFixture is a repository with a typo to fix, a config with one harness
// that fixes it and one that does not, a directory store, and a Ledger.
func laneFixture(t *testing.T) (repo, cfg string, env map[string]string) {
	t.Helper()
	repo = fixtureRepo(t, map[string]string{
		"greet.sh": "#!/bin/sh\necho helo\n", "verify/check.sh": greetVerifier, "PRODUCT.md": "# product\ngreeting must say hello\n", "DESIGN.md": "# design\n",
	})
	state := t.TempDir()
	cfg = writeConfig(t, `store:
  endpoint: file://`+filepath.Join(state, "store")+`
ledger:
  path: `+filepath.Join(state, "ledger.db")+`
ring0:
  paths: ["verify/**"]
harnesses:
  good-agent:
    command: ["sh", "-c", "sed -i.bak s/helo/hello/ greet.sh && rm greet.sh.bak && echo fixed; printf '{\"input_tokens\":2000000,\"output_tokens\":250000}' > {{.OutDir}}/usage.json"]
    timeout: 30s
  bad-agent: { command: ["sh", "-c", "echo read {{.PromptFile}} and changed nothing"], timeout: 30s }
verifiers:
  default: { command: ["sh", "verify/check.sh"], timeout: 30s }
lanes:
  good: { model: example-model, harness: good-agent, effort: high, context_policy: push, runner: local }
  bad: { model: example-model, harness: bad-agent, effort: low }
  remote: { model: example-model, harness: good-agent, runner: boat }
prices:
  example-model: { input_per_mtok: 1.00, output_per_mtok: 4.00 }
`)
	// --apply commits with the caller's Git identity.
	t.Setenv("GIT_AUTHOR_NAME", "Example")
	t.Setenv("GIT_AUTHOR_EMAIL", "dev@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "Example")
	t.Setenv("GIT_COMMITTER_EMAIL", "dev@example.com")
	return repo, cfg, map[string]string{}
}

func TestM1_4_RunProducesCapsuleWithoutTouchingGit(t *testing.T) {
	repo, cfg, env := laneFixture(t)
	head := gitOut(t, repo, "rev-parse", "HEAD")
	intent := "task:" + shaOf("fix the greeting")

	r := run(t, repo, env, "run", "--intent", intent, "--lane", "good", "--brief", "greet.sh must print hello", "--config", cfg, "--json")
	var res runResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != ExitOK {
		t.Fatalf("run: %+v %v", r, err)
	}
	if res.Schema != "chimera.run/v1" || !res.Pass || res.Intent != intent || res.BaseSHA != head || res.Commit != "" || len(res.Verdicts) != 1 ||
		res.Trailers["Chimera-Intent"] != intent || res.Trailers["Chimera-Capsule"] != res.Capsule || !capsule.ValidCheckpoint(res.Checkpoint) {
		t.Fatalf("%+v", res)
	}
	if res.Lane != (capsule.LaneConfig{Model: "example-model", Harness: "good-agent", Effort: "high", ContextPolicy: "push", Runner: "local"}) {
		t.Fatalf("lane: %+v", res.Lane)
	}
	// 2M input at $1 + 0.25M output at $4 = $3.00, from reported usage only.
	if res.CostUSD == nil || *res.CostUSD != 3.0 {
		t.Fatalf("cost: %v", res.CostUSD)
	}
	// Git is untouched: same HEAD, clean tree, no extra worktree, no notes or refs.
	if gitOut(t, repo, "rev-parse", "HEAD") != head || gitOut(t, repo, "status", "--porcelain") != "" || strings.Contains(gitOut(t, repo, "worktree", "list"), "\n") {
		t.Fatal("run mutated the repository")
	}
	if refs := gitOut(t, repo, "for-each-ref", "--format=%(refname)"); refs != "refs/heads/main" {
		t.Fatalf("refs: %s", refs)
	}
	// The Capsule is in the store with the structured trace, and indexed.
	g := run(t, repo, env, "capsule", "get", res.Capsule, "--out", filepath.Join(t.TempDir(), "c"), "--config", cfg, "--json")
	if g.code != ExitOK || !strings.Contains(g.stdout, `"tags":["cell:`) || !strings.Contains(g.stdout, `"lane:good"`) {
		t.Fatalf("get: %+v", g)
	}
	q := run(t, repo, env, "ledger", "query", "greet prints hello", "--tier", "T1", "--config", cfg)
	if q.code != ExitOK || !strings.Contains(q.stdout, "T1    fresh") && !strings.Contains(q.stdout, "T1    drift") || !strings.Contains(q.stdout, "greet.sh") {
		t.Fatalf("run's capsule is not indexed: %+v", q)
	}

	// Human output: abbreviated hashes in the table, full trailers to copy.
	h := run(t, repo, env, "run", "--intent", intent, "--lane", "good", "--config", cfg)
	if h.code != ExitOK || !strings.Contains(h.stdout, "VERDICT     PASS  1/1 criteria") || !strings.Contains(h.stdout, "COST        $3.0000") ||
		!strings.Contains(h.stdout, "\nChimera-Intent: "+intent+"\nChimera-Capsule: sha256:") || !strings.Contains(h.stderr, "git history untouched") {
		t.Fatalf("human run: %+v", h)
	}

	// A failing verifier exits 1, still with a Capsule; nothing is applied.
	f := run(t, repo, env, "run", "--intent", intent, "--lane", "bad", "--apply", "--config", cfg)
	if f.code != ExitError || !strings.Contains(f.stdout, "VERDICT     FAIL  0/1 criteria") || !strings.Contains(f.stdout, "COST        —") ||
		!strings.Contains(f.stderr, "verifier failed (1 of 1 criteria); capsule sha256:") || !strings.Contains(f.stderr, "; not applied") {
		t.Fatalf("failing run: %+v", f)
	}
	if gitOut(t, repo, "rev-parse", "HEAD") != head {
		t.Fatal("a failing lane was applied")
	}
	fj := run(t, repo, env, "--json", "run", "--intent", intent, "--lane", "bad", "--config", cfg)
	var env1 errorEnvelope
	if json.Unmarshal([]byte(fj.stdout), &env1) != nil || env1.Code != 1 || env1.Command != "run" || len(env1.Findings) != 1 || strings.Count(fj.stdout, "\n") != 1 {
		t.Fatalf("failing run --json: %+v", fj)
	}

	// Usage errors attempt nothing.
	for _, args := range [][]string{
		{"run", "--lane", "good"}, {"run", "--intent", intent}, {"run", "--intent", intent, "--lane", "nope"}, {"run", "--intent", "bogus", "--lane", "good"},
		{"run", "--intent", intent, "--lane", "good", "--verifier", "nope"}, {"run", "--intent", intent, "--lane", "good", "--base", "no-such-rev"},
	} {
		if r := run(t, repo, env, append(args, "--config", cfg)...); r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	// The boat runner runs only when configured; this config has no runners.boat.
	if r := run(t, repo, env, "run", "--intent", intent, "--lane", "remote", "--config", cfg); r.code != ExitError || !strings.Contains(r.stderr, "runner boat is not configured") {
		t.Fatalf("unconfigured boat runner: %+v", r)
	}
}

func TestM1_4_RunApplyCommitsWithBothTrailers(t *testing.T) {
	repo, cfg, env := laneFixture(t)
	head := gitOut(t, repo, "rev-parse", "HEAD")
	r := run(t, repo, env, "run", "--intent", "folio", "--lane", "good", "--apply", "--message", "greet: fix the greeting", "--config", cfg, "--json")
	var res runResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != ExitOK {
		t.Fatalf("run --apply: %+v %v", r, err)
	}
	newHead := gitOut(t, repo, "rev-parse", "HEAD")
	if res.Commit != newHead || gitOut(t, repo, "rev-parse", "HEAD~1") != head || gitOut(t, repo, "status", "--porcelain") != "" {
		t.Fatalf("commit=%s head=%s", res.Commit, newHead)
	}
	// "--intent folio" resolves to the folio Intent at the base commit.
	if !strings.HasPrefix(res.Intent, "folio:") || len(res.Intent) != 70 {
		t.Fatalf("intent %q", res.Intent)
	}
	msg := gitOut(t, repo, "log", "-1", "--format=%B")
	if msg != "greet: fix the greeting\n\nChimera-Intent: "+res.Intent+"\nChimera-Capsule: "+res.Capsule {
		t.Fatalf("commit message:\n%s", msg)
	}
	if data, _ := os.ReadFile(filepath.Join(repo, "greet.sh")); !strings.Contains(string(data), "echo hello") {
		t.Fatalf("diff not applied: %s", data)
	}
	// The loop closes: why resolves the committed line back to the lane's Capsule.
	w := run(t, repo, env, "why", "greet.sh:2", "--config", cfg, "--json")
	var wr whyResult
	if json.Unmarshal([]byte(w.stdout), &wr) != nil || w.code != ExitOK || wr.Proofs[0].Capsule != res.Capsule || wr.Proofs[0].Intent != res.Intent ||
		!wr.Proofs[0].Covers || wr.Proofs[0].Lane.Harness != "good-agent" || len(wr.Proofs[0].Verdicts) != 1 || !wr.Proofs[0].Verdicts[0].Pass {
		t.Fatalf("why after --apply: %+v", w)
	}
	// A dirty tree is never applied onto.
	writeFiles(t, repo, map[string]string{"PRODUCT.md": "# product\nedited\n"})
	d := run(t, repo, env, "run", "--intent", "folio", "--lane", "good", "--apply", "--config", cfg)
	if d.code != ExitError || !strings.Contains(d.stderr, "run: --apply: ") || gitOut(t, repo, "rev-parse", "HEAD") != newHead {
		t.Fatalf("apply onto a dirty tree: %+v", d)
	}
}

func benchFile(t *testing.T, repo string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bench.yaml")
	body := `id: greeting
k: 2
fixtures:
  - name: fix-greeting
    repo: ` + repo + `
    base_sha: HEAD
    task_brief: greet.sh must print hello
    verifier: default
axes:
  model: [example-model]
  harness: [good-agent, bad-agent]
  effort: [high]
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestM1_4_BenchTableJSONAndIndexedCapsules(t *testing.T) {
	repo, cfg, env := laneFixture(t)
	head := gitOut(t, repo, "rev-parse", "HEAD")
	matrix := benchFile(t, repo)
	html := filepath.Join(t.TempDir(), "report")

	b := run(t, repo, env, "bench", "--matrix", matrix, "-K", "3", "--html", html, "--config", cfg)
	if b.code != ExitOK {
		t.Fatalf("bench: %+v", b)
	}
	lines := strings.Split(strings.TrimRight(b.stdout, "\n"), "\n")
	if len(lines) != 3 || strings.Join(strings.Fields(lines[0]), " ") != "FIXTURE CELL MODEL HARNESS EFFORT CONTEXT PASS RATE X/K WALL P50 WALL P90 COST" {
		t.Fatalf("table:\n%s", b.stdout)
	}
	good, bad := strings.Fields(lines[1]), strings.Fields(lines[2])
	if good[0] != "fix-greeting" || good[3] != "good-agent" || good[6] != "1.00" || good[7] != "3/3" || good[10] != "$3.0000" ||
		bad[3] != "bad-agent" || bad[6] != "0.00" || bad[7] != "0/3" || bad[10] != "—" {
		t.Fatalf("rows:\n%s", b.stdout)
	}
	if strings.ContainsAny(b.stdout, "│|┌\x1b") {
		t.Fatal("box drawing or escapes in the table")
	}
	if gitOut(t, repo, "rev-parse", "HEAD") != head || gitOut(t, repo, "status", "--porcelain") != "" {
		t.Fatal("bench mutated the fixture repository")
	}
	for _, f := range []string{"index.html", "trail.css", "favicon.svg", "media/capsule-write.svg", "fonts/ibm-plex-mono-latin-400-normal.woff2"} {
		if _, err := os.Stat(filepath.Join(html, filepath.FromSlash(f))); err != nil {
			t.Errorf("report bundle lacks %s", f)
		}
	}

	// --json emits the same rows.
	j := run(t, repo, env, "bench", "--matrix", matrix, "--config", cfg, "--json", "-q")
	var rep lane.Report
	if err := json.Unmarshal([]byte(j.stdout), &rep); err != nil || j.code != ExitOK || j.stderr != "" {
		t.Fatalf("bench --json: %+v %v", j, err)
	}
	if rep.Schema != "chimera.bench/v1" || rep.Bench != "greeting" || rep.K != 2 || len(rep.Cells) != 2 {
		t.Fatalf("%+v", rep)
	}
	g, bd := rep.Cells[0], rep.Cells[1]
	if g.PassRate != 1 || g.AllPass != 2 || bd.PassRate != 0 || bd.AllPass != 0 || g.Cell != good[1] || bd.Cell != bad[1] || g.CostUSD == nil || bd.CostUSD != nil {
		t.Fatalf("json rows differ from the table: %+v %+v", g, bd)
	}
	tree := gitOut(t, repo, "rev-parse", "HEAD^{tree}")
	for _, c := range rep.Cells {
		if !strings.HasPrefix(c.Intent, "task:") || c.Intent != g.Intent || len(c.Lanes) != 2 {
			t.Fatalf("%+v", c)
		}
		for _, l := range c.Lanes {
			if l.BaseSHA != head || l.Tree != tree || l.Capsule == "" {
				t.Errorf("lane did not start from the frozen base and tree: %+v", l)
			}
		}
	}

	// Every lane's Capsule is tagged and indexed: 3+3 from the first bench, 2+2 from the second.
	store := objstore.NewDir(strings.TrimPrefix(readStoreEndpoint(t, cfg), "file://"))
	addrs, err := capsule.List(context.Background(), store)
	if err != nil || len(addrs) != 10 {
		t.Fatalf("%d capsules: %v", len(addrs), err)
	}
	d := run(t, repo, env, "ledger", "dump", "--canonical", "--config", cfg)
	if d.code != ExitOK || strings.Count(d.stdout, `"table":"lanes"`) != 10 || strings.Count(d.stdout, `"bench":"greeting"`) != 10 {
		t.Fatalf("lanes table: %d rows", strings.Count(d.stdout, `"table":"lanes"`))
	}
	for _, want := range []string{`"cell":"` + g.Cell + `"`, `"cell":"` + bd.Cell + `"`, `"k":3`, `"harness":"bad-agent"`, `"pass_rate":0,`, `"cost_usd":null`, `"cost_usd":3,`} {
		if !strings.Contains(d.stdout, want) {
			t.Errorf("ledger dump lacks %s", want)
		}
	}

	// run equals bench -K 1 on the same inputs: same Intent and lane give the
	// same cell, diff, and verdicts; only the checkpoint and times differ.
	one := run(t, repo, env, "bench", "--matrix", matrix, "-K", "1", "--config", cfg, "--json")
	var single lane.Report
	json.Unmarshal([]byte(one.stdout), &single)
	// The run's lane and the bench's cell must be the same LaneConfig; the
	// config's "good" lane uses context push, so compare through a lane that
	// matches the matrix (context none).
	cfg2 := strings.Replace(readFile(t, cfg), "context_policy: push, ", "", 1)
	cfgNone := writeConfig(t, cfg2)
	rr := run(t, repo, env, "run", "--intent", single.Cells[0].Intent, "--lane", "good", "--brief", "greet.sh must print hello", "--config", cfgNone, "--json")
	var res runResult
	if err := json.Unmarshal([]byte(rr.stdout), &res); err != nil {
		t.Fatalf("%+v", rr)
	}
	benchLane := single.Cells[0].Lanes[0]
	a, _ := capsule.ParseAddress(res.Capsule)
	bAddr, _ := capsule.ParseAddress(benchLane.Capsule)
	fromRun, err1 := capsule.Get(context.Background(), store, a)
	fromBench, err2 := capsule.Get(context.Background(), store, bAddr)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if fromRun.Manifest.Lane != fromBench.Manifest.Lane || fromRun.Manifest.Intent != fromBench.Manifest.Intent || fromRun.Manifest.BaseSHA != fromBench.Manifest.BaseSHA ||
		fromRun.Manifest.Tag("cell") != fromBench.Manifest.Tag("cell") || fromRun.Manifest.Tag("k") != "1" || fromBench.Manifest.Tag("k") != "1" {
		t.Fatalf("manifests differ:\n%+v\n%+v", fromRun.Manifest, fromBench.Manifest)
	}
	for _, m := range []string{capsule.MemberDiff, capsule.MemberVerdicts, "proof/harness.log", "proof/verifier.log"} {
		if string(fromRun.Members[m]) != string(fromBench.Members[m]) {
			t.Errorf("member %s differs between run and bench -K 1", m)
		}
	}
	if res.Pass != benchLane.Pass || res.Tree != benchLane.Tree {
		t.Fatal("run and bench -K 1 disagree")
	}
	if fromRun.Manifest.Tag("bench") != "" || fromBench.Manifest.Tag("bench") != "greeting" {
		t.Fatal("bench tag")
	}

	// Usage errors.
	for _, args := range [][]string{{"bench"}, {"bench", "--matrix", "missing.yaml"}, {"bench", "--matrix", matrix, "-K", "0"}, {"bench", "--matrix", matrix, "--k", "2"}} {
		if r := run(t, repo, env, append(args, "--config", cfg)...); r.code != ExitUsage || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readStoreEndpoint(t *testing.T, cfg string) string {
	t.Helper()
	for _, line := range strings.Split(readFile(t, cfg), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "endpoint: "); ok {
			return v
		}
	}
	t.Fatal("no endpoint in config")
	return ""
}

func TestM1_3_LedgerIndexQueryPreflightRebuild(t *testing.T) {
	repo, cfg, env := laneFixture(t)
	intent := "task:" + shaOf("fix the greeting")
	c := func(args ...string) result { return run(t, repo, env, append(args, "--config", cfg)...) }

	// Reading a Ledger that does not exist is an error with a next action.
	if r := c("ledger", "query", "hello"); r.code != ExitError || !strings.HasSuffix(r.stderr, "; run 'chimera ledger rebuild'\n") {
		t.Fatalf("query without a ledger: %+v", r)
	}
	if r := c("ledger", "index"); r.code != ExitOK || !strings.Contains(r.stderr, "4 entries, 0 lanes (+4 −0 T0, +0 capsules)") {
		t.Fatalf("index: %+v", r)
	}
	// Two lanes: one passes, one fails. Both are indexed by run itself.
	if r := c("run", "--intent", intent, "--lane", "good"); r.code != ExitOK {
		t.Fatalf("%+v", r)
	}
	if r := c("run", "--intent", intent, "--lane", "bad"); r.code != ExitError {
		t.Fatalf("%+v", r)
	}

	// query: tier first. "hello" is in PRODUCT.md (T0) and in the verdicts (T1).
	q := c("ledger", "query", "hello")
	rows := strings.Split(strings.TrimRight(q.stdout, "\n"), "\n")
	if q.code != ExitOK || len(rows) != 5 || !strings.HasPrefix(rows[0], "TIER  STATE") {
		t.Fatalf("query:\n%s%s", q.stdout, q.stderr)
	}
	var order []string
	for _, row := range rows[1:] {
		f := strings.Fields(row)
		order = append(order, f[0]+" "+f[1]+" "+f[3])
	}
	// T0 before T1 whatever the BM25; within T1, fresh before drifted. The
	// passing lane's entry anchors on the blob the lane produced, which HEAD
	// does not hold (the run was not applied), so it is not fresh.
	if got := strings.Join(order, " | "); got != "T0 fresh PRODUCT.md | T0 fresh verify/check.sh | T1 fresh — | T1 drift=1 greet.sh" {
		t.Fatalf("rank order: %s\n%s", got, q.stdout)
	}
	var qr queryResult
	qj := c("ledger", "query", "greet prints hello", "--tier", "T1", "--path", "greet.sh", "--json")
	if json.Unmarshal([]byte(qj.stdout), &qr) != nil || qr.Schema != "chimera.ledger.query/v1" || len(qr.Hits) != 1 || qr.Hits[0].Tier != "T1" || qr.Hits[0].Path != "greet.sh" ||
		!strings.HasPrefix(qr.Hits[0].Anchor, "greet.sh@") || qr.Hits[0].Intent != intent || !strings.HasPrefix(qr.Hits[0].Capsule, "sha256:") {
		t.Fatalf("query --json: %s", qj.stdout)
	}
	if r := c("ledger", "query", "zzzznomatch"); r.code != ExitOK || r.stdout != "" {
		t.Fatalf("no match: %+v", r)
	}
	for _, args := range [][]string{{"ledger", "query"}, {"ledger", "query", "x", "--tier", "T9"}, {"ledger", "query", "x", "--limit", "0"}, {"ledger", "query", "..."}, {"preflight"}} {
		if r := c(args...); r.code != ExitUsage {
			t.Errorf("%v: %+v", args, r)
		}
	}

	// preflight: bounded, byte-stable, warns about the prior failing lane with a why pointer.
	p := c("preflight", "greet.sh")
	if p.code != ExitOK || len(p.stdout) > ledger.MaxScent || !strings.HasPrefix(p.stdout, "PREFLIGHT  repo="+filepath.Base(repo)+"  paths=1  entries=2/2\n") {
		t.Fatalf("preflight: %+v", p)
	}
	flat := strings.Join(strings.Fields(p.stdout), " ")
	for _, want := range []string{"TIER STATE KIND PATH SOURCE SCENT T0 fresh code greet.sh greet.sh@", "T1 drift=1 capsule greet.sh sha256:", "[M1-4] PASS greet.sh prints hello — got hello"} {
		if !strings.Contains(flat, want) {
			t.Errorf("preflight lacks %q:\n%s", want, p.stdout)
		}
	}
	if again := c("preflight", "--paths", "greet.sh"); again.stdout != p.stdout {
		t.Fatalf("preflight is not byte-stable / --paths differs from the positional form:\n%s\n%s", p.stdout, again.stdout)
	}
	// The failing lane left its diff empty (no path), so it is found by failure signature.
	f := c("preflight", "greet.sh", "--failure", "got helo", "--repo", filepath.Base(repo))
	if f.code != ExitOK || !strings.Contains(f.stdout, "failure=sig:") || !strings.Contains(f.stdout, "entries=3/3") ||
		!strings.Contains(f.stdout, "WARN  —: same failure signature recorded in sha256:") || !strings.Contains(f.stdout, "; chimera capsule get sha256:") || !strings.Contains(f.stdout, "[M1-4] FAIL greet.sh prints hello — got helo") {
		t.Fatalf("preflight --failure:\n%s", f.stdout)
	}
	var sc ledger.Scent
	fj := c("preflight", "greet.sh", "--failure", "got helo", "--json")
	if json.Unmarshal([]byte(fj.stdout), &sc) != nil || sc.Schema != "chimera.preflight/v1" || len(sc.Entries) != 3 || sc.Total != 3 || len(fj.stdout) > ledger.MaxScent ||
		sc.Entries[2].Why != "chimera why greet.sh" || !strings.HasPrefix(sc.Entries[1].Source, "sha256:") || len(sc.Entries[1].Source) != 71 ||
		sc.Entries[1].Why != "chimera capsule get "+sc.Entries[1].Source || sc.Entries[1].Warning != "same failure signature recorded" {
		t.Fatalf("preflight --json: %s", fj.stdout)
	}

	// Drop-and-rebuild equivalence through the CLI: the incrementally built
	// Ledger and a rebuilt one have the same canonical dump.
	writeFiles(t, repo, map[string]string{"greet.sh": "#!/bin/sh\necho hello\n", "NOTES.md": "new file\n"})
	os.Remove(filepath.Join(repo, "DESIGN.md"))
	commitAll(t, repo, "fix by hand")
	if r := c("ledger", "index"); r.code != ExitOK || !strings.Contains(r.stderr, "+3 −3 T0, +0 capsules") {
		t.Fatalf("incremental index: %+v", r)
	}
	st1 := c("ledger", "status", "--json")
	inc := c("ledger", "dump", "--canonical")
	if r := c("ledger", "rebuild"); r.code != ExitOK || !strings.Contains(r.stderr, "+4 −0 T0, +2 capsules") {
		t.Fatalf("rebuild: %+v", r)
	}
	reb := c("ledger", "dump", "--canonical")
	if inc.code != ExitOK || inc.stdout == "" || shaOf(inc.stdout) != shaOf(reb.stdout) {
		t.Fatalf("incremental and rebuilt dumps differ:\n%s\n---\n%s", inc.stdout, reb.stdout)
	}
	var s1, s2 statusResult
	json.Unmarshal([]byte(st1.stdout), &s1)
	json.Unmarshal([]byte(c("ledger", "status", "--json").stdout), &s2)
	if s1.Digest != "sha256:"+shaOf(inc.stdout) || s1.Digest != s2.Digest || s2.Schema != "chimera.ledger.status/v1" || s2.Tiers["T0"] != 4 || s2.Tiers["T1"] != 2 || s2.Lanes != 2 {
		t.Fatalf("status: %+v %+v", s1, s2)
	}
	if h := c("ledger", "status"); h.code != ExitOK || !strings.Contains(h.stdout, "T0        4\n") || !strings.Contains(h.stdout, "DIGEST    sha256:"+shaOf(inc.stdout)[:12]+"\n") {
		t.Fatalf("status: %+v", h)
	}
	// The hand fix committed exactly the content the passing lane produced, so
	// that entry's anchor now equals HEAD's blob: fresh. One more edit: drift=1.
	fq := c("ledger", "query", "greet prints hello", "--tier", "T1", "--path", "greet.sh", "--json")
	json.Unmarshal([]byte(fq.stdout), &qr)
	if len(qr.Hits) != 1 || qr.Hits[0].State != "fresh" {
		t.Fatalf("after landing the lane's content: %s", fq.stdout)
	}
	writeFiles(t, repo, map[string]string{"greet.sh": "#!/bin/sh\necho hello\n# trailing comment\n"})
	commitAll(t, repo, "touch greet")
	dq := c("ledger", "query", "greet prints hello", "--tier", "T1", "--path", "greet.sh", "--json")
	json.Unmarshal([]byte(dq.stdout), &qr)
	if len(qr.Hits) != 1 || qr.Hits[0].State != "drift=1" || qr.Hits[0].Drift != 1 {
		t.Fatalf("drift after an edit: %s", dq.stdout)
	}
	// The Ledger file is never inside the repository.
	if out := gitOut(t, repo, "status", "--porcelain", "--ignored"); out != "" {
		t.Fatalf("ledger or evidence leaked into the work tree: %s", out)
	}
}
