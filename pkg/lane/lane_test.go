package lane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const verifyScript = `#!/bin/sh
out=$(sh greet.sh)
if [ "$out" = "hello" ]; then p=true; else p=false; fi
printf '[{"id":"[M1-4]","criterion":"greet.sh prints hello","pass":%s,"evidence":"got %s"},{"id":"[M1-4]","criterion":"greet.sh exists","pass":true,"evidence":""}]\n' "$p" "$out" > "$CHIMERA_OUT/verdicts.json"
`

// fixture is a repository whose greet.sh has a typo, with a verifier that
// passes only once it is fixed.
func fixture(t *testing.T) (dir, base string) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	files := map[string]string{"greet.sh": "#!/bin/sh\necho helo\n", "verify/check.sh": verifyScript, "README.md": "# widget\n"}
	for name, body := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "fixture")
	return dir, git(t, dir, "rev-parse", "HEAD")
}

var (
	goodHarness = Command{Argv: []string{"sh", "-c", "sed -i.bak s/helo/hello/ greet.sh && rm greet.sh.bak && echo fixed"}, Timeout: 20 * time.Second}
	badHarness  = Command{Argv: []string{"sh", "-c", "echo read {{.PromptFile}} and changed nothing"}, Timeout: 20 * time.Second}
	verifier    = Command{Argv: []string{"sh", "verify/check.sh"}, Timeout: 20 * time.Second}
)

func testDeps(t *testing.T) (Deps, *objstore.Dir) {
	t.Helper()
	store := objstore.NewDir(filepath.Join(t.TempDir(), "store"))
	return Deps{
		Runner: func(name string) (Runner, error) {
			switch name {
			case "local":
				return Local{}, nil
			case "boat":
				return Boat{}, nil
			}
			return nil, fmt.Errorf("unknown runner %q", name)
		},
		Push: func(ctx context.Context, dir string) error {
			_, err := capsule.Push(ctx, store, dir, secretscan.New(nil))
			return err
		},
	}, store
}

func cell(dir, base, harnessName string, h Command) Cell {
	f := Fixture{Name: "fix-greeting", Repo: "acme/widget", RepoDir: dir, BaseSHA: base, Brief: "greet.sh must print hello", Verifier: verifier}
	f.Intent = TaskIntent(f)
	return Cell{Fixture: f, Harness: h, Lane: capsule.LaneConfig{Model: "example-model", Harness: harnessName, Effort: "high", ContextPolicy: "none", Runner: "local"}}
}

func mustRun(t *testing.T, plan Plan, deps Deps) *Report {
	t.Helper()
	rep, err := Run(context.Background(), plan, deps)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestM1_4_EveryLaneIsATaggedCapsule(t *testing.T) {
	dir, base := fixture(t)
	deps, store := testDeps(t)
	rep := mustRun(t, Plan{ID: "greeting", K: 2, Cells: []Cell{cell(dir, base, "good-agent", goodHarness), cell(dir, base, "bad-agent", badHarness)}}, deps)
	if len(rep.Cells) != 2 || rep.Schema != "chimera.bench/v1" || rep.Failed() != 0 {
		t.Fatalf("%+v", rep)
	}
	good, bad := rep.Cells[0], rep.Cells[1]
	if good.PassRate != 1 || good.AllPass != 2 || good.K != 2 {
		t.Fatalf("good cell: %+v", good)
	}
	// Criterion pass rate counts criteria: this verifier reports two, and the
	// unfixed tree still meets one of them. x/K counts whole lanes.
	if bad.PassRate != 0.5 || bad.AllPass != 0 {
		t.Fatalf("bad cell: %+v", bad)
	}
	if good.Cell == bad.Cell || len(good.Cell) != 12 {
		t.Fatalf("cell hashes: %s %s", good.Cell, bad.Cell)
	}
	// Every lane is a tagged Capsule in the store.
	addrs, _ := capsule.List(context.Background(), store)
	if len(addrs) != 4 {
		t.Fatalf("%d capsules", len(addrs))
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		l, err := capsule.Get(context.Background(), store, a)
		if err != nil {
			t.Fatal(err)
		}
		m := l.Manifest
		if m.Tag("bench") != "greeting" || m.Tag("fixture") != "fix-greeting" || m.Intent != good.Intent || m.BaseSHA != base || m.Repo != "acme/widget" {
			t.Fatalf("%+v", m)
		}
		seen[m.Tag("cell")+"/"+m.Tag("k")] = true
		for _, name := range []string{capsule.MemberTranscript, capsule.MemberDiff, capsule.MemberVerdicts, capsule.MemberMetrics, "proof/harness.log", "proof/verifier.log"} {
			if _, ok := l.Members[name]; !ok {
				t.Errorf("capsule lacks %s", name)
			}
		}
		if !capsule.ValidCheckpoint(m.Checkpoint) || m.StartedAt == "" || m.EndedAt == "" {
			t.Fatalf("%+v", m)
		}
		raw, err := capsule.Unzstd(l.Members[capsule.MemberTranscript])
		if err != nil || !bytes.Contains(raw, []byte(`"checkpoint":"`+m.Checkpoint+`"`)) {
			t.Fatalf("transcript: %v %s", err, raw)
		}
	}
	for _, want := range []string{good.Cell + "/1", good.Cell + "/2", bad.Cell + "/1", bad.Cell + "/2"} {
		if !seen[want] {
			t.Errorf("no capsule tagged %s (have %v)", want, seen)
		}
	}
}

func TestM1_4_PassRatesAre1And0ForTheTwoHarnesses(t *testing.T) {
	dir, base := fixture(t)
	deps, _ := testDeps(t)
	// No verdicts.json: the verifier's exit code becomes the single criterion.
	exitOnly := Command{Argv: []string{"sh", "-c", `test "$(sh greet.sh)" = hello`}, Timeout: 20 * time.Second}
	good, bad := cell(dir, base, "good-agent", goodHarness), cell(dir, base, "bad-agent", badHarness)
	good.Fixture.Verifier, bad.Fixture.Verifier = exitOnly, exitOnly
	rep := mustRun(t, Plan{ID: "greeting", K: 2, Cells: []Cell{good, bad}}, deps)
	if got := fmt.Sprintf("%.2f %.2f", rep.Cells[0].PassRate, rep.Cells[1].PassRate); got != "1.00 0.00" {
		t.Fatalf("pass rates %s", got)
	}
	v := rep.Cells[1].Lanes[0].Verdicts
	if len(v) != 1 || v[0].ID != "verifier" || v[0].Criterion != "verifier exits 0" || v[0].Pass || !strings.HasPrefix(v[0].Evidence, "exit 1") {
		t.Fatalf("%+v", v)
	}
	if rep.Cells[0].AllPass != 2 || rep.Cells[1].AllPass != 0 {
		t.Fatalf("x/K: %d %d", rep.Cells[0].AllPass, rep.Cells[1].AllPass)
	}
}

func TestM1_4_AllLanesStartFromSameBaseAndTree(t *testing.T) {
	dir, base := fixture(t)
	wantTree := git(t, dir, "rev-parse", base+"^{tree}")
	deps, _ := testDeps(t)
	// The harness changes the tree and leaves junk; the next lane must not see it.
	messy := Command{Argv: []string{"sh", "-c", "test ! -e junk.txt && grep -q helo greet.sh && echo junk > junk.txt && sed -i.bak s/helo/hello/ greet.sh && rm greet.sh.bak"}, Timeout: 20 * time.Second}
	rep := mustRun(t, Plan{ID: "same-start", K: 3, Cells: []Cell{cell(dir, base, "good-agent", messy)}}, deps)
	lanes := rep.Cells[0].Lanes
	if len(lanes) != 3 {
		t.Fatalf("%d lanes", len(lanes))
	}
	checkpoints := map[string]bool{}
	for _, l := range lanes {
		if l.BaseSHA != base || l.Tree != wantTree {
			t.Errorf("lane k=%d started at base %s tree %s", l.K, l.BaseSHA, l.Tree)
		}
		if !l.Pass || l.Transcript[0].Event != "start" || l.Transcript[0].Tree != wantTree || l.Transcript[0].BaseSHA != base {
			t.Errorf("lane k=%d: %+v", l.K, l.Transcript[0])
		}
		if !bytes.Contains(l.Diff, []byte("junk.txt")) || !bytes.Contains(l.Diff, []byte("+echo hello")) {
			t.Errorf("lane k=%d diff:\n%s", l.K, l.Diff)
		}
		checkpoints[l.Checkpoint] = true
	}
	if len(checkpoints) != 3 {
		t.Fatalf("checkpoints not distinct: %v", checkpoints)
	}
	// Identical starts and a deterministic harness give identical diffs.
	if !bytes.Equal(lanes[0].Diff, lanes[1].Diff) || !bytes.Equal(lanes[1].Diff, lanes[2].Diff) {
		t.Fatal("diffs differ between identical-start lanes")
	}
	// The source repository is untouched and no worktree is left behind.
	if st := git(t, dir, "status", "--porcelain"); st != "" {
		t.Fatalf("source repo dirty: %s", st)
	}
	if wt := git(t, dir, "worktree", "list"); strings.Count(wt, "\n") != 0 {
		t.Fatalf("worktrees left: %s", wt)
	}
	if git(t, dir, "rev-parse", "HEAD") != base {
		t.Fatal("history moved")
	}
}

func TestM1_4_HarnessTimeoutYieldsCapsuleWithFailingVerdict(t *testing.T) {
	dir, base := fixture(t)
	deps, store := testDeps(t)
	slow := Command{Argv: []string{"sh", "-c", "echo starting; sleep 30; echo never"}, Timeout: 300 * time.Millisecond}
	start := time.Now()
	rep := mustRun(t, Plan{ID: "timeout", K: 1, Cells: []Cell{cell(dir, base, "slow-agent", slow)}}, deps)
	if time.Since(start) > 15*time.Second {
		t.Fatalf("timeout not enforced: %s", time.Since(start))
	}
	l := rep.Cells[0].Lanes[0]
	if l.Capsule == "" || l.Error != "" || l.Pass {
		t.Fatalf("%+v", l)
	}
	var harness *capsule.Verdict
	for i, v := range l.Verdicts {
		if v.ID == "harness" {
			harness = &l.Verdicts[i]
		}
	}
	if harness == nil || harness.Pass || harness.Criterion != "harness completes within its timeout" || !strings.Contains(harness.Evidence, "timed out after 300ms") {
		t.Fatalf("verdicts: %+v", l.Verdicts)
	}
	// The verifier still ran and judged the unchanged tree.
	if len(l.Verdicts) != 3 || l.Verdicts[1].ID != "[M1-4]" || l.Verdicts[1].Pass {
		t.Fatalf("verdicts: %+v", l.Verdicts)
	}
	addr, _ := capsule.ParseAddress(l.Capsule)
	got, err := capsule.Get(context.Background(), store, addr)
	if err != nil {
		t.Fatal(err)
	}
	vs, _ := got.Verdicts()
	if len(vs) != 3 || vs[0].ID != "harness" || vs[0].Pass {
		t.Fatalf("stored verdicts: %+v", vs)
	}
	if !bytes.Contains(got.Members["proof/harness.log"], []byte("starting")) || bytes.Contains(got.Members["proof/harness.log"], []byte("never")) {
		t.Fatalf("harness log: %q", got.Members["proof/harness.log"])
	}

	// A verifier that exceeds its timeout fails, too.
	c := cell(dir, base, "good-agent", goodHarness)
	c.Fixture.Verifier = Command{Argv: []string{"sleep", "30"}, Timeout: 300 * time.Millisecond}
	rep = mustRun(t, Plan{ID: "timeout", K: 1, Cells: []Cell{c}}, deps)
	v := rep.Cells[0].Lanes[0].Verdicts
	if len(v) != 1 || v[0].Pass || v[0].Criterion != "verifier completes within its timeout" || rep.Cells[0].Lanes[0].Capsule == "" {
		t.Fatalf("%+v", v)
	}
	// A harness that cannot start, and a malformed verdicts.json, fail closed.
	c = cell(dir, base, "ghost", Command{Argv: []string{"no-such-harness-binary"}})
	c.Fixture.Verifier = Command{Argv: []string{"sh", "-c", `echo "not json" > "$CHIMERA_OUT/verdicts.json"`}}
	rep = mustRun(t, Plan{ID: "broken", K: 1, Cells: []Cell{c}}, deps)
	v = rep.Cells[0].Lanes[0].Verdicts
	if len(v) != 2 || v[0].Criterion != "harness starts" || v[0].Pass || v[1].Criterion != "verifier writes a valid verdicts.json" || v[1].Pass {
		t.Fatalf("%+v", v)
	}
}

func TestM1_4_RunEqualsBenchK1(t *testing.T) {
	dir, base := fixture(t)
	deps, _ := testDeps(t)
	c := cell(dir, base, "good-agent", goodHarness)
	// A production run is the same engine with K=1 and no bench tag.
	run := mustRun(t, Plan{K: 1, Cells: []Cell{c}}, deps)
	bench := mustRun(t, Plan{ID: "greeting", K: 1, Cells: []Cell{c}}, deps)
	a, b := run.Cells[0], bench.Cells[0]
	if a.Cell != b.Cell || a.Intent != b.Intent || a.Lane != b.Lane || a.PassRate != b.PassRate || a.AllPass != b.AllPass || a.K != b.K {
		t.Fatalf("cells differ:\n%+v\n%+v", a, b)
	}
	la, lb := a.Lanes[0], b.Lanes[0]
	if !bytes.Equal(la.Diff, lb.Diff) || la.Tree != lb.Tree || la.BaseSHA != lb.BaseSHA || la.Pass != lb.Pass {
		t.Fatal("lanes differ")
	}
	if fmt.Sprint(la.Verdicts) != fmt.Sprint(lb.Verdicts) {
		t.Fatalf("verdicts differ:\n%+v\n%+v", la.Verdicts, lb.Verdicts)
	}
	text := func(evs []Event) string {
		var out []string
		for _, e := range evs {
			if e.Event == "start" || e.Event == "end" || e.WallMS != nil {
				continue // checkpoint IDs and wall times are per-lane
			}
			out = append(out, e.Text())
		}
		return strings.Join(out, "\n")
	}
	if text(la.Transcript) != text(lb.Transcript) {
		t.Fatalf("transcripts differ:\n%s\n---\n%s", text(la.Transcript), text(lb.Transcript))
	}
	if la.Capsule == lb.Capsule || la.Checkpoint == lb.Checkpoint {
		t.Fatal("two lanes share a capsule or checkpoint")
	}
}

func TestM1_4_CostComesOnlyFromReportedUsage(t *testing.T) {
	dir, base := fixture(t)
	deps, _ := testDeps(t)
	reporting := Command{Argv: []string{"sh", "-c", `printf '{"input_tokens":1000000,"output_tokens":500000}' > "{{.OutDir}}/usage.json"`}}
	priced := cell(dir, base, "reporting", reporting)
	priced.Price = &Price{InputPerMTok: 1, OutputPerMTok: 4}
	silent := cell(dir, base, "silent", badHarness)
	silent.Price = &Price{InputPerMTok: 1, OutputPerMTok: 4}
	unpriced := cell(dir, base, "reporting-unpriced", reporting)
	rep := mustRun(t, Plan{ID: "cost", K: 2, Cells: []Cell{priced, silent, unpriced}}, deps)
	if c := rep.Cells[0].CostUSD; c == nil || *c != 3.0 {
		t.Fatalf("priced cost %v", c)
	}
	if rep.Cells[1].CostUSD != nil || rep.Cells[2].CostUSD != nil {
		t.Fatalf("cost was estimated: %v %v", rep.Cells[1].CostUSD, rep.Cells[2].CostUSD)
	}
	if FormatCost(rep.Cells[1].CostUSD) != "—" || FormatCost(rep.Cells[0].CostUSD) != "$3.0000" {
		t.Fatal("cost formatting")
	}
}

func TestM1_4_Ring0PathsAreReadOnlyAndChangesFail(t *testing.T) {
	dir, base := fixture(t)
	deps, _ := testDeps(t)
	deps.Ring0 = func(p string) bool { return strings.HasPrefix(p, "verify/") }
	// A plain write is refused by the read-only bit; a determined harness that
	// replaces the file is caught by the diff.
	polite := Command{Argv: []string{"sh", "-c", "echo tampered >> verify/check.sh 2>/dev/null; sed -i.bak s/helo/hello/ greet.sh; rm -f greet.sh.bak"}}
	rude := Command{Argv: []string{"sh", "-c", "rm -f verify/check.sh && printf '#!/bin/sh\\nexit 0\\n' > verify/check.sh"}}
	rep := mustRun(t, Plan{ID: "ring0", K: 1, Cells: []Cell{cell(dir, base, "polite", polite), cell(dir, base, "rude", rude)}}, deps)
	a, b := rep.Cells[0].Lanes[0], rep.Cells[1].Lanes[0]
	if os.Geteuid() != 0 {
		if bytes.Contains(a.Diff, []byte("verify/check.sh")) || !a.Pass {
			t.Fatalf("read-only Ring-0 file was modified: %+v\n%s", a.Verdicts, a.Diff)
		}
	}
	last := b.Verdicts[len(b.Verdicts)-1]
	if b.Pass || last.ID != "ring0" || last.Evidence != "changed: verify/check.sh" || RiskClass(b) != "R3" {
		t.Fatalf("%+v", b.Verdicts)
	}
}

const fakeBoat = `#!/bin/sh
# Fake boat CLI: a sandbox is a directory under $FAKE_BOAT_ROOT.
echo "$1" >> "$FAKE_BOAT_ROOT/calls.log"
cmd=$1; shift
case "$cmd" in
  new)
    n=$(ls -d "$FAKE_BOAT_ROOT"/bx_* 2>/dev/null | wc -l | tr -d ' ')
    id="bx_fake$n"; mkdir -p "$FAKE_BOAT_ROOT/$id"
    echo "note: this line is on stderr" >&2
    echo "{\"id\":\"$id\",\"status\":\"ready\"}" ;;
  ssh)
    id=$1; shift
    cd "$FAKE_BOAT_ROOT/$id" && HOME="$FAKE_BOAT_ROOT/$id" GIT_CONFIG_GLOBAL=/dev/null sh -c "$*" ;;
  scp)
    dst=$2; id=${dst%%:*}; path=${dst#*:}
    mkdir -p "$(dirname "$FAKE_BOAT_ROOT/$id/$path")" && cp "$1" "$FAKE_BOAT_ROOT/$id/$path" ;;
  delete)
    test "$2" = "--yes" || exit 64
    rm -rf "$FAKE_BOAT_ROOT/$1"; echo "deleted $1" >> "$FAKE_BOAT_ROOT/calls.log" ;;
  *) exit 64 ;;
esac
`

func TestM1_4_BoatRunnerWithFakeExecutable(t *testing.T) {
	dir, base := fixture(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "boat"), []byte(fakeBoat), 0o755); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("FAKE_BOAT_ROOT", root)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	deps, store := testDeps(t)
	c := cell(dir, base, "good-agent", goodHarness)
	c.Lane.Runner = "boat"
	slow := cell(dir, base, "slow-agent", Command{Argv: []string{"sleep", "30"}, Timeout: 400 * time.Millisecond})
	slow.Lane.Runner = "boat"
	rep := mustRun(t, Plan{ID: "remote", K: 1, Cells: []Cell{c, slow}}, deps)
	l := rep.Cells[0].Lanes[0]
	if l.Error != "" || !l.Pass || l.Capsule == "" {
		t.Fatalf("%+v", l)
	}
	// The remote checkout is the same tree, so diffs carry the same blob IDs
	// a local lane would produce.
	if l.Tree != git(t, dir, "rev-parse", base+"^{tree}") {
		t.Fatalf("remote tree %s", l.Tree)
	}
	local := mustRun(t, Plan{ID: "remote", K: 1, Cells: []Cell{cell(dir, base, "good-agent", goodHarness)}}, deps)
	if !bytes.Equal(l.Diff, local.Cells[0].Lanes[0].Diff) {
		t.Fatalf("remote diff differs from local:\n%s\n---\n%s", l.Diff, local.Cells[0].Lanes[0].Diff)
	}
	addr, _ := capsule.ParseAddress(l.Capsule)
	got, err := capsule.Get(context.Background(), store, addr)
	if err != nil || got.Manifest.Lane.Runner != "boat" {
		t.Fatalf("%v %+v", err, got)
	}
	if s := rep.Cells[1].Lanes[0]; s.Capsule == "" || s.Pass || s.Verdicts[0].ID != "harness" {
		t.Fatalf("remote timeout: %+v", s)
	}
	// Every sandbox that was created was deleted, even after a timeout.
	log, _ := os.ReadFile(filepath.Join(root, "calls.log"))
	calls := string(log)
	if strings.Count(calls, "new\n") != 2 || strings.Count(calls, "deleted bx_fake") != 2 || !strings.Contains(calls, "scp\n") || !strings.Contains(calls, "ssh\n") {
		t.Fatalf("calls:\n%s", calls)
	}
	left, _ := filepath.Glob(filepath.Join(root, "bx_*"))
	if len(left) != 0 {
		t.Fatalf("sandboxes left behind: %v", left)
	}
	// A boat that cannot create a sandbox is a lane with no capsule: missing proof.
	os.WriteFile(filepath.Join(bin, "boat"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
	rep = mustRun(t, Plan{ID: "remote", K: 1, Cells: []Cell{c}}, deps)
	if l := rep.Cells[0].Lanes[0]; l.Capsule != "" || l.Error != "runner boat: boat new failed" || rep.Failed() != 1 {
		t.Fatalf("%+v", l)
	}
}

func TestM1_4_SecretInHarnessOutputBlocksTheCapsule(t *testing.T) {
	dir, base := fixture(t)
	deps, store := testDeps(t)
	leak := Command{Argv: []string{"sh", "-c", `echo "token is ghp_$(printf %036d 7 | tr 0 a)"`}}
	rep := mustRun(t, Plan{ID: "leak", K: 1, Cells: []Cell{cell(dir, base, "leaky", leak)}}, deps)
	l := rep.Cells[0].Lanes[0]
	if l.Capsule != "" || l.Pass || !strings.Contains(l.Error, "secret gate") || rep.Failed() != 1 {
		t.Fatalf("%+v", l)
	}
	if strings.Contains(l.Error, "ghp_") {
		t.Fatal("error echoes the secret")
	}
	if addrs, _ := capsule.List(context.Background(), store); len(addrs) != 0 {
		t.Fatalf("capsule stored despite the gate: %v", addrs)
	}
}

func TestM1_4_MatrixExpandsCrossProductInOrder(t *testing.T) {
	m, err := ParseMatrix([]byte(`
k: 3
fixtures:
  - name: fix-greeting
    repo: .
    task_brief: greet.sh must print hello
    verifier: { command: ["sh", "verify/check.sh"], timeout: 30s }
  - name: named-verifier
    verifier: default
axes:
  model: [m1, m2]
  harness: [good-agent, bad-agent]
  effort: [low, high]
`))
	if err != nil {
		t.Fatal(err)
	}
	if m.K != 3 || len(m.ID) != 12 || m.Fixtures[1].Verifier.Name != "default" || m.Fixtures[0].Verifier.Timeout != "30s" {
		t.Fatalf("%+v", m)
	}
	lcs := m.Axes.LaneConfigs()
	var got []string
	for _, lc := range lcs {
		got = append(got, lc.Model+"/"+lc.Harness+"/"+lc.Effort+"/"+lc.ContextPolicy+"/"+lc.Runner)
	}
	want := "m1/good-agent/low/none/local m1/good-agent/high/none/local m1/bad-agent/low/none/local m1/bad-agent/high/none/local " +
		"m2/good-agent/low/none/local m2/good-agent/high/none/local m2/bad-agent/low/none/local m2/bad-agent/high/none/local"
	if strings.Join(got, " ") != want {
		t.Fatalf("%v", got)
	}
	for _, bad := range []string{"fixtures: []\naxes: {harness: [a]}", "fixtures: [{name: x}]\naxes: {}", "fixtures: [{name: x}]\naxes: {harness: [a], context_policy: [pull]}", "fixtures: [{name: x}]\naxes: {harness: [a]}\nbogus: 1"} {
		if _, err := ParseMatrix([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	f := Fixture{Repo: "acme/widget", BaseSHA: strings.Repeat("a", 40), Brief: "b", Verifier: verifier}
	g := f
	g.Brief = "c"
	if TaskIntent(f) != TaskIntent(f) || TaskIntent(f) == TaskIntent(g) || !capsule.ValidIntent(TaskIntent(f)) {
		t.Fatal("task intent is not a stable content address")
	}
}

func TestM1_4_PercentilesAreNearestRank(t *testing.T) {
	s := []int64{50, 10, 40, 20, 30, 60, 70, 80, 90, 100}
	if Percentile(s, 50) != 50 || Percentile(s, 90) != 90 || Percentile(s[:1], 90) != 50 || Percentile(nil, 50) != 0 {
		t.Fatalf("p50=%d p90=%d", Percentile(s, 50), Percentile(s, 90))
	}
	if FormatDuration(1420) != "1.42s" || FormatDuration(187000) != "3m07s" {
		t.Fatalf("%s %s", FormatDuration(1420), FormatDuration(187000))
	}
}

func sha(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestM1_4_ReportBundleFollowsDesignAndShipsLockedAssets(t *testing.T) {
	dir, base := fixture(t)
	deps, _ := testDeps(t)
	slow := Command{Argv: []string{"sleep", "30"}, Timeout: 300 * time.Millisecond}
	rep := mustRun(t, Plan{ID: "greeting", K: 2, Cells: []Cell{cell(dir, base, "good-agent", goodHarness), cell(dir, base, "bad-agent", badHarness), cell(dir, base, "slow-agent", slow)}}, deps)
	out := filepath.Join(t.TempDir(), "report")
	if err := WritePage(out, rep); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	// The locked Folio assets are shipped byte-for-byte.
	if got := sha(read("favicon.svg")); got != "dc98e47e34fa87a7856088769013bd5a3ec2a631fbece9190cb8d6e7e165d7d5" {
		t.Errorf("favicon.svg sha256 %s", got)
	}
	if got := sha(read("media/capsule-write.svg")); got != "a778295fb943d0e0ca073862e67fad39b140a1c0ac84e49993316b85234ba289" {
		t.Errorf("capsule-write.svg sha256 %s", got)
	}
	for _, name := range lockedAssets {
		src, err := os.ReadFile(filepath.Join("..", "..", "folio", "assets", "trail-reference", filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(src, read(name)) {
			t.Errorf("%s differs from the Folio asset (%v)", name, err)
		}
	}
	ref, _ := os.ReadFile(filepath.Join("..", "..", "folio", "assets", "trail-reference", "trail.css"))
	css := read("trail.css")
	if !bytes.HasPrefix(css, ref) || !bytes.Contains(css[len(ref):], []byte(".best { font-weight: 600; }")) {
		t.Error("trail.css is not the reference stylesheet plus the bench rules")
	}
	if bytes.Contains(bytes.ToLower(css), []byte("inter")) && bytes.Contains(css, []byte(`"Inter"`)) {
		t.Error("Inter in the font stack")
	}

	html := string(read("index.html"))
	// Platform rules: strict CSP, nothing inline, nothing third-party.
	for _, banned := range []string{"<style", "<script", " style=", "http://", "https://", "onclick", "Great news"} {
		if strings.Contains(html, banned) {
			t.Errorf("page contains %q", banned)
		}
	}
	for _, want := range []string{
		`<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`,
		`<link rel="stylesheet" href="trail.css">`, `<link rel="icon" href="favicon.svg" type="image/svg+xml">`,
		`<p class="wordmark">chimera / bench</p>`, `<span class="mono">bench:greeting</span>`,
		`<img src="media/capsule-write.svg" width="720" height="200" alt="`,
		`<th scope="col">Pass rate</th><th scope="col">x/K</th><th scope="col">Wall p50</th><th scope="col">Wall p90</th><th scope="col">Cost</th>`,
		`<td class="num best">1.00</td><td class="num best">2/2</td>`, `<td class="num">0.50</td><td class="num">0/2</td>`,
		`<span class="risk">R1</span>`, `<p class="none">None.</p>`, `<span class="state">FAIL</span>`, `<td class="num">—</td>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Failures first: section order is fixed.
	order := []string{`id="risk"`, `id="unmet"`, `id="missing"`, `id="bench"`, `id="verdicts"`, `id="media"`, `id="lanes"`}
	pos := -1
	for _, id := range order {
		i := strings.Index(html, "<section "+id)
		if i <= pos {
			t.Fatalf("section %s out of order", id)
		}
		pos = i
	}
	// The timed-out lanes are open risk; the unfixed greeting is unmet intent.
	risk := html[strings.Index(html, `<section id="risk"`):strings.Index(html, `<section id="unmet"`)]
	if strings.Count(risk, `<tr class="fail">`) != 2 || !strings.Contains(risk, "harness completes within its timeout") {
		t.Errorf("open risk section:\n%s", risk)
	}
	unmet := html[strings.Index(html, `<section id="unmet"`):strings.Index(html, `<section id="missing"`)]
	if strings.Count(unmet, "greet.sh prints hello") != 2 || strings.Contains(unmet, "greet.sh exists") {
		t.Errorf("unmet intent section:\n%s", unmet)
	}
	// One click to the transcript: every verdict link resolves to a line anchor.
	verdicts := html[strings.Index(html, `<section id="verdicts"`):strings.Index(html, `<section id="media"`)]
	links := strings.Split(verdicts, `<a href="#`)[1:]
	if len(links) != 14 {
		t.Fatalf("%d verdict links", len(links))
	}
	for _, l := range links {
		anchor := l[:strings.Index(l, `"`)]
		if !strings.HasPrefix(anchor, "t-") || !strings.Contains(html, `<li id="`+anchor+`">`) {
			t.Errorf("verdict link #%s has no transcript line", anchor)
		}
	}
	if strings.Index(verdicts, `class="fail"`) > strings.Index(verdicts, "<tr><td") {
		t.Error("failing verdicts are not listed first")
	}
	if strings.Count(html, "<details id=") != 6 || strings.Count(html, "<h1>") != 1 {
		t.Error("lane drill-downs or headings")
	}
	// Same report, same bytes.
	again, _ := RenderPage(rep)
	if string(again) != html {
		t.Fatal("page is not deterministic")
	}
}
