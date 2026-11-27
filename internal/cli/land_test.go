package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/land"
	"chimera/pkg/objstore"
)

// landVerifier passes any tree except one holding both a.flag and b.flag:
// each change passes on its own, the pair fails only once rebased together.
const landVerifier = `#!/bin/sh
if [ -f a.flag ] && [ -f b.flag ]; then p=false; else p=true; fi
printf '[{"id":"[M2-2]","criterion":"a.flag and b.flag never ship together","pass":%s,"evidence":"checked the rebased tree"}]\n' "$p" > "$CHIMERA_OUT/verdicts.json"
`

// landFixture is a bare repository acting as the forge, with four agent
// branches authored from the same base, plus the lander's own clone of it
// and a config pointing the CLI at both.
func landFixture(t *testing.T) (bare, lander, cfg, state string) {
	t.Helper()
	seed := fixtureRepo(t, map[string]string{"README.md": "# widget\n", "verify/check.sh": landVerifier})
	branch := func(name string, files map[string]string, msg string) {
		git(t, seed, "checkout", "-q", "-b", name, "main")
		writeFiles(t, seed, files)
		commitAll(t, seed, msg)
	}
	branch("agent-a", map[string]string{"a.flag": "a\n"}, "flags: add a\n\nChimera-Intent: "+fxIntent+"\nChimera-Capsule: sha256:"+strings.Repeat("a1", 32))
	branch("agent-b", map[string]string{"b.flag": "b\n"}, "flags: add b")
	branch("agent-c", map[string]string{"c.txt": "c\n"}, "docs: add c")
	branch("agent-r", map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"}, "verify: always pass")
	git(t, seed, "checkout", "-q", "main")
	root := t.TempDir()
	bare, lander, state = filepath.Join(root, "forge.git"), filepath.Join(root, "lander"), filepath.Join(root, "state")
	git(t, root, "clone", "-q", "--bare", seed, bare)
	git(t, root, "clone", "-q", bare, lander)
	cfg = writeConfig(t, `tenant:
  repos: [acme/widget]
store:
  endpoint: file://`+filepath.Join(state, "store")+`
ledger:
  path: `+filepath.Join(state, "ledger.db")+`
ring0:
  paths: ["verify/**"]
forge:
  kind: git
  dir: `+bare+`
land:
  target: main
  remote: origin
verifiers:
  default: { command: ["sh", "verify/check.sh"], timeout: 30s }
`)
	return bare, lander, cfg, state
}

func noEscapes(t *testing.T, r result) {
	t.Helper()
	if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
		t.Fatalf("escape byte off a TTY: %+v", r)
	}
}

func TestM2_2_LandEnqueueStatusRunEndToEnd(t *testing.T) {
	bare, lander, cfg, state := landFixture(t)
	base := gitOut(t, bare, "rev-parse", "main")
	headA := gitOut(t, bare, "rev-parse", "agent-a")

	// Nothing queued, no epoch yet.
	r := run(t, lander, nil, "land", "status", "--config", cfg, "--json")
	var st land.StatusReport
	if err := json.Unmarshal([]byte(r.stdout), &st); err != nil || r.code != ExitOK {
		t.Fatalf("status: %+v %v", r, err)
	}
	if st.Schema != "chimera.land.status/v1" || st.Repo != "acme/widget" || st.Target != "main" || string(st.Head) != base || st.Epoch != 0 || st.Queue == nil || st.Outcomes == nil || len(st.Queue)+len(st.Outcomes) != 0 {
		t.Fatalf("empty status: %+v", st)
	}
	if !strings.HasPrefix(r.stdout, `{"schema":"chimera.land.status/v1",`) {
		t.Fatalf("schema is not first: %s", r.stdout)
	}

	// enqueue: data on stdout, exit 0; the forge now holds the queue ref.
	r = run(t, lander, nil, "land", "enqueue", "agent-a", "--config", cfg)
	if r.code != ExitOK || r.stdout != "POS  SEQ  BRANCH   HEAD          TARGET  STATE\n1    1    agent-a  "+headA[:12]+"  main    PENDING\n" ||
		!strings.Contains(r.stderr, "position 1 for main") {
		t.Fatalf("enqueue a: %+v", r)
	}
	noEscapes(t, r)
	if got := gitOut(t, bare, "rev-parse", "refs/chimera/land/main/00000001/agent-a"); got != headA {
		t.Fatalf("queue ref at %s", got)
	}
	r = run(t, lander, nil, "land", "enqueue", "refs/heads/agent-b", "--config", cfg, "--json", "-q")
	var enq enqueueResult
	if err := json.Unmarshal([]byte(r.stdout), &enq); err != nil || r.code != ExitOK || r.stderr != "" {
		t.Fatalf("enqueue b: %+v %v", r, err)
	}
	if enq.Schema != "chimera.land.enqueue/v1" || enq.Position != 2 || !enq.Created || enq.Change.Branch != "agent-b" || enq.Change.Seq != 2 || enq.Change.Target != "main" ||
		enq.Change.Ref != "refs/chimera/land/main/00000002/agent-b" || enq.Change.ID != "2/agent-b" {
		t.Fatalf("enqueue b: %+v", enq)
	}
	for _, b := range []string{"agent-c", "agent-r"} {
		if r := run(t, lander, nil, "land", "enqueue", b, "--config", cfg, "-q"); r.code != ExitOK {
			t.Fatalf("enqueue %s: %+v", b, r)
		}
	}
	// The same commit again changes nothing.
	r = run(t, lander, nil, "land", "enqueue", "agent-a", "--config", cfg, "--json")
	if json.Unmarshal([]byte(r.stdout), &enq); r.code != ExitOK || enq.Created || enq.Position != 1 || !strings.Contains(r.stderr, "already queued") {
		t.Fatalf("re-enqueue: %+v", r)
	}
	// A branch the forge does not have.
	r = run(t, lander, nil, "land", "enqueue", "no-such", "--config", cfg)
	if r.code != ExitError || r.stdout != "" || r.stderr != "chimera: land enqueue: no-such: branch not found on the forge; nothing queued; push the branch first\n" {
		t.Fatalf("enqueue missing: %+v", r)
	}

	// status <branch> while queued: exit 3, pending.
	r = run(t, lander, nil, "land", "status", "agent-c", "--config", cfg)
	if r.code != ExitPending || !strings.Contains(r.stdout, "3    3    agent-c") || !strings.HasPrefix(r.stderr, "chimera: land status: agent-c: pending at position 3 of 4 for main; ") {
		t.Fatalf("status queued: %+v", r)
	}
	oneLowercaseErrorLine(t, []string{"land", "status", "agent-c"}, r.stderr)
	r = run(t, lander, nil, "land", "status", "agent-c", "--config", cfg, "--json")
	var env errorEnvelope
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil || r.code != ExitPending || env.Schema != "chimera.error/v1" || env.Code != 3 || env.Command != "land status" || len(env.Findings) != 1 {
		t.Fatalf("status queued --json: %+v %v", r, err)
	}
	r = run(t, lander, nil, "land", "status", "--config", cfg)
	if r.code != ExitOK || !strings.Contains(r.stdout, "TARGET  main") || !strings.Contains(r.stdout, "EPOCH   0") || strings.Count(r.stdout, "PENDING") != 4 ||
		!strings.Contains(r.stdout, "POS  SEQ  BRANCH   HEAD          STATE\n") || !strings.Contains(r.stdout, "STATE  BRANCH  HEAD  LANDED  EPOCH  AT  DETAIL\n") {
		t.Fatalf("status table: %+v", r)
	}
	noEscapes(t, r)

	// run: a lands; b is evicted because the REBASED tree fails; c lands;
	// r touches Ring-0 without owner approval and is evicted. Exit 1.
	r = run(t, lander, nil, "land", "run", "--config", cfg, "-q")
	if r.code != ExitError {
		t.Fatalf("run: %+v", r)
	}
	noEscapes(t, r)
	oneLowercaseErrorLine(t, []string{"land", "run"}, r.stderr)
	if !strings.HasPrefix(r.stderr, "chimera: land run: 2 of 4 changes evicted (agent-b: verifier failed ([M2-2] a.flag and b.flag never ship together), capsule sha256:") ||
		!strings.HasSuffix(r.stderr, "; 2 landed on main; each owner was told the reason\n") {
		t.Fatalf("run stderr: %q", r.stderr)
	}
	// Humans get 12 hex characters; the full address stays in JSON and the store.
	if regexp.MustCompile(`[0-9a-f]{13,}`).MatchString(r.stdout + r.stderr) {
		t.Fatalf("a hash is printed in full for humans: %+v", r)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "STATE    BRANCH   HEAD          LANDED") || !strings.HasPrefix(lines[1], "LANDED   agent-a  "+headA[:12]+"  "+headA[:12]+"  sha256:") ||
		!strings.HasPrefix(lines[2], "EVICTED  agent-b  ") || !strings.Contains(lines[2], "  —  ") || !strings.HasPrefix(lines[3], "LANDED   agent-c  ") ||
		!strings.HasPrefix(lines[4], "EVICTED  agent-r  ") || !strings.Contains(lines[4], "touches Ring-0 (verify/check.sh); needs explicit owner approval") {
		t.Fatalf("run table:\n%s", r.stdout)
	}
	// The forge: linear main with a then c (rebased), no queue or staging refs,
	// the agents' branches untouched, the reasons delivered.
	if got := gitOut(t, bare, "log", "--format=%s", base+"..main"); got != "docs: add c\nflags: add a" {
		t.Fatalf("forge history:\n%s", got)
	}
	head := gitOut(t, bare, "rev-parse", "main")
	if gitOut(t, bare, "rev-parse", "main~1") != headA || head == gitOut(t, bare, "rev-parse", "agent-c") || gitOut(t, bare, "rev-list", "--merges", "--count", "main") != "0" {
		t.Fatal("main is not a (as authored) then c (rebased)")
	}
	if got := gitOut(t, bare, "ls-tree", "-r", "--name-only", "main"); got != "README.md\na.flag\nc.txt\nverify/check.sh" {
		t.Fatalf("landed tree:\n%s", got)
	}
	if got := gitOut(t, bare, "log", "-1", "--format=%(trailers:only)", "main~1"); !strings.Contains(got, "Chimera-Intent: "+fxIntent) || !strings.Contains(got, "Chimera-Capsule: sha256:a1a1") {
		t.Fatalf("landed a lost its trailers:\n%s", got)
	}
	if refs := gitOut(t, bare, "for-each-ref", "--format=%(refname)", "refs/chimera"); refs != "" {
		t.Fatalf("refs left on the forge:\n%s", refs)
	}
	events, err := (&forge.Git{Dir: bare}).Events(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, e := range events {
		k := e.Kind
		if e.Check != nil {
			k += ":" + string(e.Check.State)
		}
		kinds[k]++
	}
	if kinds["report:PASS"] != 2 || kinds["report:FAIL"] != 2 || kinds["notify"] != 2 {
		t.Fatalf("forge events: %+v", kinds)
	}
	// The lander's checkout and branches were never touched.
	if gitOut(t, lander, "rev-parse", "HEAD") != base || gitOut(t, lander, "status", "--porcelain") != "" || strings.Count(gitOut(t, lander, "worktree", "list"), "\n") != 0 {
		t.Fatal("the lander's own checkout changed")
	}

	// Every verdict is a real Capsule recorded against the rebased commit.
	store := objstore.NewDir(filepath.Join(state, "store"))
	addrs, err := capsule.List(context.Background(), store)
	if err != nil || len(addrs) != 3 {
		t.Fatalf("capsules: %v %v", addrs, err)
	}
	bases := map[string]bool{}
	for _, a := range addrs {
		l, err := capsule.Get(context.Background(), store, a)
		if err != nil {
			t.Fatal(err)
		}
		bases[l.Manifest.BaseSHA] = true
		if l.Manifest.Tag("land") != "main" || l.Manifest.Tag("epoch") != "1" || l.Manifest.Repo != "acme/widget" {
			t.Fatalf("capsule manifest: %+v", l.Manifest)
		}
	}
	if !bases[headA] || !bases[head] || bases[gitOut(t, bare, "rev-parse", "agent-b")] || bases[gitOut(t, bare, "rev-parse", "agent-c")] {
		t.Fatalf("capsules were not recorded against the rebased commits: %v", bases)
	}
	// The store holds the epoch, a push intent per pushed change, and one
	// outcome per change, keyed by sequence, head, and epoch.
	keys, _ := store.List(context.Background(), "land/acme/widget/")
	var kinds2 []string
	for _, k := range keys {
		kinds2 = append(kinds2, strings.SplitN(strings.TrimPrefix(k, "land/acme/widget/"), "/", 2)[0])
	}
	if strings.Join(kinds2, ",") != "attempt,attempt,epoch-1,outcome,outcome,outcome,outcome" ||
		keys[0] != "land/acme/widget/attempt/main/00000001-"+headA[:12]+"/"+headA[:12]+".json" || keys[1] != "land/acme/widget/attempt/main/00000003-"+gitOut(t, bare, "rev-parse", "agent-c")[:12]+"/"+head[:12]+".json" ||
		keys[3] != "land/acme/widget/outcome/main/00000001-"+headA[:12]+"-e1.json" {
		t.Fatalf("land keys: %v", keys)
	}

	// status per branch: 0 landed, 1 evicted with the reason, 1 unknown.
	r = run(t, lander, nil, "land", "status", "agent-a", "--config", cfg)
	if r.code != ExitOK || r.stderr != "" || !strings.Contains(r.stdout, "LANDED  agent-a  "+headA[:12]+"  "+headA[:12]+"  1  ") {
		t.Fatalf("status landed: %+v", r)
	}
	r = run(t, lander, nil, "land", "status", "agent-c", "--config", cfg, "--json")
	if err := json.Unmarshal([]byte(r.stdout), &st); err != nil || r.code != ExitOK || len(st.Outcomes) != 1 || st.Outcomes[0].State != "LANDED" || string(st.Outcomes[0].Landed) != head ||
		st.Epoch != 1 || !strings.HasPrefix(st.Holder, "pid-") || string(st.Head) != head {
		t.Fatalf("status landed --json: %+v %v", r, err)
	}
	r = run(t, lander, nil, "land", "status", "agent-b", "--config", cfg)
	if r.code != ExitError || !strings.HasPrefix(r.stderr, "chimera: land status: agent-b: evicted: verifier failed (") || !strings.Contains(r.stdout, "EVICTED  agent-b") {
		t.Fatalf("status evicted: %+v", r)
	}
	r = run(t, lander, nil, "land", "status", "nobody", "--config", cfg)
	if r.code != ExitError || r.stdout != "" || !strings.Contains(r.stderr, "nobody: not queued and no outcome recorded for main") {
		t.Fatalf("status unknown: %+v", r)
	}
	r = run(t, lander, nil, "land", "status", "--config", cfg)
	if r.code != ExitOK || strings.Count(r.stdout, "\nLANDED ") != 2 || strings.Count(r.stdout, "\nEVICTED ") != 2 || !strings.Contains(r.stdout, "EPOCH   1") {
		t.Fatalf("final status: %+v", r)
	}

	// A second run finds the queue empty: exit 0, a new epoch.
	r = run(t, lander, nil, "land", "run", "--config", cfg, "--json")
	var res landRunResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != ExitOK || res.Schema != "chimera.land.run/v1" || res.Epoch != 2 || res.Results == nil || len(res.Results) != 0 ||
		res.Repo != "acme/widget" || res.Target != "main" || !strings.Contains(r.stderr, "queue for main is empty") {
		t.Fatalf("empty run: %+v %v", r, err)
	}
}

func TestM2_2_LandRunSquashOnASingleRepositoryAndRefusesACheckedOutTarget(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{"README.md": "# widget\n", "verify/check.sh": landVerifier})
	base := gitOut(t, repo, "rev-parse", "main")
	git(t, repo, "checkout", "-q", "-b", "feature")
	writeFiles(t, repo, map[string]string{"one.txt": "1\n"})
	commitAll(t, repo, "feat: one\n\nChimera-Intent: "+fxIntent+"\nChimera-Capsule: sha256:"+strings.Repeat("01", 32)+"\nSigned-off-by: Dev <dev@example.com>")
	writeFiles(t, repo, map[string]string{"two.txt": "2\n"})
	commitAll(t, repo, "feat: two\n\nChimera-Intent: "+fxIntent+"\nChimera-Capsule: sha256:"+strings.Repeat("02", 32)+"\nSigned-off-by: Dev <dev@example.com>")
	git(t, repo, "checkout", "-q", "main")
	state := t.TempDir()
	cfg := writeConfig(t, "store:\n  endpoint: file://"+filepath.Join(state, "store")+"\nledger:\n  path: "+filepath.Join(state, "ledger.db")+
		"\nforge:\n  kind: git\nland:\n  target: main\n  strategy: squash\nverifiers:\n  check: { command: [\"sh\", \"verify/check.sh\"], timeout: 30s }\n")
	if r := run(t, repo, nil, "land", "enqueue", "feature", "--config", cfg, "-q"); r.code != ExitOK {
		t.Fatalf("enqueue: %+v", r)
	}
	// The forge is this work tree and main is checked out: refuse before anything moves.
	r := run(t, repo, nil, "land", "run", "--config", cfg, "--verifier", "check", "--repo", "acme/widget")
	if r.code != ExitUsage || !strings.Contains(r.stderr, "--target: main is checked out in "+repo+"; ") || gitOut(t, repo, "rev-parse", "main") != base {
		t.Fatalf("checked-out target: %+v", r)
	}
	// The configured default verifier does not exist: usage, nothing attempted.
	git(t, repo, "checkout", "-q", "--detach")
	if r := run(t, repo, nil, "land", "run", "--config", cfg, "--repo", "acme/widget"); r.code != ExitUsage || !strings.Contains(r.stderr, `verifier "default": not configured`) {
		t.Fatalf("missing verifier: %+v", r)
	}
	r = run(t, repo, nil, "land", "run", "--config", cfg, "--verifier", "check", "--repo", "acme/widget", "--json", "--once")
	var res landRunResult
	if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != ExitOK || len(res.Results) != 1 || res.Results[0].State != "LANDED" || res.Results[0].Attempts != 1 ||
		!strings.HasPrefix(res.Results[0].Capsule, "sha256:") || res.Epoch != 1 {
		t.Fatalf("squash run: %+v %v", r, err)
	}
	landed := gitOut(t, repo, "rev-parse", "main")
	if landed != string(res.Results[0].Landed) || gitOut(t, repo, "rev-parse", "main~1") != base {
		t.Fatalf("main is not one commit on the base: %s", landed)
	}
	want := "Chimera-Intent: " + fxIntent + "\nChimera-Capsule: sha256:" + strings.Repeat("01", 32) + "\nSigned-off-by: Dev <dev@example.com>\nChimera-Capsule: sha256:" + strings.Repeat("02", 32)
	if got := gitOut(t, repo, "log", "-1", "--format=%(trailers:only)", "main"); got != want {
		t.Fatalf("squash trailers:\n%s", got)
	}
	if got := gitOut(t, repo, "log", "-1", "--format=%s", "main"); got != "feat: one" {
		t.Fatalf("squash subject: %s", got)
	}
	// The landing Capsule is recorded against the change's own Intent.
	store := objstore.NewDir(filepath.Join(state, "store"))
	addr, _ := capsule.ParseAddress(res.Results[0].Capsule)
	l, err := capsule.Get(context.Background(), store, addr)
	if err != nil || l.Manifest.Intent != fxIntent || l.Manifest.BaseSHA != landed || l.Manifest.Tag("change") != "1/feature" {
		t.Fatalf("landing capsule: %+v %v", l, err)
	}
}

func TestM2_2_LandUsageErrorsExit2AndAnUnreachableForgeIsPending(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{"README.md": "# widget\n"})
	state := t.TempDir()
	storeYAML := "store:\n  endpoint: file://" + filepath.Join(state, "store") + "\n"
	cases := []struct {
		name string
		cfg  string
		env  map[string]string
		args []string
		want string
	}{
		{"no forge", storeYAML + "land:\n  target: main\n", nil, []string{"land", "status"}, "forge.kind: not configured"},
		{"no target", storeYAML + "forge:\n  kind: git\n", nil, []string{"land", "enqueue", "x"}, "--target: not given and land.target is not configured"},
		{"no token", storeYAML + "forge:\n  kind: github\n  repo: acme/widget\nland:\n  target: main\n", nil, []string{"land", "enqueue", "x"}, "CHIMERA_FORGE_TOKEN is <unset>"},
		{"bad repo", storeYAML + "forge:\n  kind: github\n  repo: widget\nland:\n  target: main\n", nil, []string{"land", "status"}, "forge.repo: must be owner/name"},
		{"no store", "forge:\n  kind: git\nland:\n  target: main\n", nil, []string{"land", "status"}, "store"},
		{"bad kind", storeYAML + "forge:\n  kind: svn\n", nil, []string{"land", "status"}, "forge.kind: must be github or git"},
		{"bad strategy", storeYAML + "land:\n  strategy: merge\n", nil, []string{"land", "run"}, "land.strategy: must be rebase or squash"},
		{"no repo name", storeYAML + "forge:\n  kind: git\nland:\n  target: main\nverifiers:\n  default: { command: [\"true\"] }\n", nil, []string{"land", "run"}, "--repo: repository name not configured; set forge.repo or pass --repo"},
		{"no repo name for status", storeYAML + "forge:\n  kind: git\nland:\n  target: main\n", nil, []string{"land", "status"}, "--repo: repository name not configured"},
		{"no branch", storeYAML + "forge:\n  kind: git\nland:\n  target: main\n", nil, []string{"land", "enqueue"}, "wrong number of arguments"},
		{"two branches", storeYAML + "forge:\n  kind: git\nland:\n  target: main\n", nil, []string{"land", "status", "a", "b"}, "wrong number of arguments"},
		{"unknown flag", storeYAML + "forge:\n  kind: git\nland:\n  target: main\n", nil, []string{"land", "enqueue", "x", "--squash"}, "unknown flag"},
	}
	for _, tc := range cases {
		cfg := writeConfig(t, tc.cfg)
		r := run(t, repo, tc.env, append(tc.args, "--config", cfg)...)
		if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, tc.want) {
			t.Errorf("%s: %+v", tc.name, r)
		}
		if r.stderr != "" {
			oneLowercaseErrorLine(t, tc.args, r.stderr)
		}
	}
	if r := run(t, repo, nil, "land", "--help"); r.code != ExitOK || !strings.Contains(r.stdout, "enqueue <branch>") || !strings.Contains(r.stdout, "status [branch]") {
		t.Fatalf("land --help: %+v", r)
	}

	// A forge that does not answer: the request was valid, the answer is not
	// final. Exit 3, and the token never appears.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	token := "test-" + genTerm(t)
	cfg := writeConfig(t, storeYAML+"forge:\n  kind: github\n  repo: acme/widget\n  api: "+dead.URL+"\nland:\n  target: main\n")
	for _, args := range [][]string{{"land", "enqueue", "feature"}, {"land", "status"}, {"land", "status", "feature", "--json"}} {
		r := run(t, repo, map[string]string{"CHIMERA_FORGE_TOKEN": token}, append(args, "--config", cfg)...)
		if r.code != ExitPending || !strings.Contains(r.stderr, "no answer from the forge; outcome unknown; run the command again") {
			t.Errorf("%v against a dead forge: %+v", args, r)
		}
		if strings.Contains(r.stdout+r.stderr, token) || strings.Contains(r.stdout+r.stderr, dead.URL) {
			t.Errorf("%v leaks the token or the endpoint: %+v", args, r)
		}
	}
	// A forge that answers "bad credentials" is an error, not pending.
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer gh.Close()
	cfg = writeConfig(t, storeYAML+"forge:\n  kind: github\n  repo: acme/widget\n  api: "+gh.URL+"\nland:\n  target: main\n")
	r := run(t, repo, map[string]string{"CHIMERA_FORGE_TOKEN": token}, "land", "enqueue", "feature", "--config", cfg)
	if r.code != ExitError || !strings.Contains(r.stderr, "status 401: Bad credentials") || strings.Contains(r.stderr, token) {
		t.Fatalf("bad credentials: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(state, "store")); err == nil {
		t.Fatal("a refused command wrote to the store")
	}
}

// sshKey generates an ed25519 signing key. A machine without ssh-keygen
// fails this test: owner approval cannot be shown to work there.
func sshKey(t *testing.T, dir, name string) (priv, pub string) {
	t.Helper()
	priv = filepath.Join(dir, name)
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", priv)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	return priv, strings.TrimSpace(string(raw))
}

// TestM2_2_Ring0ApprovalBindsToTheVerifiedSignerNotTheCommitterHeader: a
// Ring-0 change lands only when its commit carries a good signature made by
// an owner. A signature by someone else the lander's Git trusts is not
// approval, whatever the committer header claims; nor is no signature.
func TestM2_2_Ring0ApprovalBindsToTheVerifiedSignerNotTheCommitterHeader(t *testing.T) {
	seed := fixtureRepo(t, map[string]string{"README.md": "# widget\n", "verify/check.sh": landVerifier})
	keys := t.TempDir()
	ownerKey, ownerPub := sshKey(t, keys, "owner")
	devKey, devPub := sshKey(t, keys, "dev")
	// The lander verifies signatures of everyone who contributes; only one of them is an owner.
	allowed := filepath.Join(keys, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("owner@example.com "+ownerPub+"\ndev@example.com "+devPub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := func(branch, key, committer, line string) string {
		git(t, seed, "checkout", "-q", "-b", branch, "main")
		writeFiles(t, seed, map[string]string{"verify/check.sh": landVerifier + "# " + line + "\n"})
		git(t, seed, "add", "-A")
		args := []string{"-c", "user.name=Example", "-c", "user.email=" + committer, "-c", "gpg.format=ssh"}
		if key != "" {
			args = append(args, "-c", "user.signingkey="+key, "commit", "-q", "-S", "-m", "verify: "+line)
		} else {
			args = append(args, "commit", "-q", "-m", "verify: "+line)
		}
		git(t, seed, args...)
		return gitOut(t, seed, "rev-parse", "HEAD")
	}
	unsignedHead := signed("unsigned", "", "owner@example.com", "unsigned, committer header says owner")
	spoofHead := signed("spoofed", devKey, "owner@example.com", "signed by dev, committer header says owner")
	ownerHead := signed("approved", ownerKey, "dev@example.com", "signed by the owner")
	git(t, seed, "checkout", "-q", "main")

	root := t.TempDir()
	bare, lander, state := filepath.Join(root, "forge.git"), filepath.Join(root, "lander"), filepath.Join(root, "state")
	git(t, root, "clone", "-q", "--bare", seed, bare)
	git(t, root, "clone", "-q", bare, lander)
	git(t, lander, "config", "gpg.format", "ssh")
	git(t, lander, "config", "gpg.ssh.allowedSignersFile", allowed)
	// Git itself vouches for both signatures; only the signer differs.
	if got := gitOut(t, lander, "log", "-1", "--format=%G? %GS %ce", spoofHead); got != "G dev@example.com owner@example.com" {
		t.Fatalf("git on the spoofed commit: %q", got)
	}
	if got := gitOut(t, lander, "log", "-1", "--format=%G? %GS %ce", ownerHead); got != "G owner@example.com dev@example.com" {
		t.Fatalf("git on the owner's commit: %q", got)
	}
	if got := gitOut(t, lander, "log", "-1", "--format=%G?", unsignedHead); got != "N" {
		t.Fatalf("git on the unsigned commit: %q", got)
	}
	cfg := writeConfig(t, `tenant:
  owner_emails: [Owner@Example.com]
  repos: [acme/widget]
store:
  endpoint: file://`+filepath.Join(state, "store")+`
ledger:
  path: `+filepath.Join(state, "ledger.db")+`
ring0:
  paths: ["verify/**"]
forge:
  kind: git
  dir: `+bare+`
land:
  target: main
  remote: origin
verifiers:
  default: { command: ["sh", "verify/check.sh"], timeout: 30s }
`)
	for _, b := range []string{"unsigned", "spoofed", "approved"} {
		if r := run(t, lander, nil, "land", "enqueue", b, "--config", cfg, "-q"); r.code != ExitOK {
			t.Fatalf("enqueue %s: %+v", b, r)
		}
	}
	r := run(t, lander, nil, "land", "run", "--config", cfg, "--json")
	var env struct {
		Code     int           `json:"code"`
		Findings []land.Result `json:"findings"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil || r.code != ExitError || env.Code != 1 || len(env.Findings) != 3 {
		t.Fatalf("run: %+v %v", r, err)
	}
	want := "touches Ring-0 (verify/check.sh); needs explicit owner approval"
	for i, f := range env.Findings[:2] {
		if f.State != land.Evicted || f.Reason != want || f.Capsule != "" {
			t.Fatalf("finding %d: %+v", i, f)
		}
	}
	if f := env.Findings[2]; f.State != land.Landed || f.Change.Branch != "approved" || string(f.Landed) != ownerHead || f.Capsule == "" {
		t.Fatalf("the owner-signed change: %+v", f)
	}
	if got := gitOut(t, bare, "rev-parse", "main"); got != ownerHead {
		t.Fatalf("main at %s, want the owner-signed commit %s", got, ownerHead)
	}
	if got := gitOut(t, bare, "show", "main:verify/check.sh"); !strings.HasSuffix(got, "# signed by the owner") {
		t.Fatalf("verify/check.sh on main:\n%s", got)
	}

	// The same holds with no owners configured: nobody can approve.
	if ownerSigned(lander, nil, func(string) bool { return true })(context.Background(), forge.Change{}, land.Rebased{Sources: []gitx.Commit{{SHA: ownerHead}}}, nil) {
		t.Fatal("approved with no owners configured")
	}
	if signerAddress("Example Owner <Owner@Example.com>") != "owner@example.com" || signerAddress(" owner@example.com ") != "owner@example.com" || signerAddress("") != "" {
		t.Fatal("signerAddress")
	}
}

// TestM2_2_FailedNotificationsAreVisibleAndNeverClaimedDelivered: off a TTY,
// under -q, a notification or check that could not be delivered is still one
// stderr line each, it is in the JSON, and the summary does not say the
// owners were told.
func TestM2_2_FailedNotificationsAreVisibleAndNeverClaimedDelivered(t *testing.T) {
	bare, lander, cfg, _ := landFixture(t)
	for _, b := range []string{"agent-a", "agent-b"} {
		if r := run(t, lander, nil, "land", "enqueue", b, "--config", cfg, "-q"); r.code != ExitOK {
			t.Fatalf("enqueue %s: %+v", b, r)
		}
	}
	// The forge's log cannot be written: <git-dir>/chimera is a file.
	if err := os.WriteFile(filepath.Join(bare, "chimera"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run(t, lander, nil, "land", "run", "--config", cfg, "-q", "--json")
	if r.code != ExitError {
		t.Fatalf("run: %+v", r)
	}
	noEscapes(t, r)
	lines := strings.Split(strings.TrimSpace(r.stderr), "\n")
	if len(lines) != 4 || lines[0] != "chimera: land run: warning: agent-a: report "+gitOut(t, bare, "rev-parse", "agent-a")[:12]+": forge log: cannot create directory" ||
		!strings.HasPrefix(lines[1], "chimera: land run: warning: agent-b: notify agent-b: forge log: ") || !strings.HasPrefix(lines[2], "chimera: land run: warning: agent-b: report ") {
		t.Fatalf("stderr:\n%s", r.stderr)
	}
	if strings.Contains(r.stderr, "each owner was told") || !strings.HasSuffix(lines[3], "; 1 landed on main; 1 of 1 owners could not be told the reason; see the warnings") {
		t.Fatalf("summary: %s", lines[3])
	}
	var env struct {
		Findings []land.Result `json:"findings"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil || len(env.Findings) != 2 || len(env.Findings[0].Warnings) != 1 || len(env.Findings[1].Warnings) != 2 ||
		!strings.HasPrefix(env.Findings[1].Warnings[0], "notify agent-b: ") {
		t.Fatalf("json: %s %v", r.stdout, err)
	}
	// What happened to the changes is unaffected and recorded.
	if got := gitOut(t, bare, "log", "-1", "--format=%s", "main"); got != "flags: add a" {
		t.Fatalf("main: %s", got)
	}
	if r := run(t, lander, nil, "land", "status", "agent-b", "--config", cfg); r.code != ExitError || !strings.Contains(r.stdout, "EVICTED  agent-b") {
		t.Fatalf("status: %+v", r)
	}
}

// TestM2_2_TwoClonesOfOneRepositoryShareOneEpochSequence: the landing state
// is named after the repository, never after a clone's directory, so two
// landers in differently named clones fence each other.
func TestM2_2_TwoClonesOfOneRepositoryShareOneEpochSequence(t *testing.T) {
	seed := fixtureRepo(t, map[string]string{"README.md": "# widget\n", "verify/check.sh": landVerifier})
	root := t.TempDir()
	bare, state := filepath.Join(root, "forge.git"), filepath.Join(root, "state")
	git(t, root, "clone", "-q", "--bare", seed, bare)
	body := "store:\n  endpoint: file://" + filepath.Join(state, "store") + "\nledger:\n  path: " + filepath.Join(state, "ledger.db") +
		"\nforge:\n  kind: git\n  dir: " + bare + "\nland:\n  target: main\n  remote: origin\nverifiers:\n  default: { command: [\"sh\", \"verify/check.sh\"], timeout: 30s }\n"
	unnamed := writeConfig(t, body)
	named := writeConfig(t, strings.Replace(body, "forge:\n  kind: git\n", "forge:\n  kind: git\n  repo: acme/widget\n", 1))
	for i, name := range []string{"lander-one", "lander-two"} {
		dir := filepath.Join(root, name)
		git(t, root, "clone", "-q", bare, dir)
		// Without a name there is no guessing one from the directory.
		if r := run(t, dir, nil, "land", "run", "--config", unnamed); r.code != ExitUsage || !strings.Contains(r.stderr, "repository name not configured") {
			t.Fatalf("%s unnamed: %+v", name, r)
		}
		r := run(t, dir, nil, "land", "run", "--config", named, "--json")
		var res landRunResult
		if err := json.Unmarshal([]byte(r.stdout), &res); err != nil || r.code != ExitOK || res.Repo != "acme/widget" || res.Epoch != i+1 {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
	}
	keys, _ := objstore.NewDir(filepath.Join(state, "store")).List(context.Background(), "land/")
	if strings.Join(keys, ",") != "land/acme/widget/epoch-1,land/acme/widget/epoch-2" {
		t.Fatalf("land keys: %v", keys)
	}
	// --repo wins over forge.repo; a linked work tree of the forge that has the
	// target checked out is found, not just the current directory.
	plain := filepath.Join(root, "plain")
	git(t, root, "clone", "-q", seed, plain)
	wt := filepath.Join(root, "linked")
	git(t, plain, "checkout", "-q", "--detach")
	git(t, plain, "worktree", "add", "-q", wt, "main")
	local := writeConfig(t, strings.Replace(strings.Replace(body, "  dir: "+bare+"\n", "  dir: "+plain+"\n", 1), "  remote: origin\n", "", 1))
	r := run(t, plain, nil, "land", "run", "--config", local, "--repo", "acme/other")
	if r.code != ExitUsage || !strings.Contains(r.stderr, "--target: main is checked out in "+wt+"; ") {
		t.Fatalf("linked work tree: %+v", r)
	}
}
