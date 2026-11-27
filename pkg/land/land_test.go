package land

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// The lander must work with no Git identity configured anywhere.
func TestMain(m *testing.M) {
	os.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	os.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL", "EMAIL"} {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}

type repo struct {
	t   *testing.T
	dir string
}

func (r *repo) run(env []string, stdin string, args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=Example", "-c", "user.email=dev@example.com"}, args...)...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

func (r *repo) git(args ...string) string { r.t.Helper(); return r.run(nil, "", args...) }

// commit writes a commit on top of parent with plumbing only: no checkout,
// no shared index, so many "agents" can author at once.
func (r *repo) commit(parent forge.SHA, files map[string]string, msg string) forge.SHA {
	r.t.Helper()
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(r.t.TempDir(), "index")}
	if !parent.IsZero() {
		r.run(env, "", "read-tree", string(parent))
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		blob := r.run(nil, files[p], "hash-object", "-w", "--stdin")
		r.run(env, "", "update-index", "--add", "--cacheinfo", "100644,"+blob+","+p)
	}
	tree := r.run(env, "", "write-tree")
	args := []string{"commit-tree", tree, "-F", "-"}
	if !parent.IsZero() {
		args = append(args, "-p", string(parent))
	}
	return forge.SHA(r.run(nil, msg, args...))
}

func (r *repo) subjects(from, to forge.SHA) []string {
	r.t.Helper()
	out := r.git("log", "--reverse", "--format=%s", string(from)+".."+string(to))
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func (r *repo) parents(sha forge.SHA) []string {
	r.t.Helper()
	return strings.Fields(r.git("log", "-1", "--format=%P", string(sha)))
}

func (r *repo) files(sha forge.SHA) string {
	r.t.Helper()
	return strings.ReplaceAll(r.git("ls-tree", "-r", "--name-only", string(sha)), "\n", " ")
}

func (r *repo) trailers(sha forge.SHA) string {
	r.t.Helper()
	ts, err := gitx.CommitTrailers(context.Background(), r.dir, string(sha))
	if err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, tr := range ts {
		out = append(out, tr.Key+": "+tr.Value)
	}
	return strings.Join(out, "\n")
}

const verifyScript = `#!/bin/sh
if [ -f a.flag ] && [ -f b.flag ]; then p=false; else p=true; fi
printf '[{"id":"[M2-2]","criterion":"a.flag and b.flag never ship together","pass":%s,"evidence":"checked the tree in the lane"}]\n' "$p" > "$CHIMERA_OUT/verdicts.json"
`

// fixture is a repository with a base commit on main, a fake forge whose
// main points at it, and a directory store.
type fixture struct {
	*repo
	base  forge.SHA
	forge *forge.Fake
	store objstore.Store
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	r := &repo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	base := r.commit(forge.Zero, map[string]string{"README.md": "# widget\n", "greet.sh": "#!/bin/sh\necho hello\n", "verify/check.sh": verifyScript}, "base\n")
	r.git("update-ref", "refs/heads/main", string(base))
	f := forge.NewFake()
	f.SetRef("main", base)
	return &fixture{repo: r, base: base, forge: f, store: objstore.NewDir(filepath.Join(t.TempDir(), "store"))}
}

func intentOf(n int) string  { return fmt.Sprintf("folio:%064x", n) }
func capsuleOf(n int) string { return fmt.Sprintf("sha256:%064x", n) }

func trailered(subject string, n int) string {
	return fmt.Sprintf("%s\n\nBody of %s.\n\nChimera-Intent: %s\nChimera-Capsule: %s\n", subject, subject, intentOf(1), capsuleOf(n))
}

// author commits on a branch from parent, publishes the branch on the fake
// forge, and enqueues it.
func (fx *fixture) author(branch string, parent forge.SHA, files map[string]string, msg string) forge.Change {
	fx.t.Helper()
	head := fx.commit(parent, files, msg)
	fx.forge.SetRef(branch, head)
	c, _, created, err := Enqueue(context.Background(), fx.forge, "main", branch)
	if err != nil || !created {
		fx.t.Fatalf("enqueue %s: %v (created %v)", branch, err, created)
	}
	return c
}

type verifyLog struct {
	mu       sync.Mutex
	seen     []Rebased
	inFlight int32
	overlap  bool
}

func (v *verifyLog) record(rb Rebased) {
	if atomic.AddInt32(&v.inFlight, 1) != 1 {
		v.overlap = true
	}
	time.Sleep(2 * time.Millisecond)
	v.mu.Lock()
	v.seen = append(v.seen, rb)
	v.mu.Unlock()
	atomic.AddInt32(&v.inFlight, -1)
}

func (v *verifyLog) shas() map[forge.SHA]bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[forge.SHA]bool{}
	for _, rb := range v.seen {
		out[rb.SHA] = true
	}
	return out
}

func (fx *fixture) train(v *verifyLog) *Train {
	return &Train{Forge: fx.forge, Store: fx.store, Repo: "acme/widget", Target: "main", Git: &GitWorkspace{Dir: fx.dir}, Holder: "lander-1",
		Verify: func(ctx context.Context, c forge.Change, rb Rebased) (Verification, error) {
			if v != nil {
				v.record(rb)
			}
			return Verification{Pass: true, Capsule: capsuleOf(900 + c.Seq)}, nil
		}}
}

func targetPushes(f *forge.Fake) (ok []forge.PushRecord, stale int) {
	for _, p := range f.Pushes() {
		if p.Ref != "refs/heads/main" {
			continue
		}
		if p.Err == nil {
			ok = append(ok, p)
		} else if errors.Is(p.Err, forge.ErrStale) {
			stale++
		}
	}
	return ok, stale
}

func TestM2_2_ConcurrentBranchesLandSeriallyWithPostRebaseVerification(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	const n = 8
	heads := make([]forge.SHA, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) { // n agents author and enqueue at the same time, all from the same base
			defer wg.Done()
			branch := fmt.Sprintf("agent-%d", i)
			heads[i] = fx.commit(fx.base, map[string]string{fmt.Sprintf("work/f%d.txt", i): fmt.Sprintf("agent %d\n", i)}, trailered(fmt.Sprintf("work: change %d", i), i))
			fx.forge.SetRef(branch, heads[i])
			if _, _, created, err := Enqueue(ctx, fx.forge, "main", branch); err != nil || !created {
				t.Errorf("enqueue %s: %v", branch, err)
			}
		}(i)
	}
	wg.Wait()
	queue, err := fx.forge.Queue(ctx, "main")
	if err != nil || len(queue) != n {
		t.Fatalf("queue: %d %v", len(queue), err)
	}

	var log verifyLog
	tr := fx.train(&log)
	// The verifier sees the tree that will land: this change on top of every
	// change that landed before it.
	inner := tr.Verify
	landedSoFar := 0
	tr.Verify = func(ctx context.Context, c forge.Change, rb Rebased) (Verification, error) {
		if got := strings.Count(fx.files(rb.SHA), "work/f"); got != landedSoFar+1 {
			t.Errorf("verifying %s: tree holds %d changes, want %d", c.Branch, got, landedSoFar+1)
		}
		landedSoFar++
		return inner(ctx, c, rb)
	}
	sum, err := tr.Run(ctx, false)
	if err != nil || len(sum.Results) != n || sum.Count(Landed) != n || sum.Epoch != 1 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if log.overlap {
		t.Fatal("two verifications overlapped: the critical section is not serialized")
	}
	head, _ := fx.forge.Head(ctx, "main")
	// Linear history holding every change exactly once, in queue order.
	var want []string
	for _, c := range queue {
		want = append(want, "work: change "+strings.TrimPrefix(c.Branch, "agent-"))
	}
	if got := fx.subjects(fx.base, head); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("history %q, want %q", got, want)
	}
	for sha := head; sha != fx.base; {
		p := fx.parents(sha)
		if len(p) != 1 {
			t.Fatalf("%s has %d parents", sha.Short(), len(p))
		}
		sha = forge.SHA(p[0])
	}
	// Every pushed commit is exactly a commit that was verified, each push is
	// a compare-and-swap from the previous one, and what landed is the
	// rebased commit, not the authored one.
	pushes, stale := targetPushes(fx.forge)
	verified := log.shas()
	if len(pushes) != n || stale != 0 {
		t.Fatalf("%d pushes, %d stale", len(pushes), stale)
	}
	prev := fx.base
	rebasedCount := 0
	for i, p := range pushes {
		if !verified[p.New] {
			t.Fatalf("push %d landed %s, which was never verified", i, p.New.Short())
		}
		if p.Old != prev {
			t.Fatalf("push %d swapped from %s, want %s", i, p.Old.Short(), prev.Short())
		}
		prev = p.New
		res := sum.Results[i]
		if res.Landed != p.New || res.Change != queue[i] || res.Attempts != 1 {
			t.Fatalf("result %d: %+v", i, res)
		}
		if p.New != queue[i].Head {
			rebasedCount++
		}
		// Rebase keeps each commit's own trailers.
		idx := 0
		fmt.Sscanf(queue[i].Branch, "agent-%d", &idx)
		if got := fx.trailers(p.New); got != "Chimera-Intent: "+intentOf(1)+"\nChimera-Capsule: "+capsuleOf(idx) {
			t.Fatalf("landed commit %d trailers:\n%s", i, got)
		}
	}
	if rebasedCount != n-1 || pushes[0].New != queue[0].Head {
		t.Fatalf("%d of %d landed commits differ from their authored heads", rebasedCount, n)
	}
	// The lander has no Git identity here, so it commits as the neutral fallback.
	if got := fx.git("log", "-1", "--format=%ce|%ae", string(head)); got != "land@chimera.invalid|dev@example.com" {
		t.Fatalf("committer|author of the landed tip: %s", got)
	}
	// The queue is empty, every landing is reported and recorded, and no
	// owning branch moved.
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 0 {
		t.Fatalf("queue not drained: %+v", q)
	}
	reports := fx.forge.Reports()
	if len(reports) != n || reports[0].Check.Name != CheckName || reports[0].Check.State != forge.Pass || reports[0].SHA != pushes[0].New ||
		!strings.Contains(reports[0].Check.Summary, capsuleOf(900+queue[0].Seq)) {
		t.Fatalf("reports: %+v", reports)
	}
	if len(fx.forge.Notifications()) != 0 {
		t.Fatal("a landed change was notified as evicted")
	}
	for i, h := range heads {
		if got, _ := fx.forge.Head(ctx, fmt.Sprintf("agent-%d", i)); got != h {
			t.Fatalf("branch agent-%d moved", i)
		}
	}
	st, err := Status(ctx, fx.forge, fx.store, "acme/widget", "main")
	if err != nil || st.Schema != StatusSchema || st.Head != head || st.Epoch != 1 || st.Holder != "lander-1" || st.AcquiredAt == "" || len(st.Queue) != 0 || len(st.Outcomes) != n {
		t.Fatalf("status: %+v %v", st, err)
	}
	for _, o := range st.Outcomes {
		if o.State != Landed || o.Epoch != 1 || o.Landed.IsZero() || o.At == "" {
			t.Fatalf("outcome: %+v", o)
		}
	}
	// The user's checkout was never touched and no worktree is left behind.
	if got := fx.git("worktree", "list", "--porcelain"); strings.Count(got, "worktree ") != 1 {
		t.Fatalf("worktrees left behind:\n%s", got)
	}
}

func laneDeps(store objstore.Store) lane.Deps {
	return lane.Deps{
		Runner: func(string) (lane.Runner, error) { return lane.Local{}, nil },
		Push: func(ctx context.Context, dir string) error {
			_, err := capsule.Push(ctx, store, dir, secretscan.New(nil))
			return err
		},
	}
}

// TestM2_2_TheLaneVerifiesTheRebasedTreeNotTheAuthoredOne: two changes each
// pass the verifier on the tree they were authored on, and fail it only in
// combination. The first lands; the second is evicted, because what the
// Lane judges is the second rebased onto the first.
func TestM2_2_TheLaneVerifiesTheRebasedTreeNotTheAuthoredOne(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	a := fx.author("agent-a", fx.base, map[string]string{"a.flag": "a\n"}, trailered("flags: add a", 1))
	b := fx.author("agent-b", fx.base, map[string]string{"b.flag": "b\n"}, "flags: add b\n")
	tr := fx.train(nil)
	lv := LaneVerifier{RepoDir: fx.dir, Repo: "acme/widget", Target: "main", Deps: laneDeps(fx.store), Epoch: tr.Epoch,
		Verifier: lane.Command{Argv: []string{"sh", "verify/check.sh"}, Timeout: 20 * time.Second}}
	// Alone, on the tree it was authored on, each change passes.
	for _, c := range []forge.Change{a, b} {
		v, err := lv.Verify(ctx, c, Rebased{SHA: c.Head, Base: fx.base})
		if err != nil || !v.Pass || v.Capsule == "" {
			t.Fatalf("%s alone: %+v %v", c.Branch, v, err)
		}
	}
	tr.Verify = lv.Verify
	sum, err := tr.Run(ctx, false)
	if err != nil || len(sum.Results) != 2 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	ra, rb := sum.Results[0], sum.Results[1]
	if ra.State != Landed || ra.Landed != a.Head || rb.State != Evicted {
		t.Fatalf("results: %+v", sum.Results)
	}
	if !strings.Contains(rb.Reason, "verifier failed ([M2-2] a.flag and b.flag never ship together)") || !strings.Contains(rb.Reason, rb.Capsule) ||
		!strings.Contains(rb.Reason, "rebased onto main "+a.Head.Short()) {
		t.Fatalf("eviction reason: %s", rb.Reason)
	}
	if head, _ := fx.forge.Head(ctx, "main"); head != a.Head {
		t.Fatalf("main at %s, want only a", head.Short())
	}
	// The verdicts are real Capsules, recorded against the rebased commits.
	for i, res := range sum.Results {
		addr, err := capsule.ParseAddress(res.Capsule)
		if err != nil {
			t.Fatalf("result %d capsule %q: %v", i, res.Capsule, err)
		}
		local, err := capsule.Get(ctx, fx.store, addr)
		if err != nil {
			t.Fatal(err)
		}
		m := local.Manifest
		if m.Tag("land") != "main" || m.Tag("epoch") != "1" || m.Tag("change") != res.Change.ID || m.Repo != "acme/widget" || m.Lane.Runner != "local" {
			t.Fatalf("capsule %d manifest: %+v", i, m)
		}
		vs, _ := local.Verdicts()
		if len(vs) != 1 || vs[0].ID != "[M2-2]" || vs[0].Pass != (i == 0) {
			t.Fatalf("capsule %d verdicts: %+v", i, vs)
		}
		switch i {
		case 0:
			if m.BaseSHA != string(a.Head) || m.Intent != intentOf(1) {
				t.Fatalf("a's capsule: base %s intent %s", m.BaseSHA, m.Intent)
			}
		case 1:
			// Not the authored head: the rebased commit, whose parent is a.
			if m.BaseSHA == string(b.Head) || fx.parents(forge.SHA(m.BaseSHA))[0] != string(a.Head) || fx.files(forge.SHA(m.BaseSHA)) != "README.md a.flag b.flag greet.sh verify/check.sh" {
				t.Fatalf("b's capsule was not recorded against the rebased tree: %s", m.BaseSHA)
			}
			if !strings.HasPrefix(m.Intent, "task:") {
				t.Fatalf("untrailered change with no Folio: intent %s", m.Intent)
			}
		}
		if _, ok := local.Members["proof/verifier.log"]; !ok {
			t.Fatal("capsule lacks the verifier log")
		}
	}
	notes := fx.forge.Notifications()
	if len(notes) != 1 || notes[0].Change != b || !strings.Contains(notes[0].Msg, "verifier failed") {
		t.Fatalf("notifications: %+v", notes)
	}
}

func TestM2_2_ConflictedChangeIsEvictedWhileTheNextLands(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	a := fx.author("agent-a", fx.base, map[string]string{"greet.sh": "#!/bin/sh\necho hello from a\n"}, "greet: a's wording\n")
	b := fx.author("agent-b", fx.base, map[string]string{"greet.sh": "#!/bin/sh\necho hello from b\n", "b.txt": "b\n"}, "greet: b's wording\n")
	c := fx.author("agent-c", fx.base, map[string]string{"c.txt": "c\n"}, "docs: c\n")
	var log verifyLog
	sum, err := fx.train(&log).Run(ctx, false)
	if err != nil || len(sum.Results) != 3 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if sum.Results[0].State != Landed || sum.Results[1].State != Evicted || sum.Results[2].State != Landed {
		t.Fatalf("states: %+v", sum.Results)
	}
	head, _ := fx.forge.Head(ctx, "main")
	if got := fx.subjects(fx.base, head); strings.Join(got, "|") != "greet: a's wording|docs: c" {
		t.Fatalf("history: %q", got)
	}
	if fx.files(head) != "README.md c.txt greet.sh verify/check.sh" {
		t.Fatalf("tree: %s", fx.files(head))
	}
	// The conflicted change was never verified, went back to its owner with
	// the reason at once, and its branch is untouched.
	if len(log.seen) != 2 {
		t.Fatalf("%d verifications", len(log.seen))
	}
	want := "conflict rebasing onto main " + a.Head.Short() + ": greet.sh"
	if sum.Results[1].Reason != want {
		t.Fatalf("reason %q", sum.Results[1].Reason)
	}
	notes := fx.forge.Notifications()
	if len(notes) != 1 || notes[0].Change != b || !strings.Contains(notes[0].Msg, want) || !strings.Contains(notes[0].Msg, "agent-b") {
		t.Fatalf("notifications: %+v", notes)
	}
	var failed []forge.ReportRecord
	for _, r := range fx.forge.Reports() {
		if r.Check.State == forge.Fail {
			failed = append(failed, r)
		}
	}
	if len(failed) != 1 || failed[0].SHA != b.Head || failed[0].Check.Title != "evicted: "+want {
		t.Fatalf("failing reports: %+v", failed)
	}
	if got, _ := fx.forge.Head(ctx, "agent-b"); got != b.Head {
		t.Fatal("the evicted branch moved")
	}
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 0 {
		t.Fatalf("queue stalled: %+v", q)
	}
	// The eviction happened before c was processed: order of forge writes.
	var order []string
	for _, p := range fx.forge.Pushes() {
		switch {
		case p.Ref == b.Ref && p.New.IsZero():
			order = append(order, "evict-b")
		case p.Ref == "refs/heads/main" && p.Err == nil:
			order = append(order, "land")
		}
	}
	if strings.Join(order, ",") != "land,evict-b,land" {
		t.Fatalf("order: %v", order)
	}
	st, _ := Status(ctx, fx.forge, fx.store, "acme/widget", "main")
	states := map[string]string{}
	for _, o := range st.Outcomes {
		states[o.Change.Branch] = o.State
	}
	if len(st.Outcomes) != 3 || states["agent-a"] != Landed || states["agent-b"] != Evicted || states["agent-c"] != Landed || c.Seq != 3 {
		t.Fatalf("outcomes: %+v", st.Outcomes)
	}
	// No rebase state leaked into the repository.
	if out := fx.git("status", "--porcelain", "--untracked-files=no"); strings.Contains(out, "UU") {
		t.Fatalf("conflict leaked into the checkout:\n%s", out)
	}
	if got := fx.git("worktree", "list", "--porcelain"); strings.Count(got, "worktree ") != 1 {
		t.Fatalf("worktrees left behind:\n%s", got)
	}
}

func TestM2_2_StaleCompareAndSwapRetriesFromTheRebase(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))
	interloper := fx.commit(fx.base, map[string]string{"hotfix.txt": "pushed by someone else\n"}, "hotfix: outside the queue\n")
	moved := false
	// Between the lander's Head and its Push, another writer moves main.
	fx.forge.OnPush(func(ref string, old, new forge.SHA) {
		if ref == "refs/heads/main" && !moved {
			moved = true
			fx.forge.SetRef("main", interloper)
		}
	})
	var log verifyLog
	sum, err := fx.train(&log).Run(ctx, false)
	if err != nil || len(sum.Results) != 1 || sum.Results[0].State != Landed || sum.Results[0].Attempts != 2 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	landed := sum.Results[0].Landed
	if p := fx.parents(landed); len(p) != 1 || p[0] != string(interloper) {
		t.Fatalf("landed commit's parent is %v, want the interloper %s", p, interloper)
	}
	// Verified twice: once per rebase. The second verdict is on the tree that landed.
	if len(log.seen) != 2 || log.seen[0].Base != fx.base || log.seen[0].SHA != c.Head || log.seen[1].Base != interloper || log.seen[1].SHA != landed {
		t.Fatalf("verifications: %+v", log.seen)
	}
	if fx.files(landed) != "README.md a.txt greet.sh hotfix.txt verify/check.sh" {
		t.Fatalf("landed tree: %s", fx.files(landed))
	}
	ok, stale := targetPushes(fx.forge)
	if len(ok) != 1 || stale != 1 || ok[0].Old != interloper || ok[0].New != landed {
		t.Fatalf("pushes: %+v stale=%d", ok, stale)
	}
	if got := fx.trailers(landed); got != "Chimera-Intent: "+intentOf(1)+"\nChimera-Capsule: "+capsuleOf(1) {
		t.Fatalf("trailers after two rebases:\n%s", got)
	}

	// A target that never holds still: the change is left queued as PENDING
	// after the bounded retries, nothing is evicted, and nothing is recorded.
	fx2 := newFixture(t)
	c2 := fx2.author("agent-a", fx2.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
	tip, n := fx2.base, 0
	fx2.forge.OnPush(func(ref string, old, new forge.SHA) {
		if ref == "refs/heads/main" {
			n++
			tip = fx2.commit(tip, map[string]string{fmt.Sprintf("churn%d.txt", n): "x\n"}, fmt.Sprintf("churn %d\n", n))
			fx2.forge.SetRef("main", tip)
		}
	})
	tr := fx2.train(nil)
	tr.MaxStale = 3
	sum, err = tr.Run(ctx, false)
	if err != nil || len(sum.Results) != 1 || sum.Results[0].State != Pending || sum.Results[0].Attempts != 3 || !strings.Contains(sum.Results[0].Reason, "still queued") {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if q, _ := fx2.forge.Queue(ctx, "main"); len(q) != 1 || q[0] != c2 {
		t.Fatalf("pending change left the queue: %+v", q)
	}
	if st, _ := Status(ctx, fx2.forge, fx2.store, "acme/widget", "main"); len(st.Outcomes) != 0 || len(fx2.forge.Notifications()) != 0 {
		t.Fatalf("a pending change was recorded or notified: %+v", st.Outcomes)
	}
}

func s3Store(t *testing.T) objstore.Store {
	t.Helper()
	fake := objstore.NewFake("test-access", "test-secret-value")
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	store, err := objstore.Open(srv.URL, "capsules", "auto", objstore.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-secret-value"})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// recForge records which lander pushed the target, and in which epoch.
type recForge struct {
	forge.Forge
	lander string
	epoch  func() int
	mu     *sync.Mutex
	log    *[]landerPush
}

type landerPush struct {
	lander string
	epoch  int
	new    forge.SHA
}

func (r recForge) Push(ctx context.Context, ref string, old, new forge.SHA) error {
	err := r.Forge.Push(ctx, ref, old, new)
	if err == nil && forge.RefName(ref) == "refs/heads/main" {
		r.mu.Lock()
		*r.log = append(*r.log, landerPush{r.lander, r.epoch(), new})
		r.mu.Unlock()
	}
	return err
}

func TestM2_2_TwoLandersNeverBothPushWithinOneEpoch(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	fx.store = s3Store(t) // real If-None-Match semantics over HTTP
	for i := 0; i < 3; i++ {
		fx.author(fmt.Sprintf("agent-%d", i), fx.base, map[string]string{fmt.Sprintf("f%d.txt", i): "x\n"}, fmt.Sprintf("work: change %d\n", i))
	}
	var mu sync.Mutex
	var pushes []landerPush
	lander := func(name string) *Train {
		tr := fx.train(nil)
		tr.Holder = name
		tr.Forge = recForge{Forge: fx.forge, lander: name, epoch: tr.Epoch, mu: &mu, log: &pushes}
		return tr
	}
	l1, l2 := lander("lander-1"), lander("lander-2")

	// L1 acquires epoch 1 and lands one change.
	sum, err := l1.Run(ctx, true)
	if err != nil || sum.Epoch != 1 || sum.Count(Landed) != 1 {
		t.Fatalf("l1: %+v %v", sum, err)
	}
	// L2 acquires epoch 2: L1 is fenced from that moment.
	if e, err := l2.Acquire(ctx); err != nil || e != 2 {
		t.Fatalf("l2 acquire: %d %v", e, err)
	}
	before := len(fx.forge.Pushes())
	sum, err = l1.Run(ctx, false)
	if !errors.Is(err, ErrFenced) || len(sum.Results) != 0 {
		t.Fatalf("fenced l1: %+v %v", sum, err)
	}
	if after := len(fx.forge.Pushes()); after != before {
		t.Fatalf("a fenced lander made %d pushes", after-before)
	}
	// The epoch records are write-once: one holder each.
	if n, rec, err := HighestEpoch(ctx, fx.store, "acme/widget"); err != nil || n != 2 || rec.Holder != "lander-2" {
		t.Fatalf("highest epoch: %d %+v %v", n, rec, err)
	}
	raw, _ := fx.store.Get(ctx, "land/acme/widget/epoch-1")
	if !bytes.Contains(raw, []byte(`"holder":"lander-1"`)) {
		t.Fatalf("epoch-1 record: %s", raw)
	}
	if created, _ := fx.store.Put(ctx, "land/acme/widget/epoch-1", []byte(`{"holder":"usurper"}`)); created {
		t.Fatal("an epoch was written twice")
	}
	// L2 lands the rest.
	sum, err = l2.Run(ctx, false)
	if err != nil || sum.Epoch != 2 || sum.Count(Landed) != 2 {
		t.Fatalf("l2: %+v %v", sum, err)
	}
	byEpoch := map[int]map[string]int{}
	for _, p := range pushes {
		if byEpoch[p.epoch] == nil {
			byEpoch[p.epoch] = map[string]int{}
		}
		byEpoch[p.epoch][p.lander]++
	}
	if len(byEpoch) != 2 || byEpoch[1]["lander-1"] != 1 || byEpoch[2]["lander-2"] != 2 || len(byEpoch[1]) != 1 || len(byEpoch[2]) != 1 {
		t.Fatalf("pushes by epoch: %+v", byEpoch)
	}

	// A fenced lander does not evict either: it stops before any forge write.
	fx.author("agent-conflict", fx.base, map[string]string{"f0.txt": "conflicts with change 0\n"}, "work: conflicting\n")
	before = len(fx.forge.Pushes())
	if _, err := l1.Run(ctx, false); !errors.Is(err, ErrFenced) || len(fx.forge.Pushes()) != before || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("fenced l1 on a conflicting change: %v", err)
	}
}

func TestM2_2_ConcurrentLandersAreFencedByEpochAndCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	fx.store = s3Store(t)
	const n = 6
	for i := 0; i < n; i++ {
		fx.author(fmt.Sprintf("agent-%d", i), fx.base, map[string]string{fmt.Sprintf("f%d.txt", i): "x\n"}, fmt.Sprintf("work: change %d\n", i))
	}
	// Sixteen landers ask for an epoch at once: sixteen distinct epochs.
	epochs := make([]int, 16)
	var wg sync.WaitGroup
	for i := range epochs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tr := fx.train(nil)
			tr.Repo = "acme/other"
			e, err := tr.Acquire(ctx)
			if err != nil {
				t.Errorf("acquire: %v", err)
			}
			epochs[i] = e
		}(i)
	}
	wg.Wait()
	sort.Ints(epochs)
	for i, e := range epochs {
		if e != i+1 {
			t.Fatalf("epochs %v are not 1..16, each held once", epochs)
		}
	}

	// Two landers run over one queue at the same time.
	var mu sync.Mutex
	var pushes []landerPush
	errs := make([]error, 2)
	trains := make([]*Train, 2)
	for i := range trains {
		tr := fx.train(nil)
		tr.Holder = fmt.Sprintf("lander-%d", i+1)
		tr.Forge = recForge{Forge: fx.forge, lander: tr.Holder, epoch: tr.Epoch, mu: &mu, log: &pushes}
		trains[i] = tr
	}
	for i, tr := range trains {
		wg.Add(1)
		go func(i int, tr *Train) {
			defer wg.Done()
			_, errs[i] = tr.Run(ctx, false)
		}(i, tr)
	}
	wg.Wait()
	finished := 0
	for i, err := range errs {
		switch {
		case err == nil:
			finished++
		case !errors.Is(err, ErrFenced):
			t.Fatalf("lander %d: %v", i+1, err)
		}
	}
	if finished == 0 || trains[0].Epoch() == trains[1].Epoch() || trains[0].Epoch()+trains[1].Epoch() != 3 {
		t.Fatalf("epochs %d and %d, %d landers finished", trains[0].Epoch(), trains[1].Epoch(), finished)
	}
	// Every push was made by the lander the store's write-once epoch record
	// names as that epoch's holder: no epoch has pushes from two landers.
	for _, p := range pushes {
		raw, err := fx.store.Get(ctx, fmt.Sprintf("land/acme/widget/epoch-%d", p.epoch))
		if err != nil || !bytes.Contains(raw, []byte(`"holder":"`+p.lander+`"`)) {
			t.Fatalf("push of %s by %s in epoch %d, whose record is %s (%v)", p.new.Short(), p.lander, p.epoch, raw, err)
		}
	}
	// Nothing was evicted or notified, and every outcome is a landing.
	if n := fx.forge.Notifications(); len(n) != 0 {
		t.Fatalf("notifications: %+v", n)
	}
	for _, r := range fx.forge.Reports() {
		if r.Check.State != forge.Pass {
			t.Fatalf("report: %+v", r)
		}
	}
	if got := outcomeStates(t, fx); strings.Contains(got, Evicted) || strings.Count(got, Landed) < n {
		t.Fatalf("outcomes: %s", got)
	}
	// Every change landed exactly once, on a linear history, and the queue is empty.
	head, _ := fx.forge.Head(ctx, "main")
	got := fx.subjects(fx.base, head)
	sort.Strings(got)
	var want []string
	for i := 0; i < n; i++ {
		want = append(want, fmt.Sprintf("work: change %d", i))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") || len(pushes) != n {
		t.Fatalf("history %q (%d pushes)", got, len(pushes))
	}
	for sha := head; sha != fx.base; {
		p := fx.parents(sha)
		if len(p) != 1 {
			t.Fatalf("%s has %d parents", sha.Short(), len(p))
		}
		sha = forge.SHA(p[0])
	}
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 0 {
		t.Fatalf("queue not drained: %+v", q)
	}
}

func TestM2_2_SquashWritesTheTrailerUnionAndRebaseKeepsEachCommitsOwn(t *testing.T) {
	ctx := context.Background()
	signed := "Signed-off-by: Dev <dev@example.com>"
	build := func(fx *fixture) forge.Change {
		c1 := fx.commit(fx.base, map[string]string{"one.txt": "1\n"}, "feat: one\n\nFirst body.\n\nChimera-Intent: "+intentOf(1)+"\nChimera-Capsule: "+capsuleOf(1)+"\n"+signed+"\n")
		c2 := fx.commit(c1, map[string]string{"two.txt": "2\n"}, "feat: two\n\nChimera-Intent: "+intentOf(1)+"\nChimera-Capsule: "+capsuleOf(2)+"\n"+signed+"\n")
		c3 := fx.commit(c2, map[string]string{"three.txt": "3\n"}, "docs: three, no trailers\n")
		c4 := fx.commit(c3, map[string]string{"four.txt": "4\n"}, "feat: four\n\nChimera-Intent: "+intentOf(2)+"\nChimera-Capsule: "+capsuleOf(1)+"\n")
		fx.forge.SetRef("feature", c4)
		c, _, _, err := Enqueue(ctx, fx.forge, "main", "feature")
		if err != nil {
			t.Fatal(err)
		}
		// main has moved, so the change is really rebased.
		fx.forge.SetRef("main", fx.commit(fx.base, map[string]string{"other.txt": "o\n"}, "other: on main\n"))
		return c
	}
	union := strings.Join([]string{"Chimera-Intent: " + intentOf(1), "Chimera-Capsule: " + capsuleOf(1), signed, "Chimera-Capsule: " + capsuleOf(2), "Chimera-Intent: " + intentOf(2)}, "\n")

	// Squash: one commit carrying the union, de-duplicated, in original order.
	fx := newFixture(t)
	build(fx)
	tr := fx.train(nil)
	tr.Squash = true
	sum, err := tr.Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("squash run: %+v %v", sum, err)
	}
	landed := sum.Results[0].Landed
	mainBefore := fx.parents(landed)
	if got := fx.subjects(forge.SHA(mainBefore[0]), landed); len(got) != 1 || got[0] != "feat: one" {
		t.Fatalf("squash history: %q", got)
	}
	if got := fx.trailers(landed); got != union {
		t.Fatalf("squash trailers:\n%s\nwant:\n%s", got, union)
	}
	msg := fx.git("log", "-1", "--format=%B", string(landed))
	if !strings.HasPrefix(msg, "feat: one\n\nFirst body.\n\n") || strings.Count(msg, "Chimera-Intent: "+intentOf(1)) != 1 {
		t.Fatalf("squash message:\n%s", msg)
	}
	if fx.files(landed) != "README.md four.txt greet.sh one.txt other.txt three.txt two.txt verify/check.sh" {
		t.Fatalf("squash tree: %s", fx.files(landed))
	}
	if got := fx.git("log", "-1", "--format=%an <%ae>", string(landed)); got != "Example <dev@example.com>" {
		t.Fatalf("squash author: %s", got)
	}

	// Rebase: four commits, each with exactly its own trailers.
	fx = newFixture(t)
	build(fx)
	sum, err = fx.train(nil).Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("rebase run: %+v %v", sum, err)
	}
	commits, err := gitx.RangeCommits(ctx, fx.dir, "refs/heads/main", string(sum.Results[0].Landed))
	if err != nil {
		t.Fatal(err)
	}
	// refs/heads/main in the work repo is still the base; the fake's main moved. Skip the "other" commit.
	var per []string
	for _, c := range commits {
		if c.Subject == "other: on main" {
			continue
		}
		per = append(per, fmt.Sprintf("%s=%d", c.Subject, len(c.Trailers)))
	}
	if strings.Join(per, "|") != "feat: one=3|feat: two=3|docs: three, no trailers=0|feat: four=2" {
		t.Fatalf("rebased commits: %v", per)
	}
	var all [][]gitx.Trailer
	for _, c := range commits {
		all = append(all, c.Trailers)
	}
	var got []string
	for _, tr := range gitx.UnionTrailers(all...) {
		got = append(got, tr.Key+": "+tr.Value)
	}
	if strings.Join(got, "\n") != union {
		t.Fatalf("union over the rebased commits:\n%s", strings.Join(got, "\n"))
	}
}

func TestM2_2_Ring0ChangeLandsOnlyWithOwnerApproval(t *testing.T) {
	ctx := context.Background()
	ring0 := func(p string) bool { return strings.HasPrefix(p, "verify/") }
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n", "a.txt": "a\n"}, "verify: always pass\n")
	ok := fx.author("agent-b", fx.base, map[string]string{"b.txt": "b\n"}, "docs: b\n")
	var log verifyLog
	tr := fx.train(&log)
	tr.Ring0 = ring0
	sum, err := tr.Run(ctx, false)
	if err != nil || len(sum.Results) != 2 || sum.Results[0].State != Evicted || sum.Results[1].State != Landed {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if sum.Results[0].Reason != "touches Ring-0 (verify/check.sh); needs explicit owner approval" {
		t.Fatalf("reason: %s", sum.Results[0].Reason)
	}
	// Fail closed: the unapproved change was never even verified.
	if len(log.seen) != 1 || log.seen[0].SHA != ok.Head {
		t.Fatalf("verifications: %+v", log.seen)
	}
	if n := fx.forge.Notifications(); len(n) != 1 || n[0].Change != c {
		t.Fatalf("notifications: %+v", n)
	}

	// With explicit owner approval for exactly those paths, it lands.
	fx = newFixture(t)
	c = fx.author("agent-a", fx.base, map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0\n"}, "verify: always pass\n")
	tr = fx.train(nil)
	tr.Ring0 = ring0
	var asked []string
	tr.Approved = func(_ context.Context, ch forge.Change, rb Rebased, paths []string) bool {
		asked = append(asked, ch.Branch+":"+strings.Join(paths, ",")+fmt.Sprintf(":%d", len(rb.Sources)))
		return true
	}
	sum, err = tr.Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 || strings.Join(asked, "|") != "agent-a:verify/check.sh:1" {
		t.Fatalf("approved run: %+v %v %v", sum, err, asked)
	}
}

func TestM2_2_EnqueueIsIdempotentAndFIFO(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	if _, _, _, err := Enqueue(ctx, fx.forge, "main", "no-such-branch"); !errors.Is(err, forge.ErrNotFound) {
		t.Fatalf("missing branch: %v", err)
	}
	if _, _, _, err := Enqueue(ctx, fx.forge, "", "x"); err == nil {
		t.Fatal("empty target accepted")
	}
	heads := map[string]forge.SHA{}
	for _, b := range []string{"zeta", "alpha", "mid/dle"} {
		heads[b] = fx.commit(fx.base, map[string]string{b + ".txt": b}, b+"\n")
		fx.forge.SetRef(b, heads[b])
	}
	for i, b := range []string{"zeta", "alpha", "mid/dle"} {
		c, pos, created, err := Enqueue(ctx, fx.forge, "refs/heads/main", b)
		if err != nil || !created || pos != i+1 || c.Seq != i+1 || c.Branch != b || c.Head != heads[b] || c.Target != "main" || c.Ref != forge.QueueRef("main", i+1, b) {
			t.Fatalf("enqueue %s: %+v pos=%d created=%v err=%v", b, c, pos, created, err)
		}
	}
	// The same commit again: nothing changes.
	writes := len(fx.forge.Pushes())
	c, pos, created, err := Enqueue(ctx, fx.forge, "main", "alpha")
	if err != nil || created || pos != 2 || c.Seq != 2 || len(fx.forge.Pushes()) != writes {
		t.Fatalf("re-enqueue: %+v pos=%d created=%v err=%v", c, pos, created, err)
	}
	// A newer commit on the branch: the old pin leaves, the new one goes to the back.
	newer := fx.commit(heads["zeta"], map[string]string{"more.txt": "m"}, "zeta: more\n")
	fx.forge.SetRef("zeta", newer)
	c, pos, created, err = Enqueue(ctx, fx.forge, "main", "zeta")
	if err != nil || !created || pos != 3 || c.Seq != 4 || c.Head != newer {
		t.Fatalf("moved branch: %+v pos=%d created=%v err=%v", c, pos, created, err)
	}
	q, _ := fx.forge.Queue(ctx, "main")
	var order []string
	for _, c := range q {
		order = append(order, c.Branch)
	}
	if strings.Join(order, ",") != "alpha,mid/dle,zeta" {
		t.Fatalf("queue order: %v", order)
	}

	// Many agents enqueue at once: every branch gets exactly one place.
	const n = 12
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		b := fmt.Sprintf("agent-%02d", i)
		fx.forge.SetRef(b, fx.commit(fx.base, map[string]string{b: b}, b+"\n"))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, created, err := Enqueue(ctx, fx.forge, "main", b); err != nil || !created {
				t.Errorf("enqueue %s: %v", b, err)
			}
		}()
	}
	wg.Wait()
	q, _ = fx.forge.Queue(ctx, "main")
	seen := map[string]int{}
	for i, c := range q {
		seen[c.Branch]++
		if i > 0 && (q[i-1].Seq > c.Seq || (q[i-1].Seq == c.Seq && q[i-1].Branch >= c.Branch)) {
			t.Fatalf("queue is not in one total order at %d: %+v", i, q)
		}
	}
	if len(q) != n+3 || len(seen) != n+3 {
		t.Fatalf("queue has %d entries for %d branches", len(q), len(seen))
	}
}

// hookForge lets a test stand between a lander and the forge's Push.
type hookForge struct {
	forge.Forge
	before func(ref string, old, new forge.SHA) error // a non-nil error is returned instead of pushing
	after  func(ref string, old, new forge.SHA, err error)
}

func (h hookForge) Push(ctx context.Context, ref string, old, new forge.SHA) error {
	if h.before != nil {
		if err := h.before(forge.RefName(ref), old, new); err != nil {
			return err
		}
	}
	err := h.Forge.Push(ctx, ref, old, new)
	if h.after != nil {
		h.after(forge.RefName(ref), old, new, err)
	}
	return err
}

type died struct{}

// runUntilDeath runs a lander that is killed the instant its target push
// succeeds: nothing after the compare-and-swap runs, exactly as for a
// process that received SIGKILL there.
func runUntilDeath(t *testing.T, fx *fixture, tr *Train) (pushed forge.SHA) {
	t.Helper()
	tr.Forge = hookForge{Forge: fx.forge, after: func(ref string, old, new forge.SHA, err error) {
		if ref == "refs/heads/main" && err == nil {
			pushed = new
			panic(died{})
		}
	}}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(died); !ok {
				panic(r)
			}
		}
	}()
	tr.Run(context.Background(), false)
	t.Fatal("the lander never pushed")
	return
}

func outcomeStates(t *testing.T, fx *fixture) string {
	t.Helper()
	st, err := Status(context.Background(), fx.forge, fx.store, "acme/widget", "main")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, o := range st.Outcomes {
		out = append(out, o.Change.Branch+"="+o.State)
	}
	return strings.Join(out, ",")
}

func reportStates(fx *fixture) string {
	var out []string
	for _, r := range fx.forge.Reports() {
		out = append(out, string(r.Check.State)+"@"+r.SHA.Short())
	}
	return strings.Join(out, ",")
}

// TestM2_2_LanderThatDiedAfterThePushConvergesOnTheNextRun: the push intent
// stored before the compare-and-swap is what tells the next lander that the
// change landed — as a fast-forward, rebased, or squashed — so it is
// dequeued and recorded as LANDED, never evicted, never pushed again.
func TestM2_2_LanderThatDiedAfterThePushConvergesOnTheNextRun(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name            string
		squash, moveTip bool
		twoCommits      bool
	}{
		{name: "fast-forward"},
		{name: "rebased", moveTip: true},
		{name: "squash of two commits on one line", squash: true, twoCommits: true},
		{name: "squash rebased", squash: true, moveTip: true, twoCommits: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			head := fx.commit(fx.base, map[string]string{"greet.sh": "#!/bin/sh\necho hello v1\n"}, trailered("greet: v1", 1))
			if tc.twoCommits {
				head = fx.commit(head, map[string]string{"greet.sh": "#!/bin/sh\necho hello v2\n"}, trailered("greet: v2", 2))
			}
			fx.forge.SetRef("agent-a", head)
			c, _, _, err := Enqueue(ctx, fx.forge, "main", "agent-a")
			if err != nil {
				t.Fatal(err)
			}
			if tc.moveTip {
				fx.forge.SetRef("main", fx.commit(fx.base, map[string]string{"other.txt": "o\n"}, "other: on main\n"))
			}
			l1 := fx.train(nil)
			l1.Squash = tc.squash
			pushed := runUntilDeath(t, fx, l1)
			if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 1 || outcomeStates(t, fx) != "" {
				t.Fatalf("the dead lander dequeued or recorded: %+v %s", q, outcomeStates(t, fx))
			}
			if tc.name == "fast-forward" && pushed != c.Head {
				t.Fatalf("not a fast-forward: %s", pushed.Short())
			}
			before, _ := targetPushes(fx.forge)

			var log verifyLog
			l2 := fx.train(&log)
			l2.Holder, l2.Squash = "lander-2", tc.squash
			sum, err := l2.Run(ctx, false)
			if err != nil || sum.Epoch != 2 || len(sum.Results) != 1 {
				t.Fatalf("recovery run: %+v %v", sum, err)
			}
			res := sum.Results[0]
			if res.State != Landed || res.Reason != "already in main" || res.Landed != pushed || res.Capsule != capsuleOf(900+c.Seq) || len(res.Warnings) != 0 {
				t.Fatalf("recovery result: %+v", res)
			}
			after, _ := targetPushes(fx.forge)
			if len(after) != len(before) || len(log.seen) != 0 {
				t.Fatalf("recovery pushed the target again (%d pushes) or verified (%d)", len(after)-len(before), len(log.seen))
			}
			if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 0 || len(fx.forge.Notifications()) != 0 {
				t.Fatalf("queue %+v, notifications %+v", q, fx.forge.Notifications())
			}
			// The one check is PASS, on the commit that was verified and pushed.
			if got := reportStates(fx); got != "PASS@"+pushed.Short() {
				t.Fatalf("reports: %s", got)
			}
			if got := outcomeStates(t, fx); got != "agent-a=LANDED" {
				t.Fatalf("outcomes: %s", got)
			}
			if head, _ := fx.forge.Head(ctx, "main"); head != pushed {
				t.Fatal("main moved during recovery")
			}
		})
	}
}

// TestM2_2_NothingToLandIsAnEvictionAndNeverAPassOnAnUnverifiedCommit: with
// no push intent in the target, a change that leaves nothing to apply is
// evicted, and the target's head — which this train never verified — gets
// no check.
func TestM2_2_NothingToLandIsAnEvictionAndNeverAPassOnAnUnverifiedCommit(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	// A net no-op change: add a file, then remove it again.
	c1 := fx.commit(fx.base, map[string]string{"x.txt": "x\n"}, "add x\n")
	tree := fx.git("rev-parse", string(fx.base)+"^{tree}")
	c2 := forge.SHA(fx.run(nil, "remove x\n", "commit-tree", tree, "-p", string(c1), "-F", "-"))
	fx.forge.SetRef("noop", c2)
	if _, _, _, err := Enqueue(ctx, fx.forge, "main", "noop"); err != nil {
		t.Fatal(err)
	}
	// Someone pushes an unverified hotfix straight to main.
	hot := fx.commit(fx.base, map[string]string{"hotfix.txt": "unverified\n"}, "hotfix\n")
	fx.forge.SetRef("main", hot)
	// A branch that is already an ancestor of main, queued without ever having been landed.
	fx.forge.SetRef("behind", fx.base)
	if _, _, _, err := Enqueue(ctx, fx.forge, "main", "behind"); err != nil {
		t.Fatal(err)
	}
	var log verifyLog
	sum, err := fx.train(&log).Run(ctx, false)
	if err != nil || len(sum.Results) != 2 || sum.Count(Evicted) != 2 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	for _, r := range sum.Results {
		if r.Reason != "nothing to land relative to main "+hot.Short() || !r.Landed.IsZero() {
			t.Fatalf("result: %+v", r)
		}
	}
	if len(log.seen) != 0 {
		t.Fatalf("%d verifications", len(log.seen))
	}
	for _, r := range fx.forge.Reports() {
		if r.Check.State == forge.Pass || r.SHA == hot {
			t.Fatalf("a check was reported on a commit nobody verified: %+v", r)
		}
	}
	if len(fx.forge.Notifications()) != 2 {
		t.Fatalf("notifications: %+v", fx.forge.Notifications())
	}
}

// TestM2_2_ADequeueFailureAfterLandingNeverEvictsAndNeverSpins: the change
// is in the target. A failing dequeue stops the run with the landing
// recorded; the next run finishes the same landing.
func TestM2_2_ADequeueFailureAfterLandingNeverEvictsAndNeverSpins(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))
	next := fx.author("agent-b", fx.base, map[string]string{"b.txt": "b\n"}, "docs: b\n")
	failing := true
	hook := func(ref string, old, new forge.SHA) error {
		if ref == c.Ref && failing {
			return fmt.Errorf("DELETE %s: status 403: resource not accessible", ref)
		}
		return nil
	}
	tr := fx.train(nil)
	tr.Forge = hookForge{Forge: fx.forge, before: hook}
	done := make(chan struct{})
	var sum Summary
	var err error
	go func() { sum, err = tr.Run(ctx, false); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the run spins on a change it cannot dequeue")
	}
	if err == nil || !strings.Contains(err.Error(), "dequeue agent-a after landing") || len(sum.Results) != 1 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	res := sum.Results[0]
	if res.State != Landed || res.Landed != c.Head || len(res.Warnings) != 1 || !strings.HasPrefix(res.Warnings[0], "dequeue agent-a:") {
		t.Fatalf("result: %+v", res)
	}
	if ok, _ := targetPushes(fx.forge); len(ok) != 1 || len(fx.forge.Notifications()) != 0 || outcomeStates(t, fx) != "agent-a=LANDED" {
		t.Fatalf("pushes %d, notifications %d, outcomes %s", len(ok), len(fx.forge.Notifications()), outcomeStates(t, fx))
	}
	// The change behind it was not touched, and is still queued behind it.
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 2 || q[0] != c || q[1] != next {
		t.Fatalf("queue: %+v", q)
	}
	// The forge recovers: the same lander finishes the landing and goes on.
	failing = false
	sum, err = tr.Run(ctx, false)
	if err != nil || len(sum.Results) != 2 || sum.Results[0].State != Landed || sum.Results[0].Reason != "already in main" || sum.Results[0].Landed != c.Head ||
		sum.Results[1].State != Landed {
		t.Fatalf("second run: %+v %v", sum, err)
	}
	if ok, _ := targetPushes(fx.forge); len(ok) != 2 || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("%d target pushes, %d notifications", len(ok), len(fx.forge.Notifications()))
	}
	for _, r := range fx.forge.Reports() {
		if r.Check.State != forge.Pass {
			t.Fatalf("a landed change got a failing check: %+v", r)
		}
	}
}

// TestM2_2_APushThatErroredButAppliedIsFoundByItsIntent: the forge moved the
// ref and then failed to say so.
func TestM2_2_APushThatErroredButAppliedIsFoundByItsIntent(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
	fx.forge.SetRef("main", fx.commit(fx.base, map[string]string{"other.txt": "o\n"}, "other: on main\n"))
	lost := false
	var applied forge.SHA
	tr := fx.train(nil)
	tr.Forge = hookForge{Forge: fx.forge, before: func(ref string, old, new forge.SHA) error {
		if ref == "refs/heads/main" && !lost {
			lost = true
			if err := fx.forge.Push(ctx, ref, old, new); err != nil {
				return err
			}
			applied = new
			return fmt.Errorf("PATCH %s: no answer from the forge: %w", ref, forge.ErrUnavailable)
		}
		return nil
	}}
	sum, err := tr.Run(ctx, false)
	if !errors.Is(err, forge.ErrUnavailable) || len(sum.Results) != 0 {
		t.Fatalf("first run: %+v %v", sum, err)
	}
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 1 || q[0] != c {
		t.Fatalf("queue: %+v", q)
	}
	var log verifyLog
	sum, err = fx.train(&log).Run(ctx, false)
	if err != nil || len(sum.Results) != 1 || sum.Results[0].State != Landed || sum.Results[0].Landed != applied || len(log.seen) != 0 {
		t.Fatalf("second run: %+v %v", sum, err)
	}
	if ok, _ := targetPushes(fx.forge); len(ok) != 1 || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("%d target pushes, %d notifications", len(ok), len(fx.forge.Notifications()))
	}
}

// TestM2_2_ASecondLanderBetweenPushAndDequeueSeesALanding: lander 2 takes
// over in the instant between lander 1's push and its dequeue. Neither may
// evict the change that is now main's head.
func TestM2_2_ASecondLanderBetweenPushAndDequeueSeesALanding(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))
	l1, l2 := fx.train(nil), fx.train(nil)
	l2.Holder = "lander-2"
	var sum2 Summary
	var err2 error
	ran := false
	l1.Forge = hookForge{Forge: fx.forge, after: func(ref string, old, new forge.SHA, err error) {
		if ref == "refs/heads/main" && err == nil && !ran {
			ran = true
			sum2, err2 = l2.Run(ctx, false)
		}
	}}
	sum1, err1 := l1.Run(ctx, false)
	if !ran || err2 != nil || len(sum2.Results) != 1 || sum2.Results[0].State != Landed || sum2.Results[0].Landed != c.Head {
		t.Fatalf("lander 2: %+v %v", sum2, err2)
	}
	// Lander 1 finishes its own landing (the queue ref is already gone), then
	// finds itself fenced or the queue empty.
	if (err1 != nil && !errors.Is(err1, ErrFenced)) || len(sum1.Results) != 1 || sum1.Results[0].State != Landed {
		t.Fatalf("lander 1: %+v %v", sum1, err1)
	}
	if len(fx.forge.Notifications()) != 0 {
		t.Fatalf("a landed change was notified as evicted: %+v", fx.forge.Notifications())
	}
	for _, r := range fx.forge.Reports() {
		if r.Check.State != forge.Pass || r.SHA != c.Head {
			t.Fatalf("report: %+v", r)
		}
	}
	if got := outcomeStates(t, fx); strings.Contains(got, Evicted) || !strings.Contains(got, "agent-a=LANDED") {
		t.Fatalf("outcomes: %s", got)
	}
	if ok, _ := targetPushes(fx.forge); len(ok) != 1 {
		t.Fatalf("%d target pushes", len(ok))
	}
}

// TestM2_2_AChangeThatCannotBeRebasedOrVerifiedIsEvictedNotStuck: the queue
// never stalls on one change's own defect.
func TestM2_2_AChangeThatCannotBeRebasedOrVerifiedIsEvictedNotStuck(t *testing.T) {
	ctx := context.Background()
	// A file name no file system here can check out.
	fx := newFixture(t)
	long := strings.Repeat("n", 300) + ".txt"
	bad := fx.author("agent-bad", fx.base, map[string]string{long: "x\n"}, "bad: long name\n")
	fx.author("agent-good", fx.base, map[string]string{"g.txt": "g\n"}, "good\n")
	fx.forge.SetRef("main", fx.commit(fx.base, map[string]string{"o.txt": "o\n"}, "other\n"))
	sum, err := fx.train(nil).Run(ctx, false)
	if err != nil || len(sum.Results) != 2 || sum.Results[0].State != Evicted || sum.Results[1].State != Landed {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if !strings.HasPrefix(sum.Results[0].Reason, "could not be rebased onto main: ") || strings.Contains(sum.Results[0].Reason, "\n") {
		t.Fatalf("reason: %q", sum.Results[0].Reason)
	}
	if n := fx.forge.Notifications(); len(n) != 1 || n[0].Change != bad {
		t.Fatalf("notifications: %+v", n)
	}
	if got := fx.git("worktree", "list", "--porcelain"); strings.Count(got, "worktree ") != 1 {
		t.Fatalf("worktrees left behind:\n%s", got)
	}

	// A verifier whose output trips the secret gate: no Capsule can be
	// recorded, which is a failed verification, not a stuck queue.
	fx = newFixture(t)
	key := "AKIA" + "IOSFODNN7" + "EXAMPLE"
	fx.author("agent-leak", fx.base, map[string]string{"fixture.txt": "aws_access_key_id = " + key + "\n"}, "test: add fixture\n")
	fx.author("agent-good", fx.base, map[string]string{"g.txt": "g\n"}, "good\n")
	tr := fx.train(nil)
	tr.Verify = LaneVerifier{RepoDir: fx.dir, Repo: "acme/widget", Target: "main", Deps: laneDeps(fx.store), Epoch: tr.Epoch,
		Verifier: lane.Command{Argv: []string{"sh", "-c", "cat fixture.txt 2>/dev/null; exit 0"}, Timeout: 20 * time.Second}}.Verify
	sum, err = tr.Run(ctx, false)
	if err != nil || len(sum.Results) != 2 || sum.Results[0].State != Evicted || sum.Results[1].State != Landed {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if r := sum.Results[0].Reason; !strings.HasPrefix(r, "verification recorded no capsule (") || !strings.Contains(r, "secret gate") || strings.Contains(r, key) {
		t.Fatalf("reason: %q", r)
	}

	// A store that does not answer is nobody's fault: nothing is evicted.
	fx = newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
	tr = fx.train(nil)
	deps := laneDeps(fx.store)
	deps.Push = func(context.Context, string) error { return &objstore.UnavailableError{Op: "PUT", Key: "cas/x"} }
	tr.Verify = LaneVerifier{RepoDir: fx.dir, Repo: "acme/widget", Target: "main", Deps: deps,
		Verifier: lane.Command{Argv: []string{"true"}, Timeout: 20 * time.Second}}.Verify
	sum, err = tr.Run(ctx, false)
	if !errors.Is(err, objstore.ErrUnavailable) || len(sum.Results) != 0 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 1 || q[0] != c || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("queue: %+v", q)
	}
	// Nor is a runner the lander does not have.
	deps = laneDeps(fx.store)
	deps.Runner = func(string) (lane.Runner, error) { return nil, fmt.Errorf("runner boat is not configured") }
	tr = fx.train(nil)
	tr.Verify = LaneVerifier{RepoDir: fx.dir, Repo: "acme/widget", Target: "main", Deps: deps, Verifier: lane.Command{Argv: []string{"true"}}}.Verify
	if sum, err = tr.Run(ctx, false); err == nil || len(sum.Results) != 0 || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("run: %+v %v", sum, err)
	}
}

// TestM2_2_EveryOutcomeIsKeptAndTheNewestWins: sequence numbers restart when
// a queue drains, so the same commit can be evicted and later land under the
// same queue ref. Both outcomes are kept; the newest is first.
func TestM2_2_EveryOutcomeIsKeptAndTheNewestWins(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
	clock := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	tr := fx.train(nil)
	tr.Now = func() time.Time { return clock }
	tr.Verify = func(context.Context, forge.Change, Rebased) (Verification, error) {
		return Verification{Pass: false, Reason: "flaky"}, nil
	}
	if sum, err := tr.Run(ctx, false); err != nil || sum.Count(Evicted) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	again, _, created, err := Enqueue(ctx, fx.forge, "main", "agent-a")
	if err != nil || !created || again != c {
		t.Fatalf("re-enqueue reused %+v, want the same ref as %+v (%v)", again, c, err)
	}
	// Same lander, same epoch, same second: the keys still differ.
	tr.Verify = func(context.Context, forge.Change, Rebased) (Verification, error) {
		return Verification{Pass: true}, nil
	}
	if sum, err := tr.Run(ctx, false); err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	if got := outcomeStates(t, fx); got != "agent-a=LANDED,agent-a=EVICTED" {
		t.Fatalf("outcomes, newest first: %s", got)
	}
	keys, _ := fx.store.List(ctx, "land/acme/widget/outcome/main/")
	want := fmt.Sprintf("land/acme/widget/outcome/main/00000001-%s-e1", c.Head.Short())
	if len(keys) != 2 || keys[0] != want+"-2.json" || keys[1] != want+".json" {
		t.Fatalf("outcome keys: %v", keys)
	}
	// A later epoch sorts above an earlier one at the same instant.
	fx.forge.SetRef("agent-b", fx.commit(fx.base, map[string]string{"a.txt": "conflict\n"}, "docs: b\n"))
	if _, _, _, err := Enqueue(ctx, fx.forge, "main", "agent-b"); err != nil {
		t.Fatal(err)
	}
	l2 := fx.train(nil)
	l2.Now = func() time.Time { return clock }
	if sum, err := l2.Run(ctx, false); err != nil || sum.Epoch != 2 || sum.Count(Evicted) != 1 {
		t.Fatalf("%+v %v", sum, err)
	}
	if got := outcomeStates(t, fx); got != "agent-b=EVICTED,agent-a=LANDED,agent-a=EVICTED" {
		t.Fatalf("outcomes, newest first: %s", got)
	}
}

// TestM2_2_AnEvictionOnceBegunIsFinishedEvenIfTheRunIsCancelled: the owner
// is told and the outcome recorded; the change is never silently dropped.
func TestM2_2_AnEvictionOnceBegunIsFinishedEvenIfTheRunIsCancelled(t *testing.T) {
	fx := newFixture(t)
	fx.author("agent-a", fx.base, map[string]string{"greet.sh": "#!/bin/sh\necho a\n"}, "a\n")
	b := fx.author("agent-b", fx.base, map[string]string{"greet.sh": "#!/bin/sh\necho b\n"}, "b\n")
	ctx, cancel := context.WithCancel(context.Background())
	tr := fx.train(nil)
	tr.Forge = hookForge{Forge: fx.forge, after: func(ref string, old, new forge.SHA, err error) {
		if ref == b.Ref && new.IsZero() {
			cancel() // the interrupt arrives right after the dequeue
		}
	}}
	sum, err := tr.Run(ctx, false)
	if !errors.Is(err, context.Canceled) || len(sum.Results) != 2 || sum.Results[1].State != Evicted {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if n := fx.forge.Notifications(); len(n) != 1 || n[0].Change != b {
		t.Fatalf("notifications: %+v", n)
	}
	if got := reportStates(fx); !strings.HasSuffix(got, "FAIL@"+b.Head.Short()) {
		t.Fatalf("reports: %s", got)
	}
	if got := outcomeStates(t, fx); !strings.Contains(got, "agent-b=EVICTED") {
		t.Fatalf("outcomes: %s", got)
	}
	// The outcome is recorded before the queue ref goes.
	if q, _ := fx.forge.Queue(context.Background(), "main"); len(q) != 0 {
		t.Fatalf("queue: %+v", q)
	}
}

// TestM2_2_ALanderFencedWhileVerifyingNeitherPushesNorEvicts: a higher epoch
// appears while lander 1 is inside its verification. Whatever the verdict,
// lander 1 writes nothing to the forge afterwards. This test fails if the
// fence before the push, or the fence before an eviction, is removed.
func TestM2_2_ALanderFencedWhileVerifyingNeitherPushesNorEvicts(t *testing.T) {
	ctx := context.Background()
	for _, pass := range []bool{true, false} {
		fx := newFixture(t)
		fx.store = s3Store(t)
		c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
		l1, l2 := fx.train(nil), fx.train(nil)
		l2.Holder = "lander-2"
		l1.Verify = func(context.Context, forge.Change, Rebased) (Verification, error) {
			if e, err := l2.Acquire(ctx); err != nil || e != 2 {
				t.Errorf("lander 2 acquire: %d %v", e, err)
			}
			return Verification{Pass: pass, Reason: "verifier failed"}, nil
		}
		before := len(fx.forge.Pushes())
		sum, err := l1.Run(ctx, false)
		if !errors.Is(err, ErrFenced) || len(sum.Results) != 0 || sum.Epoch != 1 {
			t.Fatalf("pass=%v: %+v %v", pass, sum, err)
		}
		if n := len(fx.forge.Pushes()) - before; n != 0 {
			t.Fatalf("pass=%v: the fenced lander made %d forge writes: %+v", pass, n, fx.forge.Pushes()[before:])
		}
		if len(fx.forge.Notifications()) != 0 || len(fx.forge.Reports()) != 0 || outcomeStates(t, fx) != "" {
			t.Fatalf("pass=%v: notifications %d, reports %d, outcomes %q", pass, len(fx.forge.Notifications()), len(fx.forge.Reports()), outcomeStates(t, fx))
		}
		if head, _ := fx.forge.Head(ctx, "main"); head != fx.base {
			t.Fatalf("pass=%v: main moved", pass)
		}
		if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 1 || q[0] != c {
			t.Fatalf("pass=%v: queue %+v", pass, q)
		}
		// Not even a push intent was left behind.
		if keys, _ := fx.store.List(ctx, "land/acme/widget/attempt/"); len(keys) != 0 {
			t.Fatalf("pass=%v: push intents: %v", pass, keys)
		}
	}
}

// TestM2_2_TrailersOfCommitsARebaseDoesNotReplayAreNeverLost: a merge commit
// carrying the evidence trailers is rejected by a rebase landing (with the
// way out), and its trailers ride in the union of a squash landing.
func TestM2_2_TrailersOfCommitsARebaseDoesNotReplayAreNeverLost(t *testing.T) {
	ctx := context.Background()
	build := func(fx *fixture) {
		c1 := fx.commit(fx.base, map[string]string{"one.txt": "1\n"}, "feat: one\n")
		s1 := fx.commit(fx.base, map[string]string{"side.txt": "s\n"}, "feat: side\n")
		env := []string{"GIT_INDEX_FILE=" + filepath.Join(t.TempDir(), "index")}
		fx.run(env, "", "read-tree", string(c1))
		blob := fx.run(nil, "s\n", "hash-object", "-w", "--stdin")
		fx.run(env, "", "update-index", "--add", "--cacheinfo", "100644,"+blob+",side.txt")
		tree := fx.run(env, "", "write-tree")
		m := forge.SHA(fx.run(nil, trailered("merge: side into feature", 7), "commit-tree", tree, "-p", string(c1), "-p", string(s1), "-F", "-"))
		fx.forge.SetRef("feature", m)
		if _, _, _, err := Enqueue(ctx, fx.forge, "main", "feature"); err != nil {
			t.Fatal(err)
		}
		fx.forge.SetRef("main", fx.commit(fx.base, map[string]string{"o.txt": "o\n"}, "other\n"))
	}
	fx := newFixture(t)
	build(fx)
	sum, err := fx.train(nil).Run(ctx, false)
	if err != nil || sum.Count(Evicted) != 1 || !strings.Contains(sum.Results[0].Reason, "rebase would drop the trailer Chimera-Intent") ||
		!strings.Contains(sum.Results[0].Reason, "--squash") {
		t.Fatalf("rebase run: %+v %v", sum, err)
	}
	if ok, _ := targetPushes(fx.forge); len(ok) != 0 {
		t.Fatal("a change that would lose trailers was pushed")
	}
	fx = newFixture(t)
	build(fx)
	tr := fx.train(nil)
	tr.Squash = true
	sum, err = tr.Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("squash run: %+v %v", sum, err)
	}
	if got := fx.trailers(sum.Results[0].Landed); got != "Chimera-Intent: "+intentOf(1)+"\nChimera-Capsule: "+capsuleOf(7) {
		t.Fatalf("squash trailers:\n%s", got)
	}
	if fx.files(sum.Results[0].Landed) != "README.md greet.sh o.txt one.txt side.txt verify/check.sh" {
		t.Fatalf("squash tree: %s", fx.files(sum.Results[0].Landed))
	}

	// A commit already upstream is left out by the rebase; its trailers are
	// in the target's history, so nothing is lost and the rest lands.
	fx = newFixture(t)
	a := fx.commit(fx.base, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))
	b := fx.commit(a, map[string]string{"b.txt": "b\n"}, trailered("docs: b", 2))
	fx.forge.SetRef("feature", b)
	if _, _, _, err := Enqueue(ctx, fx.forge, "main", "feature"); err != nil {
		t.Fatal(err)
	}
	other := fx.commit(fx.base, map[string]string{"o.txt": "o\n"}, "other\n")
	fx.forge.SetRef("main", fx.commit(other, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))) // a, cherry-picked
	sum, err = fx.train(nil).Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("partly-upstream run: %+v %v", sum, err)
	}
	if got := fx.subjects(other, sum.Results[0].Landed); strings.Join(got, "|") != "docs: a|docs: b" {
		t.Fatalf("history: %q", got)
	}
}

// TestM2_2_SquashWritesARepeatedTrailerOnce: a source that repeats a trailer
// is a legitimate change; the squash carries the de-duplicated union.
func TestM2_2_SquashWritesARepeatedTrailerOnce(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	signed := "Signed-off-by: Dev <dev@example.com>"
	fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n\nWhy a.\n\n"+signed+"\nReviewed-by: R <r@example.com>\n"+signed+"\n")
	tr := fx.train(nil)
	tr.Squash = true
	sum, err := tr.Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	if got := fx.trailers(sum.Results[0].Landed); got != signed+"\nReviewed-by: R <r@example.com>" {
		t.Fatalf("trailers:\n%s", got)
	}
	if msg := fx.git("log", "-1", "--format=%B", string(sum.Results[0].Landed)); !strings.HasPrefix(msg, "docs: a\n\nWhy a.\n\n"+signed+"\n") || strings.Count(msg, signed) != 1 {
		t.Fatalf("message:\n%s", msg)
	}
}

func TestM2_2_ObjectsTravelThroughTheRemoteAndStagingRefsAreRemoved(t *testing.T) {
	ctx := context.Background()
	// The forge is a bare repository; the lander works in its own clone.
	bare := &repo{t: t, dir: t.TempDir()}
	bare.git("init", "-q", "--bare", "-b", "main")
	base := bare.commit(forge.Zero, map[string]string{"README.md": "# widget\n"}, "base\n")
	bare.git("update-ref", "refs/heads/main", string(base))
	clone := &repo{t: t, dir: filepath.Join(t.TempDir(), "lander")}
	(&repo{t: t, dir: t.TempDir()}).git("clone", "-q", bare.dir, clone.dir)
	// After the clone: an agent pushes a branch, and main moves.
	head := bare.commit(base, map[string]string{"a.txt": "a\n"}, trailered("docs: a", 1))
	bare.git("update-ref", "refs/heads/agent-a", string(head))
	moved := bare.commit(base, map[string]string{"other.txt": "o\n"}, "other: on main\n")
	bare.git("update-ref", "refs/heads/main", string(moved))
	f := &forge.Git{Dir: bare.dir}
	c, pos, created, err := Enqueue(ctx, f, "main", "agent-a")
	if err != nil || !created || pos != 1 {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := gitx.Run(ctx, clone.dir, "cat-file", "-e", string(head)); err == nil {
		t.Fatal("the lander's clone already has the change; the test proves nothing")
	}
	tr := &Train{Forge: f, Store: objstore.NewDir(filepath.Join(t.TempDir(), "store")), Repo: "acme/widget", Target: "main", Holder: "lander-1",
		Git: &GitWorkspace{Dir: clone.dir, Remote: "origin"},
		Verify: func(ctx context.Context, c forge.Change, rb Rebased) (Verification, error) {
			return Verification{Pass: true}, nil
		}}
	sum, err := tr.Run(ctx, false)
	if err != nil || sum.Count(Landed) != 1 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	landed := sum.Results[0].Landed
	if got := bare.git("rev-parse", "refs/heads/main"); got != string(landed) {
		t.Fatalf("forge main at %s, want %s", got, landed)
	}
	if p := bare.parents(landed); len(p) != 1 || p[0] != string(moved) {
		t.Fatalf("landed parent %v, want %s", p, moved)
	}
	if got := bare.trailers(landed); !strings.Contains(got, "Chimera-Capsule: "+capsuleOf(1)) {
		t.Fatalf("trailers on the forge: %s", got)
	}
	if refs := bare.git("for-each-ref", "--format=%(refname)", "refs/chimera"); refs != "" {
		t.Fatalf("queue or staging refs left on the forge:\n%s", refs)
	}
	// A lander killed right after its push leaves the queue ref and the
	// staging ref behind; the next lander removes both.
	// The lander that recovers works in another clone, made before the
	// change existed: it has to fetch the target to know what is in it.
	second := &repo{t: t, dir: filepath.Join(t.TempDir(), "lander-2")}
	(&repo{t: t, dir: t.TempDir()}).git("clone", "-q", bare.dir, second.dir)
	head2 := bare.commit(base, map[string]string{"b.txt": "b\n"}, "docs: b\n")
	bare.git("update-ref", "refs/heads/agent-b", string(head2))
	if _, _, _, err := Enqueue(ctx, f, "main", "agent-b"); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(died); !ok {
					panic(r)
				}
			}
		}()
		dying := *tr
		dying.Forge = hookForge{Forge: f, after: func(ref string, old, new forge.SHA, err error) {
			if ref == "refs/heads/main" && err == nil {
				panic(died{})
			}
		}}
		dying.Run(ctx, false)
	}()
	if refs := bare.git("for-each-ref", "--format=%(refname)", "refs/chimera"); strings.Count(refs, "\n") != 1 || !strings.Contains(refs, StagingPrefix) {
		t.Fatalf("refs after the kill:\n%s", refs)
	}
	fresh := &Train{Forge: f, Store: tr.Store, Repo: tr.Repo, Target: "main", Holder: "lander-2", Git: &GitWorkspace{Dir: second.dir, Remote: "origin"}, Verify: tr.Verify}
	if tip := bare.git("rev-parse", "refs/heads/main"); (&GitWorkspace{Dir: second.dir}).has(ctx, forge.SHA(tip)) {
		t.Fatal("the second clone already has the pushed commit; the test proves nothing")
	}
	if sum, err := fresh.Run(ctx, false); err != nil || sum.Count(Landed) != 1 || sum.Results[0].Reason != "already in main" || len(sum.Results[0].Warnings) != 0 {
		t.Fatalf("recovery: %+v %v", sum, err)
	}
	if refs := bare.git("for-each-ref", "--format=%(refname)", "refs/chimera"); refs != "" {
		t.Fatalf("refs left after recovery:\n%s", refs)
	}
	// The lander's own branches did not move, and the forge logged the check.
	if got := clone.git("rev-parse", "refs/heads/main"); got != string(base) {
		t.Fatalf("the lander's own main moved to %s", got)
	}
	events, err := f.Events(ctx)
	if err != nil || len(events) != 2 || events[0].Kind != "report" || events[0].SHA != landed || events[0].Check.State != forge.Pass || events[1].Check.State != forge.Pass {
		t.Fatalf("forge events: %+v %v", events, err)
	}
	_ = c
}

func TestM2_2_AVerifierThatCannotDecideLandsNothing(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t)
	c := fx.author("agent-a", fx.base, map[string]string{"a.txt": "a\n"}, "docs: a\n")
	tr := fx.train(nil)
	tr.Verify = func(context.Context, forge.Change, Rebased) (Verification, error) {
		return Verification{}, fmt.Errorf("store unavailable")
	}
	sum, err := tr.Run(ctx, false)
	if err == nil || !strings.Contains(err.Error(), "verify agent-a: store unavailable") || len(sum.Results) != 0 {
		t.Fatalf("run: %+v %v", sum, err)
	}
	// Fail closed, and blame no one: nothing landed, nothing was evicted.
	if head, _ := fx.forge.Head(ctx, "main"); head != fx.base {
		t.Fatal("main moved without a verdict")
	}
	if q, _ := fx.forge.Queue(ctx, "main"); len(q) != 1 || q[0] != c || len(fx.forge.Notifications()) != 0 {
		t.Fatalf("queue: %+v", q)
	}
	// An unreadable epoch fence also refuses to push.
	tr = fx.train(nil)
	tr.Store = brokenList{fx.store}
	if _, err := tr.Run(ctx, false); err == nil {
		t.Fatal("a lander that cannot read the epochs ran")
	}
	if _, err := (&Train{}).Run(ctx, false); err == nil {
		t.Fatal("an unconfigured train ran")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := fx.train(nil).Run(cctx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run: %v", err)
	}
}

type brokenList struct{ objstore.Store }

func (brokenList) List(context.Context, string) ([]string, error) {
	return nil, &objstore.UnavailableError{Op: "LIST", Key: "land/"}
}
