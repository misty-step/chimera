package forge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func randSHA(t *testing.T) SHA {
	t.Helper()
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return SHA(hex.EncodeToString(b))
}

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

// subject is one Forge under the contract, with a way to mint a commit on
// top of a parent that the forge will accept as a fast-forward of it.
type subject struct {
	forge  Forge
	commit func(parent SHA) SHA
}

func fakeSubject(t *testing.T) subject {
	return subject{forge: NewFake(), commit: func(SHA) SHA { return randSHA(t) }}
}

func gitSubject(t *testing.T, bare bool) subject {
	t.Helper()
	dir := t.TempDir()
	if bare {
		git(t, dir, "init", "-q", "--bare", "-b", "main")
	} else {
		git(t, dir, "init", "-q", "-b", "main")
	}
	tree := git(t, dir, "hash-object", "-t", "tree", "-w", "/dev/null")
	n := 0
	var mu sync.Mutex
	return subject{forge: &Git{Dir: dir}, commit: func(parent SHA) SHA {
		mu.Lock()
		defer mu.Unlock()
		n++
		args := []string{"commit-tree", tree, "-m", fmt.Sprintf("commit %d", n)}
		if !parent.IsZero() {
			args = append(args, "-p", string(parent))
		}
		return SHA(git(t, dir, args...))
	}}
}

func githubSubject(t *testing.T) (subject, *ghFake) {
	t.Helper()
	gh := newGHFake(t)
	return subject{forge: gh.client(), commit: func(parent SHA) SHA {
		sha := randSHA(t)
		gh.mu.Lock()
		gh.parents[string(sha)] = string(parent)
		gh.mu.Unlock()
		return sha
	}}, gh
}

// TestM2_2_ForgeContractHoldsForEveryAdapter runs the same assertions
// against the in-memory fake, the Git adapter (work tree and bare), and the
// GitHub adapter speaking to a loopback fake of the REST API.
func TestM2_2_ForgeContractHoldsForEveryAdapter(t *testing.T) {
	gh, _ := githubSubject(t)
	subjects := map[string]subject{"fake": fakeSubject(t), "git": gitSubject(t, false), "git-bare": gitSubject(t, true), "github": gh}
	for name, s := range subjects {
		t.Run(name, func(t *testing.T) { contract(t, s) })
	}
}

func contract(t *testing.T, s subject) {
	ctx := context.Background()
	f := s.forge
	c1 := s.commit(Zero)
	c2 := s.commit(c1)
	c3 := s.commit(c2)
	side := s.commit(c1)

	// Head of a ref that does not exist.
	if _, err := f.Head(ctx, "main"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("head of a missing ref: %v", err)
	}
	// Create is a compare-and-swap from Zero.
	if err := f.Push(ctx, "main", Zero, c1); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Push(ctx, "main", Zero, c2); !errors.Is(err, ErrStale) {
		t.Fatalf("create over an existing ref: %v", err)
	}
	if got, err := f.Head(ctx, "refs/heads/main"); err != nil || got != c1 {
		t.Fatalf("head: %s %v", got, err)
	}
	// Update moves the ref only from old.
	if err := f.Push(ctx, "refs/heads/main", c1, c2); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := f.Push(ctx, "main", c1, side); !errors.Is(err, ErrStale) {
		t.Fatalf("update from a stale old: %v", err)
	}
	if err := f.Push(ctx, "main", Zero, c3); !errors.Is(err, ErrStale) {
		t.Fatalf("create over a moved ref: %v", err)
	}
	if got, _ := f.Head(ctx, "main"); got != c2 {
		t.Fatalf("a refused push moved the ref to %s", got)
	}
	if err := f.Push(ctx, "main", c2, c3); err != nil {
		t.Fatalf("second update: %v", err)
	}
	// Delete is a compare-and-swap to Zero.
	if err := f.Push(ctx, "scratch", Zero, c1); err != nil {
		t.Fatal(err)
	}
	if err := f.Push(ctx, "scratch", c2, Zero); !errors.Is(err, ErrStale) {
		t.Fatalf("delete from a stale old: %v", err)
	}
	if err := f.Push(ctx, "scratch", c1, Zero); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.Head(ctx, "scratch"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("head after delete: %v", err)
	}
	if err := f.Push(ctx, "scratch", c1, Zero); !errors.Is(err, ErrStale) {
		t.Fatalf("delete of a missing ref: %v", err)
	}
	// A ref name that prefixes another is not that ref.
	if err := f.Push(ctx, "feature/x", Zero, c1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Head(ctx, "feature"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("head of a ref prefix: %v", err)
	}

	// The queue is refs: FIFO by sequence, per target, and gone when deleted.
	if q, err := f.Queue(ctx, "main"); err != nil || len(q) != 0 {
		t.Fatalf("empty queue: %v %v", q, err)
	}
	for _, e := range []struct {
		target string
		seq    int
		branch string
		head   SHA
	}{{"main", 3, "feature/c", c3}, {"main", 1, "a", c1}, {"main", 2, "b", c2}, {"mainline", 1, "other", c1}, {"release/1.0", 7, "fix", c2}} {
		if err := f.Push(ctx, QueueRef(e.target, e.seq, e.branch), Zero, e.head); err != nil {
			t.Fatalf("enqueue %s: %v", e.branch, err)
		}
	}
	q, err := f.Queue(ctx, "refs/heads/main")
	if err != nil || len(q) != 3 {
		t.Fatalf("queue: %+v %v", q, err)
	}
	want := []Change{
		{ID: "1/a", Ref: QueueRef("main", 1, "a"), Seq: 1, Branch: "a", Head: c1, Target: "main"},
		{ID: "2/b", Ref: QueueRef("main", 2, "b"), Seq: 2, Branch: "b", Head: c2, Target: "main"},
		{ID: "3/feature/c", Ref: QueueRef("main", 3, "feature/c"), Seq: 3, Branch: "feature/c", Head: c3, Target: "main"},
	}
	for i := range want {
		if q[i] != want[i] {
			t.Fatalf("queue[%d] = %+v, want %+v", i, q[i], want[i])
		}
	}
	if rq, _ := f.Queue(ctx, "release/1.0"); len(rq) != 1 || rq[0].Branch != "fix" || rq[0].Seq != 7 {
		t.Fatalf("release queue: %+v", rq)
	}
	if err := f.Push(ctx, q[0].Ref, q[0].Head, Zero); err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	if q, _ = f.Queue(ctx, "main"); len(q) != 2 || q[0].Branch != "b" {
		t.Fatalf("queue after dequeue: %+v", q)
	}

	// Many writers, one winner.
	const writers = 8
	shas := make([]SHA, writers)
	for i := range shas {
		shas[i] = s.commit(c1)
	}
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.Push(ctx, "contended", Zero, shas[i])
		}(i)
	}
	wg.Wait()
	won := -1
	for i, err := range errs {
		switch {
		case err == nil && won >= 0:
			t.Fatalf("writers %d and %d both created the ref", won, i)
		case err == nil:
			won = i
		case !errors.Is(err, ErrStale):
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	if won < 0 {
		t.Fatal("no writer created the ref")
	}
	if got, _ := f.Head(ctx, "contended"); got != shas[won] {
		t.Fatalf("ref is at %s, winner pushed %s", got, shas[won])
	}

	// Report and Notify are accepted.
	if err := f.Report(ctx, c3, Check{Name: "chimera/land", State: Pass, Title: "landed", Summary: "verified"}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if err := f.Notify(ctx, q[0], "evicted: conflict in greet.sh"); err != nil {
		t.Fatalf("notify: %v", err)
	}
}

func TestM2_2_QueueRefsRoundTripAndIgnoreForeignRefs(t *testing.T) {
	ref := QueueRef("refs/heads/main", 12, "refs/heads/feature/x")
	if ref != "refs/chimera/land/main/00000012/feature/x" {
		t.Fatalf("queue ref %q", ref)
	}
	c, ok := ChangeFromRef("main", ref, "abc")
	if !ok || c.Seq != 12 || c.Branch != "feature/x" || c.Target != "main" || c.ID != "12/feature/x" || c.Ref != ref || c.Head != "abc" {
		t.Fatalf("%+v %v", c, ok)
	}
	for _, foreign := range []string{"refs/heads/main", "refs/chimera/land/main/12/x", "refs/chimera/land/main/00000012", "refs/chimera/land/main/00000012/",
		"refs/chimera/land/mainline/00000001/x", "refs/chimera/land/main/0000001x/y", "refs/chimera/staging/abc"} {
		if _, ok := ChangeFromRef("main", foreign, "abc"); ok {
			t.Errorf("%s decoded as a queue ref of main", foreign)
		}
	}
	refs := map[string]SHA{QueueRef("main", 2, "b"): "2", QueueRef("main", 2, "a"): "1", QueueRef("main", 1, "z"): "3", QueueRef("main", 9, "gone"): Zero, "refs/heads/main": "4"}
	q := QueueFromRefs("main", refs)
	if len(q) != 3 || q[0].Branch != "z" || q[1].Branch != "a" || q[2].Branch != "b" {
		t.Fatalf("%+v", q)
	}
	if !Same(Zero, SHA(strings.Repeat("0", 40))) || Same("a", "b") || !Same("a", "a") || Same("a", Zero) {
		t.Fatal("Same")
	}
	if SHA("0123456789abcdef").Short() != "0123456789ab" || SHA("abc").Short() != "abc" {
		t.Fatal("Short")
	}
}

func TestM2_2_FakeRecordsEverythingAndInjectsFaults(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	f.SetRef("main", "a1")
	boom := errors.New("boom")
	f.FailNext("Push", boom)
	if err := f.Push(ctx, "main", "a1", "b2"); err != boom {
		t.Fatalf("injected failure: %v", err)
	}
	// The hook runs before the push is decided: an outside writer moves the ref.
	f.OnPush(func(ref string, old, new SHA) {
		if ref == "refs/heads/main" && new == "b2" {
			f.SetRef("main", "c3")
		}
	})
	if err := f.Push(ctx, "main", "a1", "b2"); !errors.Is(err, ErrStale) {
		t.Fatalf("push after the ref moved: %v", err)
	}
	f.OnPush(nil)
	if err := f.Push(ctx, "main", "c3", "d4"); err != nil {
		t.Fatal(err)
	}
	pushes := f.Pushes()
	if len(pushes) != 3 || pushes[0].Err != boom || !errors.Is(pushes[1].Err, ErrStale) || pushes[2].Err != nil || pushes[2].Ref != "refs/heads/main" || pushes[2].New != "d4" {
		t.Fatalf("%+v", pushes)
	}
	c := Change{ID: "1/x", Branch: "x", Head: "d4", Target: "main"}
	if err := f.Report(ctx, "d4", Check{Name: "chimera/land", State: Fail, Title: "evicted"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Notify(ctx, c, "reason"); err != nil {
		t.Fatal(err)
	}
	if r := f.Reports(); len(r) != 1 || r[0].SHA != "d4" || r[0].Check.State != Fail {
		t.Fatalf("%+v", r)
	}
	if n := f.Notifications(); len(n) != 1 || n[0].Change != c || n[0].Msg != "reason" {
		t.Fatalf("%+v", n)
	}
	f.SetRef("main", Zero)
	if _, err := f.Head(ctx, "main"); !errors.Is(err, ErrNotFound) {
		t.Fatal("SetRef(Zero) did not delete")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Push(cctx, "main", Zero, "e5"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled push: %v", err)
	}
}

func TestM2_2_GitAdapterKeepsReportsAndNotificationsOutOfGit(t *testing.T) {
	ctx := context.Background()
	s := gitSubject(t, true)
	g := s.forge.(*Git)
	c1 := s.commit(Zero)
	if err := g.Push(ctx, "main", Zero, c1); err != nil {
		t.Fatal(err)
	}
	before := git(t, g.Dir, "for-each-ref")
	change := Change{ID: "1/feat", Ref: QueueRef("main", 1, "feat"), Seq: 1, Branch: "feat", Head: c1, Target: "main"}
	if err := g.Report(ctx, c1, Check{Name: "chimera/land", State: Fail, Title: "evicted: conflict", Summary: "greet.sh"}); err != nil {
		t.Fatal(err)
	}
	if err := g.Notify(ctx, change, "evicted: conflict in greet.sh"); err != nil {
		t.Fatal(err)
	}
	events, err := g.Events(ctx)
	if err != nil || len(events) != 2 {
		t.Fatalf("%+v %v", events, err)
	}
	if events[0].Kind != "report" || events[0].SHA != c1 || events[0].Check.State != Fail || events[0].At == "" ||
		events[1].Kind != "notify" || *events[1].Change != change || events[1].Msg != "evicted: conflict in greet.sh" {
		t.Fatalf("%+v", events)
	}
	// The log lives in the git directory; no ref and no object was written for it.
	if _, err := os.Stat(filepath.Join(g.Dir, "chimera", "forge.jsonl")); err != nil {
		t.Fatalf("forge log: %v", err)
	}
	if after := git(t, g.Dir, "for-each-ref"); after != before {
		t.Fatalf("reporting changed refs:\n%s\n%s", before, after)
	}
	// A push of an object the repository does not have is refused, and is not "stale".
	if err := g.Push(ctx, "main", c1, randSHA(t)); err == nil || errors.Is(err, ErrStale) {
		t.Fatalf("push of a missing object: %v", err)
	}
	if got, _ := g.Head(ctx, "main"); got != c1 {
		t.Fatalf("head moved to %s", got)
	}
	if empty, err := (&Git{Dir: t.TempDir(), Log: filepath.Join(t.TempDir(), "none.jsonl")}).Events(ctx); err != nil || empty != nil {
		t.Fatalf("missing log: %v %v", empty, err)
	}
}
