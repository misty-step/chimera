package inlet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chimera/pkg/forge"
	"chimera/pkg/objstore"
)

func parents(t *testing.T, repo string, sha forge.SHA) []string {
	t.Helper()
	return strings.Fields(git(t, repo, "log", "-1", "--format=%P", string(sha)))
}

func TestM2_3_IntentNitsCoalesceIntoOneFolioPRPerDebounceWindow(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, func(o *Options, _ *Deps) { o.Debounce = 10 * time.Minute })
	n := 0
	f.classifier.decide = func(nit Nit) (Decision, error) {
		n++
		return Decision{Kind: KindIntent, Summary: "summary of " + nit.Text}, nil
	}
	start := f.clock.Now()
	for i, text := range []string{"first nit", "second nit", "third nit"} {
		r := f.owner(nitText(text))
		if r.Code != 202 || r.Status != StatusFolio || r.Pending != i+1 || r.Branch != "chimera/folio" {
			t.Fatalf("%s: %+v", text, r)
		}
		f.clock.Advance(time.Minute)
	}
	// Inside the window nothing is pushed, however often the clock is checked.
	for _, at := range []time.Duration{3 * time.Minute, 9*time.Minute + 59*time.Second} {
		if flushed, err := f.h.Tick(ctx, start.Add(at)); flushed || err != nil || len(f.forge.Pushes()) != 0 {
			t.Fatalf("tick at +%s: flushed=%v err=%v pushes=%d", at, flushed, err, len(f.forge.Pushes()))
		}
	}
	// The window is armed by the FIRST nit: it elapses ten minutes after it.
	if flushed, err := f.h.Tick(ctx, start.Add(10*time.Minute)); !flushed || err != nil {
		t.Fatalf("tick at the window's end: flushed=%v err=%v", flushed, err)
	}
	pushes, notes := f.forge.Pushes(), f.forge.Notifications()
	if len(pushes) != 1 || pushes[0].Err != nil || pushes[0].Ref != "refs/heads/chimera/folio" || !pushes[0].Old.IsZero() || len(notes) != 1 {
		t.Fatalf("pushes=%+v notes=%d", pushes, len(notes))
	}
	first := pushes[0].New
	note := notes[0]
	if note.Change.Branch != "chimera/folio" || note.Change.Target != "main" || note.Change.Head != first || note.Change.Ref != "" {
		t.Fatalf("notified change %+v", note.Change)
	}
	for _, want := range []string{"folio: owner nits for review\n\n", "nit-20261127-0001: summary of first nit", "nit-20261127-0002: summary of second nit",
		"nit-20261127-0003: summary of third nit", "folio/rulings/nit-20261127-0003.md"} {
		if !strings.Contains(note.Msg, want) {
			t.Errorf("notification lacks %q:\n%s", want, note.Msg)
		}
	}
	if got := parents(t, f.repo, first); len(got) != 1 || got[0] != string(f.head) {
		t.Fatalf("first commit parents %v", got)
	}
	files := git(t, f.repo, "diff", "--name-only", string(f.head), string(first))
	if files != "folio/rulings/nit-20261127-0001.md\nfolio/rulings/nit-20261127-0002.md\nfolio/rulings/nit-20261127-0003.md" {
		t.Fatalf("first commit:\n%s", files)
	}
	if msg := git(t, f.repo, "log", "-1", "--format=%s", string(first)); msg != "folio: record 3 owner nits" {
		t.Fatalf("subject %q", msg)
	}
	// Nothing waits; a tick with nothing armed does nothing.
	if flushed, _ := f.h.Tick(ctx, f.clock.Advance(time.Hour)); flushed || f.h.Pending() != 0 || len(f.forge.Pushes()) != 1 {
		t.Fatal("an empty window flushed")
	}

	// A later nit starts a new window and updates the SAME branch: still one PR.
	armed := f.clock.Now()
	if r := f.owner(nitText("fourth nit")); r.Pending != 1 {
		t.Fatalf("%+v", r)
	}
	if flushed, _ := f.h.Tick(ctx, armed.Add(10*time.Minute-time.Second)); flushed {
		t.Fatal("second window flushed early")
	}
	if flushed, err := f.h.Tick(ctx, armed.Add(10*time.Minute)); !flushed || err != nil {
		t.Fatalf("second window: %v %v", flushed, err)
	}
	pushes = f.forge.Pushes()
	if len(pushes) != 2 || pushes[1].Ref != "refs/heads/chimera/folio" || pushes[1].Old != first || pushes[1].Err != nil {
		t.Fatalf("second push %+v", pushes)
	}
	second := pushes[1].New
	if got := parents(t, f.repo, second); len(got) != 1 || got[0] != string(first) {
		t.Fatalf("second commit does not fast-forward the branch: parents %v", got)
	}
	refs := f.forge.Refs()
	if len(refs) != 2 || refs["refs/heads/main"] != f.head || refs["refs/heads/chimera/folio"] != second {
		t.Fatalf("refs %v: want main and exactly one folio branch", refs)
	}
	if len(f.forge.Notifications()) != 2 || !strings.Contains(f.forge.Notifications()[1].Msg, "nit-20261127-0004") {
		t.Fatal("second update not announced")
	}

	// The target moves (code and Folio both change): the next update merges it
	// in, keeps every ruling, and still fast-forwards the one branch.
	writeFile(t, f.repo, "cmd/chimera/main.go", "package main\n\nfunc main() { println(1) }\n")
	writeFile(t, f.repo, "DESIGN.md", designV1+"Tables scroll inside their container.\n")
	git(t, f.repo, "commit", "-q", "-am", "main moves")
	moved := forge.SHA(git(t, f.repo, "rev-parse", "HEAD"))
	f.forge.SetRef("main", moved)
	f.owner(nitText("fifth nit"))
	up, err := f.h.Flush(ctx)
	if err != nil || !up.Pushed {
		t.Fatalf("%+v %v", up, err)
	}
	third := up.Change.Head
	if got := parents(t, f.repo, third); len(got) != 2 || got[0] != string(second) || got[1] != string(moved) {
		t.Fatalf("merge parents %v, want [%s %s]", got, second, moved)
	}
	files = git(t, f.repo, "diff", "--name-only", string(moved), string(third))
	want := []string{}
	for i := 1; i <= 5; i++ {
		want = append(want, "folio/rulings/nit-20261127-000"+string(rune('0'+i))+".md")
	}
	if files != strings.Join(want, "\n") {
		t.Fatalf("after the target moved the PR changes:\n%s", files)
	}
	if got := git(t, f.repo, "show", string(third)+":cmd/chimera/main.go"); !strings.Contains(got, "println(1)") {
		t.Fatal("the rebuilt branch lost the target's change")
	}
	if len(f.forge.Refs()) != 2 || f.pushes() != 3 {
		t.Fatalf("refs=%v pushes=%d", f.forge.Refs(), f.pushes())
	}
	if st := git(t, f.repo, "status", "--porcelain"); st != "" {
		t.Fatalf("work tree touched: %q", st)
	}
}

func TestM2_3_FolioPRRetriesAStaleCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	f.owner(nitText("first"))
	if _, err := f.h.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	first := f.forge.Refs()["refs/heads/chimera/folio"]
	// Someone else adds a ruling to the branch between our read and our push.
	git(t, f.repo, "checkout", "-q", "-b", "side", string(first))
	writeFile(t, f.repo, "folio/rulings/by-hand.md", "# by hand\n")
	git(t, f.repo, "add", "-A")
	git(t, f.repo, "commit", "-q", "-m", "folio: ruling by hand")
	byHand := forge.SHA(git(t, f.repo, "rev-parse", "HEAD"))
	git(t, f.repo, "checkout", "-q", "main")
	var once sync.Once
	f.forge.OnPush(func(ref string, old, new forge.SHA) {
		once.Do(func() { f.forge.SetRef("chimera/folio", byHand) })
	})
	f.owner(nitText("second"))
	up, err := f.h.Flush(ctx)
	if err != nil || !up.Pushed {
		t.Fatalf("%+v %v", up, err)
	}
	pushes := f.forge.Pushes()
	if len(pushes) != 3 || !errors.Is(pushes[1].Err, forge.ErrStale) || pushes[1].Old != first || pushes[2].Err != nil || pushes[2].Old != byHand {
		t.Fatalf("pushes %+v", pushes)
	}
	if got := parents(t, f.repo, pushes[2].New); len(got) != 1 || got[0] != string(byHand) {
		t.Fatalf("retry was not rebuilt on the branch's new head: parents %v", got)
	}
	tree := git(t, f.repo, "ls-tree", "-r", "--name-only", string(pushes[2].New), "folio/rulings")
	if tree != "folio/rulings/by-hand.md\nfolio/rulings/nit-20261127-0001.md\nfolio/rulings/nit-20261127-0002.md" {
		t.Fatalf("rulings after the retry:\n%s", tree)
	}
	if len(f.forge.Notifications()) != 2 {
		t.Fatalf("%d notifications", len(f.forge.Notifications()))
	}
	// A branch that never stops moving is an error, not a loop, and the batch is kept.
	f.forge.OnPush(nil)
	for i := 0; i < pushAttempts; i++ {
		f.forge.FailNext("Push", forge.ErrStale)
	}
	f.owner(nitText("third"))
	if _, err := f.h.Flush(ctx); err == nil || !errors.Is(err, forge.ErrStale) || f.h.Pending() != 1 {
		t.Fatalf("err=%v pending=%d", err, f.h.Pending())
	}
	if up, err := f.h.Flush(ctx); err != nil || !up.Pushed || f.h.Pending() != 0 {
		t.Fatalf("retry after failure: %+v %v", up, err)
	}
}

func TestM2_3_AnnouncementIsRetriedWithoutPushingTwice(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	f.owner(nitText("first"))
	f.forge.FailNext("Notify", errors.New("forge unavailable"))
	armed := f.clock.Now()
	up, err := f.h.Flush(ctx)
	if err == nil || !up.Pushed || f.h.Pending() != 1 || f.pushes() != 1 || len(f.forge.Notifications()) != 0 {
		t.Fatalf("up=%+v err=%v pending=%d", up, err, f.h.Pending())
	}
	// The failed batch waits a full window again: at most one update per window.
	if flushed, _ := f.h.Tick(ctx, armed.Add(DefaultDebounce-time.Second)); flushed {
		t.Fatal("retried inside the window")
	}
	if flushed, err := f.h.Tick(ctx, armed.Add(DefaultDebounce)); !flushed || err != nil {
		t.Fatalf("retry: %v %v", flushed, err)
	}
	if f.pushes() != 1 || len(f.forge.Pushes()) != 1 || len(f.forge.Notifications()) != 1 || f.h.Pending() != 0 {
		t.Fatalf("pushes=%d notifications=%d pending=%d", len(f.forge.Pushes()), len(f.forge.Notifications()), f.h.Pending())
	}
}

func TestM2_3_ClassifierSeesEarlierProposalsAndStaleEditsAreDropped(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	edit1 := productV1 + "**[UI-2] Totals are right-aligned.**\n"
	edit2 := edit1 + "**[UI-3] Negative totals use a minus sign.**\n"
	answers := []Decision{
		{Kind: KindIntent, Summary: "right-aligned", Edits: []Edit{{Path: "PRODUCT.md", Content: edit1}}},
		{Kind: KindIntent, Summary: "minus sign", Edits: []Edit{{Path: "PRODUCT.md", Content: edit2}}},
	}
	i := 0
	f.classifier.decide = func(Nit) (Decision, error) { d := answers[i]; i++; return d, nil }
	f.owner(nitText("one"))
	f.owner(nitText("two"))
	seen := f.classifier.seen
	if seen[0].Product != productV1 || seen[0].Design != designV1 {
		t.Fatalf("first classification saw %+v", seen[0])
	}
	// The second nit is judged against the Folio as the first one left it.
	if seen[1].Product != edit1 {
		t.Fatalf("second classification saw:\n%s", seen[1].Product)
	}
	up, err := f.h.Flush(ctx)
	if err != nil || len(up.Dropped) != 0 {
		t.Fatalf("%+v %v", up, err)
	}
	if got := git(t, f.repo, "show", string(up.Change.Head)+":PRODUCT.md") + "\n"; got != edit2 {
		t.Fatalf("PRODUCT.md on the branch:\n%s", got)
	}
	// With the PR open, the next classification reads the branch's Folio.
	answers = append(answers, Decision{Kind: KindIntent, Summary: "stale", Edits: []Edit{{Path: "PRODUCT.md", Content: "# Product\n\nrewritten from a stale read\n"}, {Path: "DESIGN.md", Content: designV1 + "fresh\n"}}})
	f.owner(nitText("three"))
	if f.classifier.seen[2].Product != edit2 {
		t.Fatalf("third classification saw:\n%s", f.classifier.seen[2].Product)
	}
	// Before the window ends someone edits PRODUCT.md on the branch: the
	// queued edit was made against a Folio that no longer exists. It is
	// dropped, never written over the newer text; the rest of the nit lands.
	git(t, f.repo, "checkout", "-q", "-b", "side", string(up.Change.Head))
	writeFile(t, f.repo, "PRODUCT.md", edit2+"**[UI-4] Added by hand.**\n")
	git(t, f.repo, "commit", "-q", "-am", "folio: by hand")
	byHand := forge.SHA(git(t, f.repo, "rev-parse", "HEAD"))
	git(t, f.repo, "checkout", "-q", "main")
	f.forge.SetRef("chimera/folio", byHand)
	up, err = f.h.Flush(ctx)
	if err != nil || !up.Pushed || len(up.Dropped) != 1 || up.Dropped[0] != "20261127-0003: PRODUCT.md" {
		t.Fatalf("%+v %v", up, err)
	}
	if got := git(t, f.repo, "show", string(up.Change.Head)+":PRODUCT.md"); !strings.HasSuffix(got, "**[UI-4] Added by hand.**") {
		t.Fatalf("a stale edit overwrote newer Folio text:\n%s", got)
	}
	if got := git(t, f.repo, "show", string(up.Change.Head)+":DESIGN.md"); !strings.HasSuffix(got, "fresh") {
		t.Fatalf("the fresh edit of the same nit was lost:\n%s", got)
	}
	if got := git(t, f.repo, "show", string(up.Change.Head)+":folio/rulings/nit-20261127-0003.md"); !strings.Contains(got, "three") {
		t.Fatal("the ruling of the nit with the stale edit was lost")
	}
	notes := f.forge.Notifications()
	if !strings.Contains(notes[len(notes)-1].Msg, "dropped as stale: 20261127-0003: PRODUCT.md") {
		t.Fatalf("the drop was not announced:\n%s", notes[len(notes)-1].Msg)
	}
	// Once the PR is merged, the Folio is read from the target again and the
	// next nit opens the branch afresh on top of it.
	f.forge.SetRef("main", up.Change.Head)
	answers = append(answers, Decision{Kind: KindIntent, Summary: "after the merge"})
	f.owner(nitText("four"))
	if !strings.Contains(f.classifier.seen[3].Product, "[UI-4] Added by hand.") {
		t.Fatal("classification after the merge did not read the merged Folio")
	}
	merged := up.Change.Head
	up, err = f.h.Flush(ctx)
	if err != nil || !up.Pushed {
		t.Fatalf("%+v %v", up, err)
	}
	if got := parents(t, f.repo, up.Change.Head); len(got) != 1 || got[0] != string(merged) {
		t.Fatalf("parents after the merge: %v", got)
	}
	if files := git(t, f.repo, "diff", "--name-only", string(merged), string(up.Change.Head)); files != "folio/rulings/nit-20261127-0004.md" {
		t.Fatalf("PR after the merge changes:\n%s", files)
	}
}

func TestM2_3_DivergedFolioBranchKeepsTheTargetsTextOverAStaleEdit(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	f.classifier.decide = func(Nit) (Decision, error) {
		return Decision{Kind: KindIntent, Summary: "edit", Edits: []Edit{{Path: "PRODUCT.md", Content: productV1 + "branch text\n"}, {Path: "folio/notes.md", Content: "note\n"}}}, nil
	}
	f.owner(nitText("one"))
	up, err := f.h.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
	branch := up.Change.Head
	// The target rewrites PRODUCT.md too.
	writeFile(t, f.repo, "PRODUCT.md", productV1+"target text\n")
	git(t, f.repo, "commit", "-q", "-am", "product: target text")
	moved := forge.SHA(git(t, f.repo, "rev-parse", "HEAD"))
	f.forge.SetRef("main", moved)
	f.classifier.decide = nil
	f.owner(nitText("two"))
	up, err = f.h.Flush(ctx)
	if err != nil || !up.Pushed {
		t.Fatalf("%+v %v", up, err)
	}
	if got := parents(t, f.repo, up.Change.Head); len(got) != 2 || got[0] != string(branch) || got[1] != string(moved) {
		t.Fatalf("parents %v", got)
	}
	if got := git(t, f.repo, "show", string(up.Change.Head)+":PRODUCT.md") + "\n"; got != productV1+"target text\n" {
		t.Fatalf("PRODUCT.md:\n%s", got)
	}
	if len(up.Dropped) != 1 || up.Dropped[0] != "branch: PRODUCT.md" {
		t.Fatalf("dropped %v", up.Dropped)
	}
	if files := git(t, f.repo, "diff", "--name-only", string(moved), string(up.Change.Head)); files != "folio/notes.md\nfolio/rulings/nit-20261127-0001.md\nfolio/rulings/nit-20261127-0002.md" {
		t.Fatalf("PR changes:\n%s", files)
	}
}

func TestM2_3_BranchPRFetchesAndPublishesThroughItsHooks(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	var published []forge.SHA
	f.pr.Publish = func(_ context.Context, sha forge.SHA) error { published = append(published, sha); return nil }
	up, err := f.pr.Update(ctx, []Proposal{{ID: "a", Summary: "s", Files: []ProposalFile{{Path: "folio/a.md", Content: []byte("a\n")}}}})
	if err != nil || len(published) != 1 || published[0] != up.Change.Head {
		t.Fatalf("%+v %v published=%v", up, err, published)
	}
	// A failing publish stops before the compare-and-swap.
	f.pr.Publish = func(context.Context, forge.SHA) error { return errors.New("remote refused") }
	if _, err := f.pr.Update(ctx, []Proposal{{ID: "b", Summary: "s", Files: []ProposalFile{{Path: "folio/b.md", Content: []byte("b\n")}}}}); err == nil || f.pushes() != 1 {
		t.Fatalf("err=%v pushes=%d", err, f.pushes())
	}
	// A target commit this repository does not have is fetched, or refused.
	f.pr.Publish = nil
	missing := forge.SHA(strings.Repeat("ab", 20))
	f.forge.SetRef("main", missing)
	if _, err := f.pr.Update(ctx, []Proposal{{ID: "c", Files: []ProposalFile{{Path: "folio/c.md", Content: []byte("c\n")}}}}); err == nil || !strings.Contains(err.Error(), "not in the repository") {
		t.Fatalf("err=%v", err)
	}
	fetched := 0
	f.pr.Fetch = func(_ context.Context, sha forge.SHA) error {
		fetched++
		f.forge.SetRef("main", f.head)
		return nil
	}
	if _, err := f.pr.Update(ctx, []Proposal{{ID: "c", Files: []ProposalFile{{Path: "folio/c.md", Content: []byte("c\n")}}}}); err == nil || fetched != 1 {
		t.Fatalf("err=%v fetched=%d", err, fetched)
	}
	// An empty batch on an absent branch proposes nothing and opens nothing.
	g := newFixture(t, nil)
	if up, err := g.pr.Update(ctx, nil); err != nil || up.Pushed || len(g.forge.Pushes()) != 0 || len(g.forge.Notifications()) != 0 {
		t.Fatalf("%+v %v", up, err)
	}
	if _, err := (&BranchPR{}).Update(ctx, nil); err == nil {
		t.Fatal("an unconfigured BranchPR accepted an update")
	}
}

func TestM2_3_CommandClassifierRunsTheConfiguredCommand(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	script := filepath.Join(dir, "classify.sh")
	// Echoes what it was asked, so the test can see the request, then decides.
	body := "#!/bin/sh\ncat > \"" + filepath.Join(dir, "request.json") + "\"\n" +
		`printf '{"kind":"violation","clause":"DESIGN.md §2.2","brief":"Use the accent.","acceptance":["[UI-1]"],"summary":"accent"}'` + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHIMERA_S3_SECRET_ACCESS_KEY", "do-not-pass-on")
	t.Setenv("CHIMERA_FORGE_TOKEN", "do-not-pass-on")
	c := CommandClassifier{Argv: []string{"sh", script}, Timeout: 20 * time.Second}
	d, err := c.Classify(ctx, Nit{URL: "https://app.example.com/", Text: "wrong blue"}, FolioSnapshot{Product: "P", Design: "D"})
	if err != nil || d.Kind != KindViolation || d.Clause != "DESIGN.md §2.2" || d.Brief != "Use the accent." || d.Validate() != nil {
		t.Fatalf("%+v %v", d, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "request.json"))
	var req struct {
		Schema string
		Nit    Nit
		Folio  FolioSnapshot
	}
	if json.Unmarshal(raw, &req) != nil || req.Schema != "chimera.inlet.classify/v1" || req.Nit.Text != "wrong blue" || req.Folio.Product != "P" || req.Folio.Design != "D" {
		t.Fatalf("request %s", raw)
	}
	for name, argv := range map[string][]string{
		"exit 1":       {"sh", "-c", "cat >/dev/null; echo '{\"kind\":\"intent\"}'; exit 1"},
		"not json":     {"sh", "-c", "cat >/dev/null; echo sure, looks like a violation"},
		"no such file": {filepath.Join(dir, "missing")},
		"empty":        {},
		"env leak":     {"sh", "-c", "cat >/dev/null; test -z \"$CHIMERA_S3_SECRET_ACCESS_KEY$CHIMERA_FORGE_TOKEN\" && exit 3; echo '{\"kind\":\"intent\"}'"},
	} {
		if _, err := (CommandClassifier{Argv: argv, Timeout: 20 * time.Second}).Classify(ctx, Nit{}, FolioSnapshot{}); err == nil {
			t.Errorf("%s: no error", name)
		} else if strings.Contains(err.Error(), "looks like") || strings.Contains(err.Error(), "do-not-pass-on") {
			t.Errorf("%s: error repeats command output: %v", name, err)
		}
	}
	// A classifier that hangs is killed at its timeout, children included.
	start := time.Now()
	_, err = (CommandClassifier{Argv: []string{"sh", "-c", "sleep 30 & sleep 30"}, Timeout: 300 * time.Millisecond}).Classify(ctx, Nit{}, FolioSnapshot{})
	if err == nil || !strings.Contains(err.Error(), "timed out") || time.Since(start) > 10*time.Second {
		t.Fatalf("err=%v after %s", err, time.Since(start))
	}
	// End to end through the handler, with no injected classifier.
	f := newFixture(t, func(o *Options, d *Deps) {
		d.Classifier = nil
		o.ClassifierCommand, o.ClassifierTimeout = []string{"sh", script}, 20*time.Second
	})
	if r := f.owner(goodNit); r.Code != 201 || r.Status != StatusTask || r.Clause != "DESIGN.md §2.2" {
		t.Fatalf("%+v", r)
	}
}

func TestM2_3_StoreInboxAppendsWriteOnceEntries(t *testing.T) {
	ctx := context.Background()
	store := objstore.NewDir(filepath.Join(t.TempDir(), "store"))
	at := time.Date(2026, 11, 27, 23, 59, 0, 0, time.UTC)
	a, b := &StoreInbox{Store: store, Repo: testRepo}, &StoreInbox{Store: store, Repo: testRepo}
	raw := []byte("\x00\xffnot utf-8 \x80 {")
	for i, in := range []*StoreInbox{a, b, a, b} {
		if err := in.Append(ctx, Entry{ReceivedAt: at, Body: append(raw, byte('0'+i))}); err != nil {
			t.Fatal(err)
		}
	}
	// A later instance continues the day's sequence; a new day starts at 1.
	c := &StoreInbox{Store: store, Repo: testRepo}
	if err := c.Append(ctx, Entry{ReceivedAt: at, Owner: true, Reason: "classifier", Body: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := c.Append(ctx, Entry{ReceivedAt: at.Add(2 * time.Minute), Body: []byte("next day")}); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.List(ctx, "inlet/")
	want := []string{}
	for i := 1; i <= 5; i++ {
		want = append(want, TriageKey(testRepo, "2026-11-27", i))
	}
	want = append(want, TriageKey(testRepo, "2026-11-28", 1))
	if strings.Join(keys, "\n") != strings.Join(want, "\n") || want[0] != "inlet/acme/widget/triage/2026-11-27/000001.json" {
		t.Fatalf("keys:\n%s", strings.Join(keys, "\n"))
	}
	seen := map[string]bool{}
	for i := 1; i <= 4; i++ {
		data, _ := store.Get(ctx, TriageKey(testRepo, "2026-11-27", i))
		var e Entry
		if err := json.Unmarshal(data, &e); err != nil || e.Schema != EntrySchema || e.Owner || !e.ReceivedAt.Equal(at) || len(e.Body) != len(raw)+1 || string(e.Body[:len(raw)]) != string(raw) {
			t.Fatalf("entry %d: %+v %v", i, e, err)
		}
		seen[string(e.Body)] = true
	}
	if len(seen) != 4 {
		t.Fatalf("an entry was overwritten: %d distinct bodies", len(seen))
	}
	var kept Entry
	data, _ := store.Get(ctx, TriageKey(testRepo, "2026-11-27", 5))
	if json.Unmarshal(data, &kept) != nil || !kept.Owner || kept.Reason != "classifier" {
		t.Fatalf("%+v", kept)
	}
	// Concurrent appends never collide.
	d := &StoreInbox{Store: store, Repo: "acme/gadget"}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			in := d
			if i%3 == 0 {
				in = &StoreInbox{Store: store, Repo: "acme/gadget"}
			}
			if err := in.Append(ctx, Entry{ReceivedAt: at, Body: []byte{byte(i)}}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if keys, _ := store.List(ctx, "inlet/acme/gadget/triage/"); len(keys) != 24 {
		t.Fatalf("%d entries for 24 appends", len(keys))
	}
	// The handler's default inbox is the store.
	f := newFixture(t, func(_ *Options, dd *Deps) { dd.Inbox = nil })
	if r := f.post("anonymous", "", nil); r.Status != StatusTriage {
		t.Fatalf("%+v", r)
	}
	if keys := f.keysUnder("inlet/" + testRepo + "/triage/2026-11-27/"); len(keys) != 1 {
		t.Fatalf("%v", keys)
	}
}

func TestM2_3_JWKSKeepsOnlyUsableSignatureKeys(t *testing.T) {
	keys(t)
	set, err := ParseJWKS(testJWKS)
	if err != nil || set.Len() != 3 {
		t.Fatalf("%v %d", err, set.Len())
	}
	for name, raw := range map[string]string{
		"malformed":    `{`,
		"empty":        `{"keys":[]}`,
		"symmetric":    `{"keys":[{"kty":"oct","kid":"a","k":"AAAA"}]}`,
		"short rsa":    `{"keys":[{"kty":"RSA","kid":"a","n":"` + enc(make([]byte, 128)) + `","e":"AQAB"}]}`,
		"enc key":      `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"enc","x":"` + enc(edPub) + `"}]}`,
		"off curve":    `{"keys":[{"kty":"EC","crv":"P-256","x":"` + enc(make([]byte, 32)) + `","y":"` + enc(make([]byte, 32)) + `"}]}`,
		"other curve":  `{"keys":[{"kty":"EC","crv":"P-384","x":"AAAA","y":"AAAA"}]}`,
		"short ed key": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AAAA"}]}`,
	} {
		if _, err := ParseJWKS([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	now := newClock().Now()
	// A single-key set verifies a token that names no kid; a multi-key set does not guess.
	one, _ := ParseJWKS(testJWKSOnly)
	v := &Verifier{Issuer: testIssuer, Audience: testAudience, Keys: one, Now: func() time.Time { return now }}
	id, err := v.Verify(context.Background(), mint(t, "EdDSA", "", edKey, claims(now, map[string]any{"email": "Owner@Example.COM"})))
	if err != nil || id.Email != testOwner || id.Subject != "user-1" {
		t.Fatalf("%+v %v", id, err)
	}
	// exp is exclusive; nbf and iat get sixty seconds of leeway and no more.
	rs := func(over map[string]any) error {
		_, err := (&Verifier{Issuer: testIssuer, Audience: testAudience, Keys: set, Now: func() time.Time { return now }}).
			Verify(context.Background(), mint(t, "RS256", "rsa-1", rsaKey, claims(now, over)))
		return err
	}
	for name, c := range map[string]struct {
		over map[string]any
		ok   bool
	}{
		"exp now":         {map[string]any{"exp": now.Unix()}, false},
		"exp in 1s":       {map[string]any{"exp": now.Unix() + 1}, true},
		"nbf in 60s":      {map[string]any{"nbf": now.Unix() + 60}, true},
		"nbf in 61s":      {map[string]any{"nbf": now.Unix() + 61}, false},
		"iat in 61s":      {map[string]any{"iat": now.Unix() + 61}, false},
		"aud as list":     {map[string]any{"aud": []string{"x", testAudience}}, true},
		"aud list miss":   {map[string]any{"aud": []string{"x", "y"}}, false},
		"aud is a number": {map[string]any{"aud": 7}, false},
		"email no at":     {map[string]any{"email": "owner"}, false},
		"email padded":    {map[string]any{"email": " owner@example.com"}, false},
		"email non-ascii": {map[string]any{"email": "\u212Aim@example.com"}, false},
		"aud for another": {map[string]any{"aud": "some-other-relying-party"}, false},
		"no verified":     {map[string]any{"email_verified": nil}, false},
		"verified list":   {map[string]any{"email_verified": []any{}}, false},
		"verified string": {map[string]any{"email_verified": "false"}, false},
		"exp as string":   {map[string]any{"exp": "9999999999"}, false},
		"exp huge":        {map[string]any{"exp": 1e300}, false},
	} {
		if err := rs(c.over); (err == nil) != c.ok {
			t.Errorf("%s: err=%v", name, err)
		} else if err != nil && !errors.Is(err, ErrToken) {
			t.Errorf("%s: error %v is not ErrToken", name, err)
		}
	}
	if _, err := (&Verifier{Keys: set, Audience: testAudience}).Verify(context.Background(), ownerToken(t, now)); !errors.Is(err, ErrToken) {
		t.Fatal("a verifier without an issuer accepted a token")
	}
	// A verifier without an audience accepts nothing: a token minted for some
	// other relying party of the same issuer must never make an owner.
	if _, err := (&Verifier{Issuer: testIssuer, Keys: set, Now: func() time.Time { return now }}).Verify(context.Background(), ownerToken(t, now)); !errors.Is(err, ErrToken) {
		t.Fatal("a verifier without an audience accepted a token")
	}
}

func TestM2_3_OriginPatternsMatchExactly(t *testing.T) {
	// Preview patterns: a scheme, a host that may use wildcards, an optional port.
	for _, c := range []struct {
		pattern, origin string
		want            bool
	}{
		{"https://*.preview.example.com", "https://pr-1.preview.example.com", true},
		{"https://*.preview.example.com", "https://pr-1.preview.example.com/path?q=1", true},
		{"https://*.preview.example.com", "https://a.preview.example.com.", true},
		{"https://*.preview.example.com", "https://preview.example.com", false},
		{"https://*.preview.example.com", "https://pr-1.preview.example.com.evil.example", false},
		{"https://*.preview.example.com", "http://pr-1.preview.example.com", false},
		{"https://*.preview.example.com", "https://x.preview.example.com@evil.example", false},
		{"https://*.preview.example.com", "https://evil.example/.preview.example.com", false},
		{"https://*.preview.example.com", "https://evil.example#.preview.example.com", false},
		{"https://preview.example.com", "https://preview.example.com:443", true},
		{"https://preview.example.com/", "https://preview.example.com", true},
		{"https://preview.example.com:8443", "https://preview.example.com", false},
		{"https://preview.example.com:8443", "https://preview.example.com:8443", true},
		{"https://pr-*-app.example.com", "https://pr-12-app.example.com", true},
		{"https://pr-*-app.example.com", "https://pr-12-api.example.com", false},
		{"http://[::1]:3000", "http://[::1]:3000", true},
		{"http://[::1]", "http://[::1]", true},
		{"http://[::1]:3000", "http://[::1]:3001", false},
		{"https://app.example.com", "not a url", false},
		{"https://app.example.com", "", false},
	} {
		p, err := parsePreviewPattern(c.pattern)
		if err != nil {
			t.Errorf("parsePreviewPattern(%q): %v", c.pattern, err)
			continue
		}
		if got := matchPreview([]previewPattern{p}, c.origin); got != c.want {
			t.Errorf("preview %q vs %q = %v", c.pattern, c.origin, got)
		}
	}
	for _, bad := range []string{"", "pr-*.example.com", "*", "https://", "https://preview.example.com/app", "https://*.example.com:*", "ftp://preview.example.com",
		"https://[::1", "https://a.example.com?x=1", "https://user@preview.example.com"} {
		if _, err := parsePreviewPattern(bad); err == nil {
			t.Errorf("parsePreviewPattern(%q) accepted", bad)
		}
	}
	// Allowed origins are exact: scheme, host, and effective port.
	allowed, err := parseAllowedOrigin("https://App.Example.com")
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]bool{
		"https://app.example.com": true, "https://app.example.com:443": true, "HTTPS://APP.example.com": true,
		"https://app.example.com:8443": false, "http://app.example.com": false, "https://app.example.com.evil.example": false,
		"https://sub.app.example.com": false, "null": false, "": false,
	} {
		o, ok := parseOrigin(raw)
		if got := ok && o == allowed; got != want {
			t.Errorf("allowed https://app.example.com vs %q = %v", raw, got)
		}
	}
	for _, bad := range []string{"*", "https://*.example.com", "app.example.com", "https://app.example.com/app", "https://app.example.com?x", "ftp://app.example.com", "https://u@app.example.com"} {
		if _, err := parseAllowedOrigin(bad); err == nil {
			t.Errorf("parseAllowedOrigin(%q) accepted", bad)
		}
	}
	// Same-origin: the Origin names the host the request was sent to.
	for _, c := range []struct {
		origin, host string
		want         bool
	}{
		{"https://app.example.com", "app.example.com", true},
		{"https://app.example.com", "APP.example.com:443", true},
		{"http://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"http://[::1]:8787", "[::1]:8787", true},
		{"http://127.0.0.1:8787", "127.0.0.1:8788", false},
		{"https://app.example.com", "app.example.com:8443", false},
		{"https://evil.example", "app.example.com", false},
		{"https://app.example.com", "", false},
	} {
		o, _ := parseOrigin(c.origin)
		if got := sameOrigin(o, c.host); got != c.want {
			t.Errorf("sameOrigin(%q, %q) = %v", c.origin, c.host, got)
		}
	}
	if !isBot(nil, "deploy[bot]") || !isBot([]string{"CI@example.com"}, "ci@example.com") || isBot([]string{"ci@example.com"}, "owner@example.com") || isBot(nil, "") {
		t.Error("isBot")
	}
}
