package inlet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/config"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// TestM2_3_CrossSiteRequestWithTheOwnersSessionIsNeverAnOwnerNit: a browser
// attaches the owner's edge session to any request for the inlet, whoever
// wrote the page. A page on another site must not be able to spend it.
func TestM2_3_CrossSiteRequestWithTheOwnersSessionIsNeverAnOwnerNit(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) {
		o.TokenCookie = "edge_session"
		o.AllowedOrigins = []string{"https://app.example.com"}
	})
	tok := ownerToken(t, f.clock.Now())
	session := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "edge_session", Value: tok}) }
	attacks := map[string]struct {
		edit func(*http.Request)
		code int
		want string
	}{
		// The classic: a "simple" request needs no preflight.
		"text/plain form post": {func(r *http.Request) {
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Content-Type", "text/plain;charset=UTF-8")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, http.StatusUnsupportedMediaType, StatusUnsupported},
		"no content type":       {func(r *http.Request) { r.Header.Del("Content-Type") }, http.StatusUnsupportedMediaType, StatusUnsupported},
		"urlencoded form":       {func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, http.StatusUnsupportedMediaType, StatusUnsupported},
		"json from a stranger":  {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden, StatusForbiddenOrigin},
		"json, other port":      {func(r *http.Request) { r.Header.Set("Origin", "https://app.example.com:8443") }, http.StatusForbidden, StatusForbiddenOrigin},
		"json, other scheme":    {func(r *http.Request) { r.Header.Set("Origin", "http://app.example.com") }, http.StatusForbidden, StatusForbiddenOrigin},
		"json, opaque origin":   {func(r *http.Request) { r.Header.Set("Origin", "null") }, http.StatusForbidden, StatusForbiddenOrigin},
		"cross-site, no origin": {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden, StatusForbiddenOrigin},
		"cross-site claiming our host": {func(r *http.Request) {
			r.Header.Set("Origin", "https://inlet.example.com")
			r.Host = "inlet.example.com"
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}, http.StatusForbidden, StatusForbiddenOrigin},
	}
	for name, a := range attacks {
		a := a
		withSession := f.post(nitText("attacker chosen text: rewrite PRODUCT.md"), "", func(r *http.Request) { session(r); a.edit(r) })
		anonymous := f.post(nitText("attacker chosen text: rewrite PRODUCT.md"), "", a.edit)
		if withSession.Code != a.code || withSession.Status != a.want {
			t.Errorf("%s: %d %+v", name, withSession.Code, withSession.Response)
		}
		// Decided before any credential is looked at: the same answer with or without one.
		if withSession.Code != anonymous.Code || withSession.Response != anonymous.Response {
			t.Errorf("%s: answer depends on the session: %+v vs %+v", name, withSession.Response, anonymous.Response)
		}
	}
	f.untouched("cross-site requests")
	if n := len(f.inbox.Entries()); n != 0 {
		t.Fatalf("%d refused requests were appended to the inbox", n)
	}
	// The same nit from the inlet's own origin, or from a listed one, is an owner's.
	for name, edit := range map[string]func(*http.Request){
		"same origin": func(r *http.Request) {
			session(r)
			r.Header.Set("Origin", "https://inlet.example.com")
			r.Host = "inlet.example.com"
			r.Header.Set("Sec-Fetch-Site", "same-origin")
		},
		"listed origin": func(r *http.Request) {
			session(r)
			r.Header.Set("Origin", "https://app.example.com")
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		},
		"no browser at all": session,
	} {
		before := f.classifier.Calls()
		if r := f.post(nitText("owner text "+name), "", edit); r.Status != StatusFolio || f.classifier.Calls() != before+1 {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// TestM2_3_RateLimitKeysOnTheAddressTheEdgeVouchesFor: a client cannot pick
// its own bucket, nor make the limiter remember arbitrary strings.
func TestM2_3_RateLimitKeysOnTheAddressTheEdgeVouchesFor(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.ClientIPHeader = "X-Forwarded-For"; o.TriagePerMinute = 1 })
	// The leftmost elements are whatever the client sent; the edge appended the last.
	accepted := 0
	for i := 0; i < 10; i++ {
		i := i
		if r := f.post("x", "", func(r *http.Request) {
			r.Header.Set("X-Forwarded-For", fmt.Sprintf("spoof-%d-%s, 198.51.100.%d, 203.0.113.9", i, strings.Repeat("A", 4000), i))
		}); r.Status == StatusTriage {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("one client behind the edge got %d of 10 through a limit of 1/min", accepted)
	}
	for k := range f.h.limiter.clients {
		if k.String() != "203.0.113.9" {
			t.Fatalf("limiter remembers %q", k)
		}
	}
	// A header that is not an address falls back to the connection.
	g := newFixture(t, func(o *Options, _ *Deps) { o.ClientIPHeader = "X-Client"; o.TriagePerMinute = 1 })
	junk := func(r *http.Request) { r.Header.Set("X-Client", "not-an-address"); r.RemoteAddr = "192.0.2.50:9" }
	if a, b := g.post("x", "", junk), g.post("x", "", junk); a.Status != StatusTriage || b.Status != StatusRateLimited {
		t.Fatalf("fallback: %s then %s", a.Status, b.Status)
	}
	// One IPv6 /64 is one client; another /64 is another.
	v6 := func(addr string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = addr } }
	h := newFixture(t, func(o *Options, _ *Deps) { o.TriagePerMinute = 1 })
	if a, b, c := h.post("x", "", v6("[2001:db8:1:2::1]:1")), h.post("x", "", v6("[2001:db8:1:2:ffff::9]:1")), h.post("x", "", v6("[2001:db8:1:3::1]:1")); a.Status != StatusTriage || b.Status != StatusRateLimited || c.Status != StatusTriage {
		t.Fatalf("ipv6: %s %s %s", a.Status, b.Status, c.Status)
	}
	// IPv4-mapped IPv6 is the IPv4 client.
	if r := h.post("x", "", v6("[::ffff:192.0.2.60]:1")); r.Status != StatusTriage {
		t.Fatal(r.Status)
	}
	if r := h.post("x", "", v6("192.0.2.60:2")); r.Status != StatusRateLimited {
		t.Fatal(r.Status)
	}
	// Memory is bounded: past the cap new clients share one bucket; a client
	// already tracked keeps its own; nobody is refused merely for being new.
	l := newLimiter(2)
	now := newClock().Now()
	known := parseAddr("192.0.2.1")
	l.allow(known, now)
	for i := 0; len(l.clients) < maxClients; i++ {
		l.clients[parseAddr(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))] = &bucket{tokens: 2, seen: now}
	}
	l.global = bucket{tokens: 1000, seen: now}
	if !l.allow(parseAddr("198.51.100.1"), now) || !l.allow(parseAddr("198.51.100.2"), now) || l.allow(parseAddr("198.51.100.3"), now) {
		t.Fatal("overflow bucket: want two newcomers through, the third slowed")
	}
	if len(l.clients) != maxClients || !l.allow(known, now) {
		t.Fatalf("limiter grew to %d or forgot a tracked client", len(l.clients))
	}
	// Idle clients are forgotten when room is needed.
	later := now.Add(2 * time.Minute)
	l.global = bucket{tokens: 1000, seen: later}
	if !l.allow(parseAddr("198.51.100.4"), later) || len(l.clients) != 1 {
		t.Fatalf("idle clients not evicted: %d tracked", len(l.clients))
	}
	// A flood the global bucket already refuses does not even create entries.
	m := newLimiter(1)
	for i := 0; i < 10; i++ {
		m.allow(parseAddr(fmt.Sprintf("203.0.113.%d", i)), now)
	}
	tracked := len(m.clients)
	for i := 10; i < 200; i++ {
		if m.allow(parseAddr(fmt.Sprintf("203.0.113.%d", i)), now) {
			t.Fatal("global bucket let an eleventh client through")
		}
	}
	if len(m.clients) != tracked {
		t.Fatalf("refused flood grew the limiter from %d to %d entries", tracked, len(m.clients))
	}
}

// TestM2_3_NonOwnerIsRateLimitedBeforeItsBodyIsRead: the limiter answers
// from headers; a refused request's body is never consumed.
func TestM2_3_NonOwnerIsRateLimitedBeforeItsBodyIsRead(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.TriagePerMinute = 1 })
	if r := f.post("x", "", nil); r.Status != StatusTriage {
		t.Fatal(r.Status)
	}
	body := &countingBody{}
	req, _ := http.NewRequest(http.MethodPost, Path, body)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:40001"
	rec := newRecorder()
	f.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || body.read.Load() != 0 {
		t.Fatalf("code %d, %d bytes of a refused body were read", rec.Code, body.read.Load())
	}
}

// TestM2_3_AcceptedProposalsSurviveARestart: 202 means durable. A handler
// built later on the same store pushes what an earlier one accepted.
func TestM2_3_AcceptedProposalsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	f.classifier.decide = func(Nit) (Decision, error) {
		return Decision{Kind: KindIntent, Summary: "kept across a restart", Edits: []Edit{{Path: "folio/notes/restart.md", Content: "kept\n"}}}, nil
	}
	if r := f.owner(nitText("first")); r.Status != StatusFolio {
		t.Fatalf("%+v", r)
	}
	f.classifier.decide = nil
	if r := f.owner(nitText("second")); r.Status != StatusFolio {
		t.Fatalf("%+v", r)
	}
	if got := f.keysUnder("inlet/" + testRepo + "/pending/"); len(got) != 2 || got[0] != PendingKey(testRepo, "20261127-0001") {
		t.Fatalf("pending keys %v", got)
	}
	// The process dies inside the debounce window: nothing was pushed.
	f.h.Close()
	if f.pushes() != 0 {
		t.Fatal("pushed before the window")
	}
	restart := func() *Handler {
		h, err := New(f.opts, Deps{Store: f.store, Forge: f.forge, Classifier: f.classifier, Inbox: f.inbox, FolioPR: f.pr, Now: f.clock.Now,
			AfterFunc: func(time.Duration, func()) func() { return func() {} }})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(h.Close)
		return h
	}
	h2 := restart()
	if h2.Pending() != 2 {
		t.Fatalf("a new handler queued %d of 2 accepted proposals", h2.Pending())
	}
	// The window is armed again on reload: it elapses one window after the restart.
	if flushed, _ := h2.Tick(ctx, f.clock.Now().Add(DefaultDebounce-time.Second)); flushed {
		t.Fatal("flushed before the reloaded window elapsed")
	}
	if flushed, err := h2.Tick(ctx, f.clock.Now().Add(DefaultDebounce)); !flushed || err != nil {
		t.Fatalf("reloaded window: %v %v", flushed, err)
	}
	head := f.forge.Refs()["refs/heads/chimera/folio"]
	files := git(t, f.repo, "diff", "--name-only", string(f.head), string(head))
	if files != "folio/notes/restart.md\nfolio/rulings/nit-20261127-0001.md\nfolio/rulings/nit-20261127-0002.md" {
		t.Fatalf("pushed after the restart:\n%s", files)
	}
	flushed := f.keysUnder("inlet/" + testRepo + "/flushed/")
	if len(flushed) != 2 {
		t.Fatalf("flushed markers %v", flushed)
	}
	raw, _ := f.store.Get(ctx, FlushedKey(testRepo, "20261127-0001"))
	var rec flushedRecord
	if json.Unmarshal(raw, &rec) != nil || rec.State != "pushed" || rec.Head != string(head) || !strings.HasPrefix(rec.Capsule, "sha256:") {
		t.Fatalf("flushed record %s", raw)
	}
	// A third start has nothing left to queue, and pushes nothing.
	h3 := restart()
	if h3.Pending() != 0 {
		t.Fatalf("settled proposals were queued again: %d", h3.Pending())
	}
	if _, err := h3.Flush(ctx); err != nil || f.pushes() != 1 {
		t.Fatalf("err=%v pushes=%d", err, f.pushes())
	}
}

// TestM2_3_OnePoisonProposalNeverHoldsTheOthersBack: a proposal that can
// never be staged is refused, recorded, and kept in the triage inbox; the
// rest of the batch lands in the same update.
func TestM2_3_OnePoisonProposalNeverHoldsTheOthersBack(t *testing.T) {
	ctx := context.Background()
	for name, edits := range map[string][]Edit{
		"a file where a directory is": {{Path: "folio/assets", Content: "x"}},
		"a file below a file":         {{Path: "folio/assets/mark.svg/x", Content: "x"}},
		"a directory below PRODUCT":   {{Path: "folio/ok.md", Content: "ok\n"}, {Path: "folio/rulings", Content: "x"}},
	} {
		f := newFixture(t, nil)
		edits := edits
		f.classifier.decide = func(Nit) (Decision, error) { return Decision{Kind: KindIntent, Summary: "poison", Edits: edits}, nil }
		if r := f.owner(nitText("poison")); r.Status != StatusFolio {
			t.Fatalf("%s: %+v", name, r)
		}
		f.classifier.decide = nil
		if r := f.owner(nitText("good nit after")); r.Status != StatusFolio {
			t.Fatalf("%s: %+v", name, r)
		}
		up, err := f.h.Flush(ctx)
		if err != nil || !up.Pushed || len(up.Refused) != 1 || up.Refused[0].ID != "20261127-0001" || up.Refused[0].Reason != "path-conflict" {
			t.Fatalf("%s: %+v err=%v", name, up, err)
		}
		if f.h.Pending() != 0 || f.pushes() != 1 {
			t.Fatalf("%s: pending=%d pushes=%d", name, f.h.Pending(), f.pushes())
		}
		files := git(t, f.repo, "diff", "--name-only", string(f.head), string(up.Change.Head))
		if files != "folio/rulings/nit-20261127-0002.md" {
			t.Fatalf("%s: pushed:\n%s", name, files)
		}
		// What the owner said is in the triage inbox, with the reason.
		kept := f.inbox.Entries()
		var nit Nit
		if len(kept) != 1 || !kept[0].Owner || kept[0].Reason != "path-conflict" || json.Unmarshal(kept[0].Body, &nit) != nil || nit.Text != "poison" {
			t.Fatalf("%s: inbox %+v", name, kept)
		}
		raw, _ := f.store.Get(ctx, FlushedKey(testRepo, "20261127-0001"))
		if !strings.Contains(string(raw), `"state":"refused"`) || !strings.Contains(string(raw), `"reason":"path-conflict"`) {
			t.Fatalf("%s: record %s", name, raw)
		}
		// Later windows are not poisoned either.
		f.owner(nitText("another good nit"))
		if up, err := f.h.Flush(ctx); err != nil || !up.Pushed || len(up.Refused) != 0 {
			t.Fatalf("%s: next window: %+v %v", name, up, err)
		}
	}
	// A transient failure is different: the whole batch waits for the next window.
	f := newFixture(t, nil)
	f.owner(nitText("one"))
	f.forge.FailNext("Head", forge.ErrUnavailable)
	if _, err := f.h.Flush(ctx); err == nil || f.h.Pending() != 1 || len(f.keysUnder("inlet/"+testRepo+"/flushed/")) != 0 {
		t.Fatalf("transient failure: err=%v pending=%d", err, f.h.Pending())
	}
	if up, err := f.h.Flush(ctx); err != nil || !up.Pushed {
		t.Fatalf("retry: %+v %v", up, err)
	}
}

// TestM2_3_FolioCommitsCarryBothTrailersAndAVerifiableCapsule: every commit
// the inlet authors binds to its evidence (PRODUCT.md §1).
func TestM2_3_FolioCommitsCarryBothTrailersAndAVerifiableCapsule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, nil)
	f.classifier.decide = func(n Nit) (Decision, error) {
		return Decision{Kind: KindIntent, Summary: "summary of " + n.Text, Edits: []Edit{{Path: "folio/assets/notes.md", Content: n.Text + "\n"}}}, nil
	}
	f.owner(nitText("one"))
	f.owner(nitText("two"))
	up, err := f.h.Flush(ctx)
	if err != nil || !up.Pushed {
		t.Fatalf("%+v %v", up, err)
	}
	check := func(commit forge.SHA, diffBase string, nits ...string) {
		t.Helper()
		trailers, err := gitx.CommitTrailers(ctx, f.repo, string(commit))
		if err != nil || len(trailers) != 2 || trailers[0].Key != gitx.TrailerIntent || trailers[1].Key != gitx.TrailerCapsule {
			t.Fatalf("trailers of %s: %+v %v", commit.Short(), trailers, err)
		}
		// The Intent is the Folio of the commit's own tree.
		want, err := gitx.FolioIntent(ctx, f.repo, string(commit))
		if err != nil || trailers[0].Value != want {
			t.Fatalf("intent %q, the commit's Folio is %q (%v)", trailers[0].Value, want, err)
		}
		addr, err := capsule.ParseAddress(trailers[1].Value)
		if err != nil {
			t.Fatal(err)
		}
		// The Capsule was in the store before the commit existed, and verifies.
		c, err := capsule.Get(ctx, f.store, addr)
		if err != nil {
			t.Fatalf("capsule %s: %v", addr, err)
		}
		if c.Manifest.Intent != want || c.Manifest.Repo != testRepo || c.Manifest.BaseSHA != diffBase || !capsule.ValidCheckpoint(c.Manifest.Checkpoint) || c.Manifest.Lane.Harness != "inlet" {
			t.Fatalf("manifest %+v", c.Manifest)
		}
		verdicts, err := c.Verdicts()
		if err != nil || len(verdicts) != 1 || verdicts[0].ID != "fence" || !verdicts[0].Pass || !strings.HasPrefix(verdicts[0].Evidence, "transcript:") {
			t.Fatalf("verdicts %+v %v", verdicts, err)
		}
		transcript, err := capsule.Unzstd(c.Members[capsule.MemberTranscript])
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range nits {
			if !strings.Contains(string(transcript), "nit-"+n) {
				t.Errorf("transcript lacks nit-%s:\n%s", n, transcript)
			}
		}
		if strings.Contains(strings.ToLower(string(transcript)), testOwner) {
			t.Error("transcript names the owner")
		}
		// diff.patch is the commit's change against its diff base, and touches the Folio only.
		for _, touched := range capsule.TouchedPaths(c.Members[capsule.MemberDiff]) {
			if !InFence(touched.Path) {
				t.Errorf("capsule diff touches %q", touched.Path)
			}
		}
		gitDiff := git(t, f.repo, "diff", "--name-only", diffBase, string(commit))
		var paths []string
		for _, touched := range capsule.TouchedPaths(c.Members[capsule.MemberDiff]) {
			paths = append(paths, touched.Path)
		}
		if strings.Join(paths, "\n") != gitDiff {
			t.Errorf("capsule diff paths %v, git says:\n%s", paths, gitDiff)
		}
	}
	first := up.Change.Head
	check(first, string(f.head), "20261127-0001", "20261127-0002")
	if up.Capsule == "" || !strings.Contains(git(t, f.repo, "log", "-1", "--format=%B", string(first)), "Chimera-Capsule: "+up.Capsule) {
		t.Fatalf("Update.Capsule %q is not what the commit cites", up.Capsule)
	}
	// The next commit on the branch cites its own Capsule against its parent.
	f.owner(nitText("three"))
	up, err = f.h.Flush(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check(up.Change.Head, string(first), "20261127-0003")
	// A merge of a moved target cites a Capsule whose diff is what the pull
	// request proposes against that target.
	writeFile(t, f.repo, "cmd/chimera/main.go", "package main\n\nfunc main() { println(2) }\n")
	git(t, f.repo, "commit", "-q", "-am", "main moves")
	moved := forge.SHA(git(t, f.repo, "rev-parse", "HEAD"))
	f.forge.SetRef("main", moved)
	f.owner(nitText("four"))
	up, err = f.h.Flush(ctx)
	if err != nil || len(parents(t, f.repo, up.Change.Head)) != 2 {
		t.Fatalf("%+v %v", up, err)
	}
	check(up.Change.Head, string(moved), "20261127-0004")

	// No store, no commit: a Folio commit without a Capsule is never pushed.
	g := newFixture(t, nil)
	g.pr.Store = nil
	if _, err := g.pr.Update(ctx, []Proposal{{ID: "a", Summary: "s", Files: []ProposalFile{{Path: "folio/a.md", Content: []byte("a\n")}}}}); err == nil || len(g.forge.Pushes()) != 0 {
		t.Fatalf("err=%v pushes=%d", err, len(g.forge.Pushes()))
	}
	// A store that is down fails the update before anything is pushed.
	g.pr.Store = downStore{}
	if _, err := g.pr.Update(ctx, []Proposal{{ID: "a", Summary: "s", Files: []ProposalFile{{Path: "folio/a.md", Content: []byte("a\n")}}}}); err == nil || !errors.Is(err, objstore.ErrUnavailable) || len(g.forge.Pushes()) != 0 {
		t.Fatalf("err=%v pushes=%d", err, len(g.forge.Pushes()))
	}
}

// TestM2_3_SecretGateRefusesWhatIsBoundForGit: an owner's words go into a
// public Folio; a secret or a tenant term in them stops at the gate, and the
// finding names a place and a rule, never the value.
func TestM2_3_SecretGateRefusesWhatIsBoundForGit(t *testing.T) {
	ctx := context.Background()
	secret := fakeSecret()
	value := secret[strings.LastIndexByte(secret, ' ')+1:]
	// At the door: the owner is told at once and nothing is queued.
	f := newFixture(t, nil)
	if r := f.owner(nitText("please rotate this: " + secret)); r.Status != StatusTriage || r.Reason != "secret-gate" || f.h.Pending() != 0 {
		t.Fatalf("%+v pending=%d", r, f.h.Pending())
	}
	if len(f.keysUnder("inlet/"+testRepo+"/pending/")) != 0 {
		t.Fatal("a gated proposal was persisted as pending")
	}
	// A tenant term configured by the host is caught the same way.
	term := "acme-internal-codename"
	gate := secretscan.New([]secretscan.Term{{Value: term, Rule: secretscan.RuleTenantTerm}})
	h := newFixture(t, func(_ *Options, d *Deps) { d.Gate = gate })
	h.classifier.decide = func(Nit) (Decision, error) {
		return Decision{Kind: KindIntent, Summary: "s", Edits: []Edit{{Path: "DESIGN.md", Content: designV1 + "Use the " + strings.ToUpper(term) + " palette.\n"}}}, nil
	}
	if r := h.owner(nitText("fine text")); r.Status != StatusTriage || r.Reason != "secret-gate" {
		t.Fatalf("tenant term: %+v", r)
	}
	// At the pull request, whoever calls it: the offending proposal is
	// refused, the clean one lands, and nothing of the value is repeated.
	g := newFixture(t, nil)
	up, err := g.pr.Update(ctx, []Proposal{
		{ID: "a", Summary: "clean", Files: []ProposalFile{{Path: "folio/a.md", Content: []byte("a\n")}}},
		{ID: "b", Summary: "leaky", Files: []ProposalFile{{Path: "folio/b.md", Content: []byte("line one\n" + secret + "\n")}}},
	})
	if err != nil || !up.Pushed || len(up.Refused) != 1 || up.Refused[0].ID != "b" || up.Refused[0].Reason != "secret-gate" {
		t.Fatalf("%+v %v", up, err)
	}
	if d := up.Refused[0].Detail; !strings.Contains(d, "folio/b.md:2:") || !strings.Contains(d, secretscan.RuleAssignedSecret) || strings.Contains(d, value) {
		t.Fatalf("refusal detail %q", d)
	}
	if files := git(t, g.repo, "diff", "--name-only", string(g.head), string(up.Change.Head)); files != "folio/a.md" {
		t.Fatalf("pushed:\n%s", files)
	}
	// Carried content nobody proposed (someone put a secret on the branch by
	// hand) fails the update closed at the Capsule's gate.
	git(t, g.repo, "checkout", "-q", "-b", "side", string(up.Change.Head))
	writeFile(t, g.repo, "folio/by-hand.md", secret+"\n")
	git(t, g.repo, "add", "-A")
	git(t, g.repo, "commit", "-q", "-m", "folio: by hand")
	g.forge.SetRef("chimera/folio", forge.SHA(git(t, g.repo, "rev-parse", "HEAD")))
	git(t, g.repo, "checkout", "-q", "main")
	writeFile(t, g.repo, "go.mod", "module widget\n\ngo 1.23\n")
	git(t, g.repo, "commit", "-q", "-am", "main moves")
	g.forge.SetRef("main", forge.SHA(git(t, g.repo, "rev-parse", "HEAD")))
	pushes := g.pushes()
	_, err = g.pr.Update(ctx, []Proposal{{ID: "c", Summary: "clean", Files: []ProposalFile{{Path: "folio/c.md", Content: []byte("c\n")}}}})
	if err == nil || !strings.Contains(err.Error(), "secret gate") || !strings.Contains(err.Error(), "diff.patch:") || strings.Contains(err.Error(), value) || g.pushes() != pushes {
		t.Fatalf("carried secret: err=%v pushes=%d", err, g.pushes()-pushes)
	}
}

// TestM2_3_FolioBranchMayOnlyHoldPlainFilesAndIsNeverItsOwnTarget.
func TestM2_3_FolioBranchMayOnlyHoldPlainFilesAndIsNeverItsOwnTarget(t *testing.T) {
	ctx := context.Background()
	one := []Proposal{{ID: "y", Summary: "s", Files: []ProposalFile{{Path: "folio/ok.md", Content: []byte("ok\n")}}}}
	for name, taint := range map[string]func(repo string){
		"symlink": func(repo string) {
			if err := os.Symlink("../../../../etc/hostname", filepath.Join(repo, "folio", "assets", "link")); err != nil {
				t.Fatal(err)
			}
		},
		"executable": func(repo string) {
			writeFile(t, repo, "folio/run.sh", "#!/bin/sh\n")
			if err := os.Chmod(filepath.Join(repo, "folio", "run.sh"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"mode change only": func(repo string) {
			if err := os.Chmod(filepath.Join(repo, "PRODUCT.md"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
	} {
		g := newFixture(t, nil)
		git(t, g.repo, "checkout", "-q", "-b", "side")
		taint(g.repo)
		git(t, g.repo, "add", "-A")
		git(t, g.repo, "commit", "-q", "-m", "taint")
		g.forge.SetRef("chimera/folio", forge.SHA(git(t, g.repo, "rev-parse", "HEAD")))
		git(t, g.repo, "checkout", "-q", "main")
		up, err := g.pr.Update(ctx, one)
		if err == nil || !strings.Contains(err.Error(), "not a plain file") || up.Pushed || len(g.forge.Pushes()) != 0 {
			t.Errorf("%s on the branch: %+v err=%v", name, up, err)
		}
	}
	// The pull request's branch is never the branch it proposes to change.
	g := newFixture(t, nil)
	for _, branch := range []string{"main", "refs/heads/main"} {
		g.pr.Branch = branch
		if _, err := g.pr.Update(ctx, []Proposal{{ID: "y", Summary: "s", Files: []ProposalFile{{Path: "PRODUCT.md", Content: []byte("rewritten\n")}}}}); err == nil || g.forge.Refs()["refs/heads/main"] != g.head {
			t.Fatalf("branch %q: err=%v, main moved=%v", branch, err, g.forge.Refs()["refs/heads/main"] != g.head)
		}
	}
	// A name is never a pattern: with no glob in the fence, a proposal cannot
	// be mistaken for a file that is already there.
	if InFence("folio/assets/*") {
		t.Fatal("a glob is in the fence")
	}
}

// TestM2_3_OwnerNitIsKeptWhenTheOwnerHangsUp: a disconnect during
// classification loses nothing.
func TestM2_3_OwnerNitIsKeptWhenTheOwnerHangsUp(t *testing.T) {
	f := newFixture(t, func(_ *Options, d *Deps) { d.Inbox = nil })
	ctx, cancel := context.WithCancel(context.Background())
	f.classifier.decide = func(Nit) (Decision, error) { cancel(); return Decision{}, ctx.Err() }
	r := f.post(goodNit, ownerToken(t, f.clock.Now()), func(r *http.Request) { *r = *r.WithContext(ctx) })
	if r.Status != StatusTriage || r.Reason != "classifier" {
		t.Fatalf("%+v", r)
	}
	if kept := f.keysUnder("inlet/" + testRepo + "/triage/"); len(kept) != 1 {
		t.Fatalf("triage keys %v", kept)
	}
	nits := f.keysUnder("inlet/" + testRepo + "/nits/")
	if len(nits) != 2 || !strings.HasSuffix(nits[0], "0001.decision.json") || !strings.HasSuffix(nits[1], "0001.json") {
		t.Fatalf("slot and decision: %v", nits)
	}
}

// TestM2_3_DebounceWindowFlushesOnTheRealTimer: the path production uses.
func TestM2_3_DebounceWindowFlushesOnTheRealTimer(t *testing.T) {
	f := newFixture(t, func(o *Options, d *Deps) { o.Debounce = 150 * time.Millisecond; o.DailyCap = 100; d.AfterFunc = nil })
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r := f.owner(nitText(fmt.Sprintf("timer nit %d", i))); r.Status != StatusFolio {
				t.Errorf("%+v", r)
			}
		}(i)
	}
	wg.Wait()
	deadline := time.Now().Add(20 * time.Second)
	for (f.h.Pending() != 0 || f.pushes() == 0 || len(f.forge.Notifications()) == 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	head := f.forge.Refs()["refs/heads/chimera/folio"]
	if head.IsZero() || f.h.Pending() != 0 {
		t.Fatalf("the timer never flushed: pending=%d", f.h.Pending())
	}
	// All six arrived inside one window: one update carries them all.
	rulings := strings.Split(git(t, f.repo, "ls-tree", "-r", "--name-only", string(head), "folio/rulings"), "\n")
	if len(rulings) != 6 || f.pushes() != 1 {
		t.Fatalf("%d rulings in %d pushes", len(rulings), f.pushes())
	}
	// Close stops a window that is armed: nothing fires afterwards.
	f.owner(nitText("armed, then closed"))
	f.h.Close()
	time.Sleep(400 * time.Millisecond)
	if f.pushes() != 1 || f.h.Pending() != 1 {
		t.Fatalf("a closed handler flushed: pushes=%d pending=%d", f.pushes(), f.h.Pending())
	}
}

// TestM2_3_InboxFindsItsPlaceWithoutProbing: an instance that fell behind
// asks once where the day stands instead of sending the body again and again.
func TestM2_3_InboxFindsItsPlaceWithoutProbing(t *testing.T) {
	ctx := context.Background()
	base := objstore.NewDir(t.TempDir())
	counted := &countingStore{Store: base}
	at := time.Date(2026, 11, 27, 1, 0, 0, 0, time.UTC)
	a, b := &StoreInbox{Store: base, Repo: testRepo}, &StoreInbox{Store: counted, Repo: testRepo}
	if err := b.Append(ctx, Entry{ReceivedAt: at, Body: []byte("b0")}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if err := a.Append(ctx, Entry{ReceivedAt: at, Body: []byte("a")}); err != nil {
			t.Fatal(err)
		}
	}
	counted.puts.Store(0)
	if err := b.Append(ctx, Entry{ReceivedAt: at, Body: make([]byte, MaxBody)}); err != nil {
		t.Fatal(err)
	}
	if n := counted.puts.Load(); n > 2 {
		t.Fatalf("one append on an instance 300 entries behind cost %d PUTs of the body", n)
	}
	if keys, _ := base.List(ctx, "inlet/"); len(keys) != 302 {
		t.Fatalf("%d entries", len(keys))
	}
}

type countingStore struct {
	objstore.Store
	puts atomic.Int32
}

func (c *countingStore) Put(ctx context.Context, key string, body []byte) (bool, error) {
	c.puts.Add(1)
	return c.Store.Put(ctx, key, body)
}

type downStore struct{}

func (downStore) Put(context.Context, string, []byte) (bool, error) {
	return false, &objstore.UnavailableError{Op: "PUT", Key: "k"}
}
func (downStore) Get(context.Context, string) ([]byte, error) {
	return nil, &objstore.UnavailableError{Op: "GET", Key: "k"}
}
func (downStore) List(context.Context, string) ([]string, error) {
	return nil, &objstore.UnavailableError{Op: "LIST", Key: "k"}
}

type countingBody struct{ read atomic.Int64 }

func (c *countingBody) Read(p []byte) (int, error) {
	c.read.Add(int64(len(p)))
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func (c *countingBody) Close() error { return nil }

// TestM2_3_TenantGateDoesNotRefuseAReconcileOrderForNamingItsOwnRepo: a host
// wires the tenant-term gate, and the tenant's repository name is one of its
// terms. A task manifest must name that repository; only the rest of it is
// scanned, so a reconcile order still becomes a task Intent, while the same
// term in the owner's words is still refused.
func TestM2_3_TenantGateDoesNotRefuseAReconcileOrderForNamingItsOwnRepo(t *testing.T) {
	gate := secretscan.New([]secretscan.Term{{Value: testRepo, Rule: secretscan.RuleTenantTerm}})
	f := newFixture(t, func(_ *Options, d *Deps) { d.Gate = gate })
	f.classifier.decide = func(n Nit) (Decision, error) {
		return Decision{Kind: KindViolation, Clause: "DESIGN.md §2.2", Brief: n.Text, Summary: "s"}, nil
	}
	r := f.owner(nitText("The FAIL colour is below the documented contrast."))
	if r.Code != http.StatusCreated || r.Status != StatusTask || !capsule.ValidIntent(r.Intent) {
		t.Fatalf("%+v", r)
	}
	m, err := capsule.GetTask(context.Background(), f.store, r.Intent)
	if err != nil || m.Repo != testRepo || m.Clause != "DESIGN.md §2.2" {
		t.Fatalf("%+v %v", m, err)
	}
	if r := f.owner(nitText("This page should link to " + testRepo + " on the forge.")); r.Status != StatusTriage || r.Reason != "secret-gate" {
		t.Fatalf("tenant term in the brief: %+v", r)
	}
	if f.pushes() != 0 {
		t.Fatal("a reconcile order pushed to the forge")
	}
}

// TestM2_3_ExampleConfigConfiguresAnInlet: the committed example loads and
// maps to handler options — placeholders only, nothing missing.
func TestM2_3_ExampleConfigConfiguresAnInlet(t *testing.T) {
	cfg, err := config.Load(config.Options{File: filepath.Join("..", "..", "chimera.example.yaml")}, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	o, err := OptionsFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if o.Repo != "acme/widget" || o.Issuer != "https://id.example.com" || o.Audience == "" || o.Debounce != 10*time.Minute || o.DailyCap != 20 ||
		o.FolioBranch != "chimera/folio" || o.Target != "main" || o.EmailVerified != "required" || o.ClientIPHeader == "" || len(o.OwnerEmails) != 1 ||
		strings.Join(o.Verifier.Command, " ") != "go test ./..." || o.Verifier.Timeout != "10m" {
		t.Fatalf("%+v", o)
	}
}
