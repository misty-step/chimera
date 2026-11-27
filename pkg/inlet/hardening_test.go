package inlet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
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
// Deps.AfterFunc is nil, so the window is a time.AfterFunc timer and the
// flush runs on the timer's goroutine, through the real BranchPR and git.
//
// "All six arrived inside one window" is a statement about wall-clock time,
// so the test makes it true instead of hoping: accepting a nit costs
// milliseconds here (the store is in memory and the Folio is read without a
// subprocess — on a slow disk six durable accepts alone outlast a second),
// the window is far longer than that, and the arrivals are timed. Should
// the machine stall for a whole window anyway, the run proves nothing either
// way and is repeated with a longer window rather than reported as a result.
func TestM2_3_DebounceWindowFlushesOnTheRealTimer(t *testing.T) {
	window := 1200 * time.Millisecond
	for attempt := 1; ; attempt++ {
		took, inside := debounceOnTheRealTimer(t, window)
		if inside {
			return
		}
		if attempt == 3 {
			t.Fatalf("six nits never arrived inside one window: the last attempt took %v of %v", took, window)
		}
		t.Logf("six nits took %v, longer than the %v window; again with twice the window", took, window)
		window *= 2
	}
}

// debounceOnTheRealTimer posts six owner nits at once and checks what the
// real timer does with them. inside is false, and nothing was checked, when
// they did not all arrive before the window could have elapsed.
func debounceOnTheRealTimer(t *testing.T, window time.Duration) (took time.Duration, inside bool) {
	t.Helper()
	store := newMemStore()
	f := newFixture(t, func(o *Options, d *Deps) {
		o.Debounce, o.DailyCap = window, 100
		d.AfterFunc = nil // time.AfterFunc
		d.Store = store
		d.FolioPR.(*BranchPR).Store = store
		d.Folio = func(context.Context) (FolioSnapshot, error) {
			return FolioSnapshot{Product: productV1, Design: designV1}, nil
		}
	})
	start := time.Now()
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
	// The window opened no earlier than start and the timer cannot fire
	// before it has elapsed: all six are in it exactly when this holds.
	if took = time.Since(start); took >= window {
		f.h.Close()
		return took, false
	}
	if t.Failed() {
		t.FailNow()
	}
	// Pending counts a flush that is still running, so zero means the
	// update is pushed, announced, and settled — there is nothing else to
	// poll for.
	deadline := time.Now().Add(60 * time.Second)
	for f.h.Pending() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	flushedAfter := time.Since(start)
	head := f.forge.Refs()["refs/heads/chimera/folio"]
	if f.h.Pending() != 0 || head.IsZero() {
		t.Fatalf("the timer never flushed: pending=%d head=%q", f.h.Pending(), head)
	}
	if flushedAfter < window {
		t.Fatalf("flushed %v into a %v window", flushedAfter, window)
	}
	// All six arrived inside one window: one update carries them all.
	rulings := strings.Split(git(t, f.repo, "ls-tree", "-r", "--name-only", string(head), "folio/rulings"), "\n")
	settled, err := store.List(context.Background(), "inlet/"+testRepo+"/flushed/")
	if err != nil {
		t.Fatal(err)
	}
	if len(rulings) != 6 || f.pushes() != 1 || len(f.forge.Notifications()) != 1 || len(settled) != 6 {
		t.Fatalf("%d rulings in %d pushes, %d notifications, %d settled", len(rulings), f.pushes(), len(f.forge.Notifications()), len(settled))
	}
	// Close stops a window that is armed: nothing fires afterwards.
	f.owner(nitText("armed, then closed"))
	f.h.Close()
	time.Sleep(window + 300*time.Millisecond)
	if f.pushes() != 1 || f.h.Pending() != 1 {
		t.Fatalf("a closed handler flushed: pushes=%d pending=%d", f.pushes(), f.h.Pending())
	}
	return took, true
}

// TestM2_3_CoalescerCloseWaitsForARunningFlush: a flush the timer started
// is still writing when Close is called. Close returns only when it has
// finished — the update, OnSettled and OnFlush — and nothing is written, or
// scheduled, afterwards. All the while the batch counts as pending.
func TestM2_3_CoalescerCloseWaitsForARunningFlush(t *testing.T) {
	pr := newSlowPR()
	var closed atomic.Bool
	var writes, late atomic.Int32
	write := func() {
		writes.Add(1)
		if closed.Load() {
			late.Add(1)
		}
	}
	pr.write = write
	settling, settle := make(chan struct{}), make(chan struct{})
	c := &Coalescer{PR: pr, Window: 5 * time.Millisecond, Now: time.Now, AfterFunc: realAfterFunc,
		OnSettled: func(_ Update, landed, _ []Proposal) {
			close(settling)
			<-settle
			for range landed {
				write()
			}
		},
		OnFlush: func(Update, error) { write() },
	}
	c.Add(proposal("a"))
	c.Add(proposal("b"))
	<-pr.started // the timer's flush is inside the update
	if n := c.Pending(); n != 2 {
		t.Fatalf("pending=%d while a flush carries two proposals", n)
	}
	// One more arrives during the flush and opens a window of its own.
	c.Add(proposal("c"))
	if n := c.Pending(); n != 3 {
		t.Fatalf("pending=%d with two in flight and one waiting", n)
	}

	done := make(chan struct{})
	go func() {
		c.Close()
		closed.Store(true)
		close(done)
	}()
	for !c.isClosed() {
		time.Sleep(time.Millisecond)
	}
	returned := func(d time.Duration) bool {
		select {
		case <-done:
			return true
		case <-time.After(d):
			return false
		}
	}
	if returned(150 * time.Millisecond) {
		t.Fatal("Close returned while the update was still running")
	}
	if writes.Load() != 0 || c.Pending() != 3 {
		t.Fatalf("writes=%d pending=%d before the update was let go", writes.Load(), c.Pending())
	}
	close(pr.release) // the update lands...
	<-settling        // ...and is being settled
	if returned(150 * time.Millisecond) {
		t.Fatal("Close returned while the flush was still settling")
	}
	if n := c.Pending(); n != 3 {
		t.Fatalf("pending=%d while the flush is still settling", n)
	}
	close(settle)
	if !returned(10 * time.Second) {
		t.Fatal("Close never returned")
	}

	// The update, two settled proposals, and the flush report: all before
	// Close returned. The third proposal's window was armed during the
	// flush; it is closed now and must never fire.
	at := writes.Load()
	time.Sleep(200 * time.Millisecond) // forty windows
	if at != 4 || writes.Load() != at || late.Load() != 0 || pr.updates.Load() != 1 {
		t.Fatalf("writes at Close=%d, later=%d, after Close=%d, updates=%d", at, writes.Load(), late.Load(), pr.updates.Load())
	}
	if n := c.Pending(); n != 1 {
		t.Fatalf("pending=%d: what was waiting stays queued", n)
	}
	// Closing again is harmless, and nothing is armed for a late arrival.
	c.Close()
	c.Add(proposal("d"))
	time.Sleep(50 * time.Millisecond)
	if pr.updates.Load() != 1 || c.Pending() != 2 {
		t.Fatalf("a closed coalescer flushed: updates=%d pending=%d", pr.updates.Load(), c.Pending())
	}
}

// TestM2_3_CoalescerNeverArmsAfterClose: a flush that fails puts its batch
// back and arms a new window — unless the Coalescer was closed meanwhile.
func TestM2_3_CoalescerNeverArmsAfterClose(t *testing.T) {
	pr := newSlowPR()
	pr.err = errors.New("forge unavailable")
	var armed atomic.Int32
	c := &Coalescer{PR: pr, Window: 5 * time.Millisecond, Now: time.Now,
		AfterFunc: func(d time.Duration, f func()) func() {
			armed.Add(1)
			return realAfterFunc(d, f)
		}}
	c.Add(proposal("a"))
	<-pr.started
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	// Close has marked the coalescer closed once it is waiting; the failing
	// update is let go only then.
	for !c.isClosed() {
		time.Sleep(time.Millisecond)
	}
	close(pr.release)
	<-done
	time.Sleep(100 * time.Millisecond) // twenty windows
	if armed.Load() != 1 || pr.updates.Load() != 1 || c.Pending() != 1 {
		t.Fatalf("armed=%d updates=%d pending=%d", armed.Load(), pr.updates.Load(), c.Pending())
	}
	// Whoever owns the queue can still flush it by hand; a failure then
	// does not schedule anything either.
	if _, err := c.Flush(context.Background()); err == nil || armed.Load() != 1 || c.Pending() != 1 {
		t.Fatalf("err=%v armed=%d pending=%d", err, armed.Load(), c.Pending())
	}
	// An open coalescer does retry: the same failure arms the next window.
	pr2 := newSlowPR()
	pr2.err = errors.New("forge unavailable")
	close(pr2.release)
	var armed2 atomic.Int32
	c2 := &Coalescer{PR: pr2, Window: time.Hour, Now: time.Now,
		AfterFunc: func(time.Duration, func()) func() { armed2.Add(1); return func() {} }}
	defer c2.Close()
	c2.Add(proposal("a"))
	if _, err := c2.Flush(context.Background()); err == nil || armed2.Load() != 2 || c2.Pending() != 1 {
		t.Fatalf("err=%v armed=%d pending=%d", err, armed2.Load(), c2.Pending())
	}
}

// TestM2_3_CoalescerStaleTimerLeavesTheNextWindowAlone: a timer that could
// not be stopped in time (it had already fired) belongs to a window some
// other flush has emptied. It must not flush the next window early.
func TestM2_3_CoalescerStaleTimerLeavesTheNextWindowAlone(t *testing.T) {
	pr := newSlowPR()
	close(pr.release)
	var timers []func()
	c := &Coalescer{PR: pr, Window: time.Hour, Now: time.Now,
		// stop comes too late for every timer here.
		AfterFunc: func(_ time.Duration, f func()) func() { timers = append(timers, f); return func() {} }}
	defer c.Close()
	c.Add(proposal("a"))
	if _, err := c.Flush(context.Background()); err != nil || pr.updates.Load() != 1 {
		t.Fatalf("err=%v updates=%d", err, pr.updates.Load())
	}
	c.Add(proposal("b"))
	if len(timers) != 2 {
		t.Fatalf("%d windows armed", len(timers))
	}
	timers[0]() // the first window's timer, late
	if pr.updates.Load() != 1 || c.Pending() != 1 {
		t.Fatalf("a stale timer flushed the next window: updates=%d pending=%d", pr.updates.Load(), c.Pending())
	}
	timers[1]()
	if pr.updates.Load() != 2 || c.Pending() != 0 {
		t.Fatalf("the window's own timer did not flush: updates=%d pending=%d", pr.updates.Load(), c.Pending())
	}
}

// TestM2_3_CoalescerHandlerCloseLeavesNothingRunning: the same on the real
// path — a directory store, a git repository, the real timer. Close is
// called the moment the timer's flush starts; when it returns the update is
// pushed and settled, and neither the store nor the repository changes
// again. (A flush that outlived Close is what made removing a test's
// temporary directories fail with "directory not empty".)
func TestM2_3_CoalescerHandlerCloseLeavesNothingRunning(t *testing.T) {
	started, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := newFixture(t, func(o *Options, d *Deps) {
		o.Debounce = 20 * time.Millisecond
		d.AfterFunc = nil // time.AfterFunc
		real := d.FolioPR
		d.FolioPR = prFunc(func(ctx context.Context, batch []Proposal) (Update, error) {
			once.Do(func() { close(started) })
			<-proceed
			return real.Update(ctx, batch)
		})
	})
	if r := f.owner(nitText("closed in mid-flush")); r.Status != StatusFolio {
		t.Fatalf("%+v", r)
	}
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("the timer never flushed")
	}
	if n := f.h.Pending(); n != 1 {
		t.Fatalf("pending=%d while the flush is running", n)
	}
	done := make(chan struct{})
	go func() { f.h.Close(); close(done) }()
	// The update starts its work — git, the store, the forge — only once
	// Close is already waiting for it.
	for !f.h.coalescer.isClosed() {
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("Close returned before the flush had done anything")
	case <-time.After(100 * time.Millisecond):
	}
	close(proceed)
	<-done
	// Nothing to poll for: Close waited.
	settled := f.keysUnder("inlet/" + testRepo + "/flushed/")
	if f.h.Pending() != 0 || f.pushes() != 1 || len(f.forge.Notifications()) != 1 || len(settled) != 1 {
		t.Fatalf("Close returned before the flush was done: pending=%d pushes=%d notifications=%d settled=%v",
			f.h.Pending(), f.pushes(), len(f.forge.Notifications()), settled)
	}
	before := tree(t, f.repo, f.storeDir)
	time.Sleep(300 * time.Millisecond)
	if after := tree(t, f.repo, f.storeDir); after != before {
		t.Fatalf("files changed after Close:\n%s\n--- became ---\n%s", before, after)
	}
}

// prFunc is a FolioPR made of a function.
type prFunc func(ctx context.Context, batch []Proposal) (Update, error)

func (f prFunc) Update(ctx context.Context, batch []Proposal) (Update, error) { return f(ctx, batch) }

// slowPR is a pull request whose update takes as long as the test says.
type slowPR struct {
	started chan struct{} // receives once per update, when it begins
	release chan struct{} // close to let updates finish
	err     error         // what a finished update returns
	write   func()        // called when an update writes; may be nil
	updates atomic.Int32
}

func newSlowPR() *slowPR {
	return &slowPR{started: make(chan struct{}, 16), release: make(chan struct{})}
}

func (s *slowPR) Update(ctx context.Context, batch []Proposal) (Update, error) {
	s.started <- struct{}{}
	select {
	case <-s.release:
	case <-ctx.Done():
		return Update{}, ctx.Err()
	}
	s.updates.Add(1)
	if s.write != nil {
		s.write()
	}
	return Update{Pushed: s.err == nil}, s.err
}

func proposal(id string) Proposal {
	return Proposal{ID: id, Summary: "s", Files: []ProposalFile{{Path: "folio/rulings/" + id + ".md", Content: []byte(id + "\n")}}}
}

// realAfterFunc is what New uses when Deps.AfterFunc is nil.
func realAfterFunc(d time.Duration, f func()) func() {
	t := time.AfterFunc(d, f)
	return func() { t.Stop() }
}

func (c *Coalescer) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// tree lists every file under the given directories with its size.
func tree(t *testing.T, dirs ...string) string {
	t.Helper()
	var b strings.Builder
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return err
			}
			info, err := e.Info()
			if err != nil {
				return err
			}
			fmt.Fprintf(&b, "%s %d\n", p, info.Size())
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

// memStore is a Store in memory: the write-once semantics of the others
// without their latency.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newMemStore() *memStore { return &memStore{objects: map[string][]byte{}} }

func (m *memStore) Put(ctx context.Context, key string, body []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[key]; ok {
		return false, nil
	}
	m.objects[key] = append([]byte(nil), body...)
	return true, nil
}

func (m *memStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.objects[key]
	if !ok {
		return nil, objstore.ErrNotFound
	}
	return append([]byte(nil), body...), nil
}

func (m *memStore) List(ctx context.Context, prefix string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var keys []string
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
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
