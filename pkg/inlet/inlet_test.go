package inlet

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/config"
	"chimera/pkg/forge"
	"chimera/pkg/objstore"
)

// untouched asserts that a request triggered nothing but (at most) a triage
// append: no classifier call, no push, no notification, no task, no cap slot.
func (f *fixture) untouched(what string) {
	f.t.Helper()
	if n := f.classifier.Calls(); n != 0 {
		f.t.Fatalf("%s: classifier called %d times", what, n)
	}
	if n := len(f.forge.Pushes()); n != 0 {
		f.t.Fatalf("%s: %d forge pushes", what, n)
	}
	if n := len(f.forge.Notifications()); n != 0 {
		f.t.Fatalf("%s: %d notifications", what, n)
	}
	if keys := f.keysUnder("intent/"); len(keys) != 0 {
		f.t.Fatalf("%s: task stored: %v", what, keys)
	}
	if keys := f.keysUnder("inlet/" + testRepo + "/nits/"); len(keys) != 0 {
		f.t.Fatalf("%s: daily-cap slot consumed: %v", what, keys)
	}
	if f.h.Pending() != 0 {
		f.t.Fatalf("%s: a proposal was queued", what)
	}
}

func TestM2_3_UnsignedOrNonOwnerTokenNeverReachesClassifier(t *testing.T) {
	keys(t)
	now := newClock().Now()
	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hs := func() string { // HS256 "signed" with the public key as the secret
		tok := mint(t, "HS256", "rsa-1", nil, claims(now, nil))
		signed := tok[:strings.LastIndexByte(tok, '.')]
		mac := hmac.New(sha256.New, pubDER)
		mac.Write([]byte(signed))
		return signed + "." + enc(mac.Sum(nil))
	}
	good := mint(t, "RS256", "rsa-1", rsaKey, claims(now, nil))
	tampered := func() string { // a valid signature over different claims
		other := mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "visitor@example.com"}))
		g, o := strings.Split(good, "."), strings.Split(other, ".")
		return o[0] + "." + g[1] + "." + o[2]
	}
	cases := map[string]string{
		"no token":              "",
		"alg none":              mint(t, "none", "rsa-1", nil, claims(now, nil)),
		"alg none, bogus sig":   mint(t, "none", "rsa-1", []byte("x"), claims(now, nil)),
		"hs256 with public key": hs(),
		"wrong key":             mint(t, "RS256", "rsa-1", otherRSA, claims(now, nil)),
		"claims swapped":        tampered(),
		"unknown kid":           mint(t, "RS256", "nope", rsaKey, claims(now, nil)),
		"no kid":                mint(t, "RS256", "", rsaKey, claims(now, nil)),
		"alg and key disagree":  mint(t, "ES256", "rsa-1", ecKey, claims(now, nil)),
		"rsa key, eddsa header": mint(t, "EdDSA", "rsa-1", edKey, claims(now, nil)),
		"wrong issuer":          mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"iss": "https://id.example.org"})),
		"no issuer":             mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"iss": nil})),
		"wrong audience":        mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"aud": "another-app"})),
		"no audience":           mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"aud": nil})),
		"expired":               mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"exp": now.Add(-time.Second).Unix()})),
		"no exp":                mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"exp": nil})),
		"future nbf":            mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"nbf": now.Add(5 * time.Minute).Unix()})),
		"future iat":            mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"iat": now.Add(5 * time.Minute).Unix()})),
		"email not an owner":    mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "visitor@example.com"})),
		"owner as a prefix":     mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": testOwner + ".evil.example"})),
		"no email":              mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": nil})),
		"email_verified false":  mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email_verified": false})),
		"email_verified absent": mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email_verified": nil})),
		"email_verified string": mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email_verified": "true"})),
		"email_verified number": mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email_verified": 1})),
		"email padded":          mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": " " + testOwner + " "})),
		"email kelvin sign":     mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "\u212Aim@example.com"})),
		"email dotted capital":  mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "adm\u0130n@example.com"})),
		"email two ats":         mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "owner@example.com@example.com"})),
		"crit header":           strings.Replace(good, strings.Split(good, ".")[0], enc([]byte(`{"alg":"RS256","kid":"rsa-1","crit":["x"]}`)), 1),
		"not a jws":             "not-a-token",
		"two parts":             "a.b",
		"oversized":             strings.Repeat("a", maxToken+1),
		"corrupted header":      "!!!!" + good[4:],
		"empty signature":       good[:strings.LastIndexByte(good, '.')+1],
	}
	var anonymous reply
	// Look-alikes of these owners must not fold onto them.
	lookalikes := func(o *Options, _ *Deps) {
		o.OwnerEmails = append(o.OwnerEmails, "kim@example.com", "admin@example.com")
	}
	for name, token := range cases {
		f := newFixture(t, lookalikes)
		r := f.post(goodNit, token, nil)
		if r.Code != http.StatusAccepted || r.Status != StatusTriage || r.Reason != "" || r.Intent != "" || r.Branch != "" {
			t.Fatalf("%s: %+v", name, r)
		}
		f.untouched(name)
		entries := f.inbox.Entries()
		if len(entries) != 1 || entries[0].Owner || string(entries[0].Body) != goodNit || !entries[0].ReceivedAt.Equal(now) {
			t.Fatalf("%s: inbox %+v", name, entries)
		}
		// No oracle: every refusal answers exactly as the anonymous request did.
		if name == "no token" {
			anonymous = r
		}
	}
	for name, token := range cases {
		f := newFixture(t, lookalikes)
		r := f.post(goodNit, token, nil)
		if r.Response != anonymous.Response || r.Code != anonymous.Code || !reflect.DeepEqual(r.Header, anonymous.Header) {
			t.Fatalf("%s answers %d %+v %v, anonymous answers %d %+v %v", name, r.Code, r.Response, r.Header, anonymous.Code, anonymous.Response, anonymous.Header)
		}
	}

	// An owner's token, under each allowed algorithm, reaches the classifier exactly once.
	for name, token := range map[string]string{
		"RS256": mint(t, "RS256", "rsa-1", rsaKey, claims(now, nil)),
		"ES256": mint(t, "ES256", "ec-1", ecKey, claims(now, nil)),
		"EdDSA": mint(t, "EdDSA", "ed-1", edKey, claims(now, nil)),
		"aud list, upper-case email": mint(t, "RS256", "rsa-1", rsaKey,
			claims(now, map[string]any{"aud": []string{"other", testAudience}, "email": "OWNER@example.com"})),
	} {
		f := newFixture(t, nil)
		r := f.post(goodNit, token, nil)
		if r.Code != http.StatusAccepted || r.Status != StatusFolio || f.classifier.Calls() != 1 || len(f.inbox.Entries()) != 0 {
			t.Fatalf("%s: %+v calls=%d", name, r, f.classifier.Calls())
		}
	}
	// An edge whose tokens carry no email_verified claim is accepted only when
	// the operator says so; a present false still refuses.
	noClaim := mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email_verified": nil}))
	f := newFixture(t, func(o *Options, _ *Deps) { o.EmailVerified = "if-present" })
	if r := f.post(goodNit, noClaim, nil); r.Status != StatusFolio || f.classifier.Calls() != 1 {
		t.Fatalf("if-present, absent claim: %+v", r)
	}
	if r := f.post(goodNit, cases["email_verified false"], nil); r.Status != StatusTriage || f.classifier.Calls() != 1 {
		t.Fatalf("if-present, false claim: %+v", r)
	}
}

func TestM2_3_EdgeHeaderAndSessionCookieCarryTheToken(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.TokenHeader, o.TokenCookie = "X-Edge-Jwt", "edge_session" })
	tok := ownerToken(t, f.clock.Now())
	if r := f.post(goodNit, "", func(r *http.Request) { r.Header.Set("X-Edge-Jwt", tok) }); r.Status != StatusFolio {
		t.Fatalf("header: %+v", r)
	}
	if r := f.post(goodNit, "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "edge_session", Value: tok}) }); r.Status != StatusFolio {
		t.Fatalf("cookie: %+v", r)
	}
	if r := f.post(goodNit, "", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "other", Value: tok}) }); r.Status != StatusTriage {
		t.Fatalf("unconfigured cookie: %+v", r)
	}
	if f.classifier.Calls() != 2 {
		t.Fatalf("classifier calls %d", f.classifier.Calls())
	}
	// Without configuration only Authorization: Bearer is read.
	g := newFixture(t, nil)
	if r := g.post(goodNit, "", func(r *http.Request) { r.Header.Set("X-Edge-Jwt", tok) }); r.Status != StatusTriage || g.classifier.Calls() != 0 {
		t.Fatalf("unconfigured header: %+v", r)
	}
}

func TestM2_3_UnauthenticatedInputIsAppendedVerbatimAndTriggersNothingElse(t *testing.T) {
	keys(t)
	var fetches atomic.Int32
	var served atomic.Value
	served.Store(testJWKS)
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Write(served.Load().([]byte))
	}))
	defer jwks.Close()
	folioReads := 0
	f := newFixture(t, func(o *Options, d *Deps) {
		o.JWKS, o.JWKSURL = nil, jwks.URL
		d.HTTPClient = jwks.Client()
		d.Folio = func(context.Context) (FolioSnapshot, error) { folioReads++; return FolioSnapshot{}, nil }
	})
	// The keys were loaded once, at start. No request fetches them again.
	if fetches.Load() != 1 {
		t.Fatalf("%d JWKS fetches at start", fetches.Load())
	}
	garbage := "\x00\xff{not json at all <script>alert(1)</script> \x80"
	r := f.post(garbage, "", nil)
	if r.Code != http.StatusAccepted || r.Status != StatusTriage {
		t.Fatalf("%+v", r)
	}
	f.untouched("anonymous garbage")
	entries := f.inbox.Entries()
	if len(entries) != 1 || string(entries[0].Body) != garbage || entries[0].Owner || entries[0].Reason != "" {
		t.Fatalf("inbox %+v", entries)
	}
	if fetches.Load() != 1 || folioReads != 0 {
		t.Fatalf("anonymous input caused %d JWKS fetches and %d Folio reads", fetches.Load()-1, folioReads)
	}
	// A forged token, whatever kid it names and however often it is sent,
	// causes ZERO fetches: the request path only reads the cached set.
	unknown := mint(t, "RS256", "rotated", rsaKey, claims(f.clock.Now(), nil))
	forged := []string{mint(t, "none", "rsa-1", nil, claims(f.clock.Now(), nil)), mint(t, "HS256", "rsa-1", []byte("x"), claims(f.clock.Now(), nil)),
		"garbage", unknown, mint(t, "RS256", "whatever", []byte("x"), claims(f.clock.Now(), nil))}
	for round := 0; round < 3; round++ {
		for i, tok := range forged {
			addr := fmt.Sprintf("192.0.2.%d:1", 20+round*10+i)
			if r := f.post(goodNit, tok, func(r *http.Request) { r.RemoteAddr = addr }); r.Status != StatusTriage {
				t.Fatalf("%+v", r)
			}
		}
		f.clock.Advance(61 * time.Second)
	}
	if fetches.Load() != 1 {
		t.Fatalf("forged tokens made the inlet fetch the JWKS %d more times", fetches.Load()-1)
	}
	// Owners verify against the cached set.
	for i := 0; i < 3; i++ {
		if r := f.owner(goodNit); r.Status != StatusFolio {
			t.Fatalf("owner via remote JWKS: %+v", r)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("%d JWKS fetches after three owner tokens", fetches.Load())
	}
	// A request that is aborted cannot disturb the keys either: there is
	// nothing in flight for it to cancel.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f.post(goodNit, unknown, func(r *http.Request) { *r = *r.WithContext(ctx); r.RemoteAddr = "192.0.2.99:1" })
	if r := f.owner(goodNit); r.Status != StatusFolio {
		t.Fatalf("owner after an aborted forged request: %+v", r)
	}
	// The background refresh (driven here by hand) replaces the set: a key
	// the identity provider withdrew stops making owners.
	served.Store(testJWKSOnly)
	if err := f.h.remote.Load(context.Background()); err != nil || fetches.Load() != 2 {
		t.Fatalf("refresh: %v, %d fetches", err, fetches.Load())
	}
	if r := f.owner(goodNit); r.Status != StatusTriage {
		t.Fatalf("a withdrawn key still made an owner: %+v", r)
	}
	if r := f.post(goodNit, mint(t, "EdDSA", "ed-1", edKey, claims(f.clock.Now(), nil)), nil); r.Status != StatusFolio {
		t.Fatalf("the remaining key: %+v", r)
	}
	// A set that could not be refreshed for longer than its max age is no
	// longer trusted: nobody is an owner until the provider answers again.
	f.clock.Advance(DefaultJWKSMaxAge + time.Minute)
	if r := f.post(goodNit, mint(t, "EdDSA", "ed-1", edKey, claims(f.clock.Now(), nil)), nil); r.Status != StatusTriage {
		t.Fatalf("a stale key set still made an owner: %+v", r)
	}
	if err := f.h.remote.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := f.post(goodNit, mint(t, "EdDSA", "ed-1", edKey, claims(f.clock.Now(), nil)), nil); r.Status != StatusFolio {
		t.Fatalf("after a successful refresh: %+v", r)
	}

	// An inlet that cannot load its keys does not start.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusBadGateway) }))
	defer down.Close()
	fk := forge.NewFake()
	deps := Deps{Store: objstore.NewDir(t.TempDir()), Forge: fk, Classifier: &fakeClassifier{}, FolioPR: &BranchPR{}}
	opts := Options{Repo: testRepo, OwnerEmails: []string{testOwner}, Issuer: testIssuer, Audience: testAudience, Target: "main"}
	for name, u := range map[string]string{
		"identity provider down": down.URL,
		"plain http":             "http://id.example.com/jwks.json",
		"not a url":              "://",
	} {
		o := opts
		o.JWKSURL = u
		if _, err := New(o, deps); err == nil || !strings.Contains(err.Error(), "jwks") {
			t.Errorf("%s: New err=%v", name, err)
		}
	}
	// Neither an oversized answer nor a redirect to another host is accepted.
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(append([]byte(`{"keys":[],"pad":"`), append(bytes.Repeat([]byte("a"), maxJWKSBytes), []byte(`"}`)...)...))
	}))
	defer big.Close()
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(testJWKS) }))
	defer elsewhere.Close()
	hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)+"/jwks.json", http.StatusFound)
	}))
	defer hop.Close()
	for name, u := range map[string]string{"oversized": big.URL, "redirect to another host": hop.URL} {
		if err := (&RemoteKeys{URL: u}).Load(context.Background()); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	// Start and Close: the ticker refreshes on its own and stops when asked.
	rk := &RemoteKeys{URL: jwks.URL, Refresh: 20 * time.Millisecond}
	if err := rk.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := fetches.Load()
	rk.Start()
	deadline := time.Now().Add(5 * time.Second)
	for fetches.Load() < before+2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	rk.Close()
	rk.Close()
	after := fetches.Load()
	if after < before+2 {
		t.Fatalf("background refresh did not run: %d fetches", after-before)
	}
	time.Sleep(80 * time.Millisecond)
	if fetches.Load() != after {
		t.Fatal("refresh kept running after Close")
	}
}

func TestM2_3_TriageInboxIsRateLimited(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.TriagePerMinute = 3 })
	from := func(addr string) func(*http.Request) { return func(r *http.Request) { r.RemoteAddr = addr } }
	for i := 0; i < 3; i++ {
		if r := f.post("x", "", from("192.0.2.1:1000")); r.Code != http.StatusAccepted || r.Status != StatusTriage {
			t.Fatalf("burst %d: %+v", i, r)
		}
	}
	r := f.post("x", "", from("192.0.2.1:2000"))
	if r.Code != http.StatusTooManyRequests || r.Status != StatusRateLimited || r.Header.Get("Retry-After") == "" || len(f.inbox.Entries()) != 3 {
		t.Fatalf("over the limit: %+v, %d entries", r, len(f.inbox.Entries()))
	}
	// Another client has its own bucket.
	if r := f.post("x", "", from("192.0.2.2:1000")); r.Status != StatusTriage {
		t.Fatalf("second client: %+v", r)
	}
	// A third of a minute refills one token of three.
	f.clock.Advance(20 * time.Second)
	if r := f.post("x", "", from("192.0.2.1:1000")); r.Status != StatusTriage {
		t.Fatalf("after refill: %+v", r)
	}
	if r := f.post("x", "", from("192.0.2.1:1000")); r.Status != StatusRateLimited {
		t.Fatalf("after refill, second: %+v", r)
	}
	if len(f.inbox.Entries()) != 5 {
		t.Fatalf("%d entries", len(f.inbox.Entries()))
	}
	// A failed token is rate-limited exactly like no token.
	bad := mint(t, "RS256", "rsa-1", otherRSA, claims(f.clock.Now(), nil))
	if r := f.post(goodNit, bad, from("192.0.2.1:1000")); r.Status != StatusRateLimited {
		t.Fatalf("bad token over the limit: %+v", r)
	}
	// The global bucket (ten times the per-client rate) bounds a crowd.
	g := newFixture(t, func(o *Options, _ *Deps) { o.TriagePerMinute = 1 })
	accepted := 0
	for i := 0; i < 40; i++ {
		addr := "198.51.100." + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ":1"
		if r := g.post("x", "", from(addr)); r.Status == StatusTriage {
			accepted++
		}
	}
	if accepted != 10 || len(g.inbox.Entries()) != 10 {
		t.Fatalf("global bucket let %d of 40 clients through", accepted)
	}
	f.untouched("rate limiting")
}

func TestM2_3_DailyCapEnforced(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.DailyCap = 3 })
	for i := 1; i <= 3; i++ {
		if r := f.owner(nitText("nit " + string(rune('0'+i)))); r.Status != StatusFolio || r.Pending != i {
			t.Fatalf("nit %d: %+v", i, r)
		}
	}
	r := f.owner(nitText("one too many"))
	if r.Code != http.StatusTooManyRequests || r.Status != StatusCapped || f.classifier.Calls() != 3 || f.h.Pending() != 3 {
		t.Fatalf("fourth nit: %+v, classifier calls %d", r, f.classifier.Calls())
	}
	if slots := f.keysUnder("inlet/" + testRepo + "/nits/2026-11-27/"); len(slots) != 6 { // three nits, three decisions
		t.Fatalf("slots: %v", slots)
	}
	// The cap is per UTC day.
	f.clock.Advance(14*time.Hour + time.Minute) // 2026-11-28T00:01Z
	first := f.owner(nitText("a new day"))
	if first.Status != StatusFolio || f.classifier.Calls() != 4 || first.Ruling != "folio/rulings/nit-20261128-0001.md" {
		t.Fatalf("next day: %+v", first)
	}
	if second := f.owner(nitText("second of the day")); second.Ruling != "folio/rulings/nit-20261128-0002.md" {
		t.Fatalf("ruling path %q", second.Ruling)
	}
}

func TestM2_3_DailyCapIsSharedByHandlersOnOneStore(t *testing.T) {
	a := newFixture(t, func(o *Options, _ *Deps) { o.DailyCap = 3 })
	b := newFixture(t, func(o *Options, d *Deps) { o.DailyCap = 3; d.Store = a.store })
	want := []struct {
		f      *fixture
		status string
	}{{a, StatusFolio}, {b, StatusFolio}, {a, StatusFolio}, {b, StatusCapped}, {a, StatusCapped}}
	for i, w := range want {
		if r := w.f.owner(nitText("shared cap")); r.Status != w.status {
			t.Fatalf("request %d: %+v, want %s", i, r, w.status)
		}
	}
	if total := a.classifier.Calls() + b.classifier.Calls(); total != 3 {
		t.Fatalf("classifier calls across both handlers: %d", total)
	}
	// Concurrent owners never exceed the cap either.
	c := newFixture(t, func(o *Options, _ *Deps) { o.DailyCap = 5 })
	d := newFixture(t, func(o *Options, dd *Deps) { o.DailyCap = 5; dd.Store = c.store })
	var wg sync.WaitGroup
	var folio atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f := c
			if i%2 == 1 {
				f = d
			}
			if r := f.owner(nitText("concurrent")); r.Status == StatusFolio {
				folio.Add(1)
			} else if r.Status != StatusCapped {
				t.Errorf("unexpected %+v", r)
			}
		}(i)
	}
	wg.Wait()
	if folio.Load() != 5 || c.classifier.Calls()+d.classifier.Calls() != 5 {
		t.Fatalf("%d nits passed a cap of 5 (%d classifier calls)", folio.Load(), c.classifier.Calls()+d.classifier.Calls())
	}
}

func TestM2_3_PreviewOriginNitDroppedByLoopGuard(t *testing.T) {
	now := newClock().Now()
	nitFrom := func(u string) string {
		b, _ := json.Marshal(Nit{Schema: NitSchema, URL: u, Selector: "#x", Viewport: Viewport{W: 1, H: 1, DPR: 1}, Text: "t"})
		return string(b)
	}
	cases := []struct {
		name, body, token string
		edit              func(*http.Request)
	}{
		{"origin header", goodNit, "", from("https://pr-12.preview.example.com")},
		{"origin header, nested label and port", goodNit, "", from("https://a.b.preview.example.com:8443")},
		{"origin header, case", goodNit, "", from("HTTPS://PR-7.Preview.Example.COM")},
		{"origin header, ipv6 loopback", goodNit, "", from("http://[::1]:3000")},
		{"nit url", nitFrom("https://pr-12.preview.example.com/orders?x=1#frag"), "", nil},
		{"nit url, exact host and port", nitFrom("http://127.0.0.1:9001/index.html"), "", nil},
		{"bot actor", goodNit, mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "BOT@example.com"})), nil},
		{"bot suffix on subject", goodNit, mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"sub": "chimera[bot]"})), nil},
		{"bot suffix on email", goodNit, mint(t, "RS256", "rsa-1", rsaKey, claims(now, map[string]any{"email": "reconciler[bot]@example.com"})), nil},
	}
	for _, c := range cases {
		keys(t)
		f := newFixture(t, func(o *Options, _ *Deps) {
			o.OwnerEmails = append(o.OwnerEmails, "bot@example.com", "reconciler[bot]@example.com")
			o.PreviewOrigins = append(o.PreviewOrigins, "http://[::1]:3000")
		})
		token := c.token
		if token == "" {
			token = ownerToken(t, now)
		}
		r := f.post(c.body, token, c.edit)
		if r.Code != http.StatusAccepted || r.Status != StatusDropped || r.Reason != "loop-guard" {
			t.Fatalf("%s: %+v", c.name, r)
		}
		f.untouched(c.name)
		if len(f.inbox.Entries()) != 0 {
			t.Fatalf("%s: a dropped nit was kept", c.name)
		}
	}
	// Near misses are not previews: they are classified.
	for name, edit := range map[string]func(*http.Request){
		"other scheme":       from("http://pr-1.preview.example.com"),
		"suffix look-alike":  from("https://preview.example.com.evil.example"),
		"other port":         from("http://127.0.0.1:9002"),
		"the product itself": from("https://app.example.com"),
	} {
		f := newFixture(t, nil)
		if r := f.post(goodNit, ownerToken(t, now), edit); r.Status != StatusFolio || f.classifier.Calls() != 1 {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

func TestM2_3_FolioOnlyPathFenceRejectsOutOfFencePaths(t *testing.T) {
	for _, p := range []string{"PRODUCT.md", "DESIGN.md", "folio/rulings/a.md", "folio/assets/trail-reference/trail.css", "folio/x"} {
		if !InFence(p) {
			t.Errorf("InFence(%q) = false", p)
		}
	}
	outside := []string{"cmd/chimera/main.go", "folio/../go.mod", "/etc/passwd", "folio\\x", ".git/config", "PRODUCT.md/../AGENTS.md",
		"", "folio", "folio/", "./PRODUCT.md", "product.md", "docs/PRODUCT.md", "folio/.git/config", "folio//x", "folio/./x", "../folio/x",
		"AGENTS.md", "go.mod", "folio/x\n", "folio/ x", "folioo/x", "DESIGN.md/x", "/PRODUCT.md", "folio/a/../../go.mod",
		// No pattern, no control or format character, no dot-file, no spelling of ".git".
		"folio/*", "folio/[a]", "folio/a?", "folio/a\tb", "folio/\x1b[2J", "folio/.gitmodules", "folio/.gitattributes", "folio/.g\u200cit/config",
		"folio/.git./config", "folio/.GIT/x", "folio/a:b", "Folio/x", "FOLIO/x", "folio/\u202egpj.exe", "folio/x ", "folio/git~1/config",
		"folio/caf\u00e9.md", "folio/a\x00b", "folio/" + strings.Repeat("a", 600)}
	for _, p := range outside {
		if InFence(p) {
			t.Errorf("InFence(%q) = true", p)
		}
	}
	// One out-of-fence path rejects the whole decision: nothing is queued or pushed.
	for _, p := range outside {
		f := newFixture(t, nil)
		f.classifier.decide = func(Nit) (Decision, error) {
			return Decision{Kind: KindIntent, Summary: "s", Edits: []Edit{{Path: "DESIGN.md", Content: "# Design\n"}, {Path: p, Content: "x"}}}, nil
		}
		r := f.owner(goodNit)
		if r.Code != http.StatusAccepted || r.Status != StatusTriage || r.Reason != "path-fence" {
			t.Fatalf("%q: %+v", p, r)
		}
		if _, err := f.h.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.h.Pending() != 0 || len(f.forge.Pushes()) != 0 || len(f.forge.Notifications()) != 0 {
			t.Fatalf("%q: pending=%d pushes=%d", p, f.h.Pending(), len(f.forge.Pushes()))
		}
		kept := f.inbox.Entries()
		if len(kept) != 1 || !kept[0].Owner || kept[0].Reason != "path-fence" || string(kept[0].Body) != goodNitKept {
			t.Fatalf("%q: inbox %+v", p, kept)
		}
	}

	// In-fence edits land, and the pushed commit touches the Folio and nothing else.
	f := newFixture(t, nil)
	f.classifier.decide = func(Nit) (Decision, error) {
		return Decision{Kind: KindIntent, Summary: "Totals are right-aligned", Edits: []Edit{
			{Path: "PRODUCT.md", Content: productV1 + "**[UI-2] Totals are right-aligned.**\n"},
			{Path: "DESIGN.md", Content: designV1 + "Totals align right.\n"},
			{Path: "folio/assets/notes/totals.md", Content: "right-aligned\n"},
		}}, nil
	}
	if r := f.owner(goodNit); r.Status != StatusFolio || r.Branch != "chimera/folio" || r.Ruling != "folio/rulings/nit-20261127-0001.md" {
		t.Fatalf("%+v", r)
	}
	up, err := f.h.Flush(context.Background())
	if err != nil || !up.Pushed || len(up.Dropped) != 0 {
		t.Fatalf("%+v %v", up, err)
	}
	head := f.forge.Refs()["refs/heads/chimera/folio"]
	if head != up.Change.Head || head.IsZero() {
		t.Fatalf("branch at %q, update says %q", head, up.Change.Head)
	}
	changed := strings.Split(git(t, f.repo, "diff", "--name-only", string(f.head), string(head)), "\n")
	want := []string{"DESIGN.md", "PRODUCT.md", "folio/assets/notes/totals.md", "folio/rulings/nit-20261127-0001.md"}
	if strings.Join(changed, ",") != strings.Join(want, ",") {
		t.Fatalf("pushed commit changes %v", changed)
	}
	for _, p := range changed {
		if !InFence(p) {
			t.Fatalf("pushed commit touches %q", p)
		}
	}
	if got := git(t, f.repo, "show", string(head)+":cmd/chimera/main.go"); got != "package main\n\nfunc main() {}" {
		t.Fatalf("code changed: %q", got)
	}
	ruling := git(t, f.repo, "show", string(head)+":folio/rulings/nit-20261127-0001.md")
	for _, wantLine := range []string{"# Owner nit 20261127-0001", "- actor: owner", `- path: "/orders"`, `- selector: "#total"`,
		"- viewport: 1440x900 @2x", "Totals are right-aligned", "Total should use tabular figures."} {
		if !strings.Contains(ruling, wantLine) {
			t.Errorf("ruling lacks %q:\n%s", wantLine, ruling)
		}
	}
	msg := git(t, f.repo, "log", "-1", "--format=%an <%ae>%n%B", string(head))
	if strings.Contains(strings.ToLower(msg+ruling), testOwner) || !strings.HasPrefix(msg, "chimera inlet <inlet@chimera.invalid>\nfolio: record 1 owner nit\n") {
		t.Fatalf("commit:\n%s", msg)
	}
	// Neither the operator's host nor anything a query string carried reaches Git.
	for _, leak := range []string{"app.example.com", "page=2", "code=abc", "frag"} {
		if strings.Contains(msg+ruling, leak) {
			t.Errorf("the commit or the ruling carries %q", leak)
		}
	}
	// Every changed path is a plain file.
	for _, line := range strings.Split(git(t, f.repo, "ls-tree", "-r", string(head), "PRODUCT.md", "DESIGN.md", "folio"), "\n") {
		if !strings.HasPrefix(line, "100644 blob ") {
			t.Errorf("not a plain file: %s", line)
		}
	}
	// The user's checkout and index were never touched.
	if st := git(t, f.repo, "status", "--porcelain"); st != "" || git(t, f.repo, "rev-parse", "HEAD") != string(f.head) {
		t.Fatalf("work tree changed: %q", st)
	}

	// The pull request itself refuses an out-of-fence file, whoever asks.
	for _, p := range []string{"cmd/chimera/main.go", "folio/../go.mod", ".git/config"} {
		g := newFixture(t, nil)
		up, err := g.pr.Update(context.Background(), []Proposal{{ID: "x", Summary: "s", Files: []ProposalFile{{Path: "folio/ok.md", Content: []byte("ok\n")}, {Path: p, Content: []byte("x")}}}})
		if err != nil || up.Pushed || len(up.Refused) != 1 || up.Refused[0] != (Refusal{ID: "x", Reason: "path-fence"}) || len(g.forge.Pushes()) != 0 {
			t.Fatalf("%q: %+v err=%v pushes=%d", p, up, err, len(g.forge.Pushes()))
		}
	}
	// Second check: a branch that already carries a change outside the fence
	// (someone pushed code to it) is never extended.
	g := newFixture(t, nil)
	git(t, g.repo, "checkout", "-q", "-b", "side")
	writeFile(t, g.repo, "cmd/chimera/main.go", "package main\n\nfunc main() { panic(1) }\n")
	git(t, g.repo, "commit", "-q", "-am", "code on the folio branch")
	g.forge.SetRef("chimera/folio", forge.SHA(git(t, g.repo, "rev-parse", "HEAD")))
	git(t, g.repo, "checkout", "-q", "main")
	_, err = g.pr.Update(context.Background(), []Proposal{{ID: "y", Summary: "s", Files: []ProposalFile{{Path: "folio/ok.md", Content: []byte("ok\n")}}}})
	if err == nil || !strings.Contains(err.Error(), "outside the folio fence") || len(g.forge.Pushes()) != 0 {
		t.Fatalf("tainted branch: err=%v pushes=%d", err, len(g.forge.Pushes()))
	}
}

func TestM2_3_FolioViolationBecomesTaskIntentAndFolioStaysUntouched(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) {
		o.Verifier = capsule.TaskVerifier{Command: []string{"go", "test", "./..."}, Timeout: "10m"}
	})
	f.classifier.decide = func(n Nit) (Decision, error) {
		return Decision{Kind: KindViolation, Clause: " PRODUCT.md [UI-1] ", Brief: "Totals must use tabular figures.", Acceptance: []string{"[UI-1]"}, Summary: "tabular figures"}, nil
	}
	r := f.owner(goodNit)
	if r.Code != http.StatusCreated || r.Status != StatusTask || r.Clause != "PRODUCT.md [UI-1]" || !capsule.ValidIntent(r.Intent) || !strings.HasPrefix(r.Intent, "task:") {
		t.Fatalf("%+v", r)
	}
	m, err := capsule.GetTask(context.Background(), f.store, r.Intent)
	if err != nil {
		t.Fatal(err)
	}
	if m.Clause != "PRODUCT.md [UI-1]" || m.Repo != testRepo || m.BaseSHA != string(f.head) || strings.Join(m.Acceptance, ",") != "[UI-1]" ||
		strings.Join(m.Verifier.Command, " ") != "go test ./..." || m.Verifier.Timeout != "10m" {
		t.Fatalf("%+v", m)
	}
	for _, want := range []string{"Totals must use tabular figures.", `- path: "/orders"`, `- selector: "#total"`, "- viewport: 1440x900 @2x"} {
		if !strings.Contains(m.Brief, want) {
			t.Errorf("brief lacks %q:\n%s", want, m.Brief)
		}
	}
	for _, leak := range []string{"app.example.com", "page=2", "code=abc"} {
		if strings.Contains(m.Brief, leak) {
			t.Errorf("the brief carries %q", leak)
		}
	}
	// The daily-cap slot keeps the origin and path, never the query.
	slot, _ := f.store.Get(context.Background(), NitKey(testRepo, "2026-11-27", 1))
	if !strings.Contains(string(slot), `"url":"https://app.example.com/orders"`) || strings.Contains(string(slot), "page=2") {
		t.Errorf("slot record: %s", slot)
	}
	// The Folio is untouched: no proposal, no push, no notification, same refs, same bytes.
	if _, err := f.h.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	refs := f.forge.Refs()
	if f.h.Pending() != 0 || len(f.forge.Pushes()) != 0 || len(f.forge.Notifications()) != 0 || len(refs) != 1 || refs["refs/heads/main"] != f.head {
		t.Fatalf("pending=%d pushes=%d refs=%v", f.h.Pending(), len(f.forge.Pushes()), refs)
	}
	if git(t, f.repo, "show", "main:PRODUCT.md")+"\n" != productV1 || git(t, f.repo, "show", "main:DESIGN.md")+"\n" != designV1 || git(t, f.repo, "status", "--porcelain") != "" {
		t.Fatal("the Folio changed")
	}
	if len(f.inbox.Entries()) != 0 || f.classifier.Calls() != 1 {
		t.Fatalf("inbox=%d calls=%d", len(f.inbox.Entries()), f.classifier.Calls())
	}
	// The same violation again is the same content-addressed order.
	if again := f.owner(goodNit); again.Intent != r.Intent {
		t.Fatalf("second order %q, first %q", again.Intent, r.Intent)
	}
	// A violation that names no clause, or tries to edit the Folio, is no order at all.
	for reason, d := range map[string]Decision{
		"no clause":   {Kind: KindViolation, Brief: "b"},
		"with edits":  {Kind: KindViolation, Clause: "DESIGN.md §2", Edits: []Edit{{Path: "DESIGN.md", Content: "x"}}},
		"unknown":     {Kind: "praise"},
		"bad id":      {Kind: KindViolation, Clause: "c", Acceptance: []string{"UI-1"}},
		"empty":       {},
		"dup edit":    {Kind: KindIntent, Edits: []Edit{{Path: "DESIGN.md", Content: "a"}, {Path: "DESIGN.md", Content: "b"}}},
		"file as dir": {Kind: KindIntent, Edits: []Edit{{Path: "folio/a", Content: "a"}, {Path: "folio/a/b", Content: "b"}}},
		"deep as dir": {Kind: KindIntent, Edits: []Edit{{Path: "folio/a/b/c", Content: "a"}, {Path: "folio/a/b", Content: "b"}}},
		"huge intent": {Kind: KindIntent, Edits: []Edit{{Path: "folio/big.md", Content: strings.Repeat("x", maxEditBytes+1)}}},
	} {
		g := newFixture(t, nil)
		d := d
		g.classifier.decide = func(Nit) (Decision, error) { return d, nil }
		if r := g.owner(goodNit); r.Status != StatusTriage || r.Reason != "decision" || len(g.keysUnder("intent/")) != 0 || g.h.Pending() != 0 {
			t.Fatalf("%s: %+v", reason, r)
		}
		if kept := g.inbox.Entries(); len(kept) != 1 || !kept[0].Owner {
			t.Fatalf("%s: inbox %+v", reason, kept)
		}
	}
	// A classifier that fails closes the same way: the nit is kept, nothing is routed.
	g := newFixture(t, nil)
	g.classifier.decide = func(Nit) (Decision, error) { return Decision{}, errors.New("model unavailable") }
	if r := g.owner(goodNit); r.Code != http.StatusAccepted || r.Status != StatusTriage || r.Reason != "classifier" || g.h.Pending() != 0 || len(g.keysUnder("intent/")) != 0 {
		t.Fatalf("classifier failure: %+v", r)
	}
	if kept := g.inbox.Entries(); len(kept) != 1 || !kept[0].Owner || kept[0].Reason != "classifier" || string(kept[0].Body) != goodNitKept {
		t.Fatalf("inbox %+v", kept)
	}
	// A reconcile order that would carry a secret into the store is not written.
	g = newFixture(t, nil)
	g.classifier.decide = func(Nit) (Decision, error) {
		return Decision{Kind: KindViolation, Clause: "DESIGN.md §2", Brief: fakeSecret()}, nil
	}
	if r := g.owner(goodNit); r.Status != StatusTriage || r.Reason != "secret-gate" || len(g.keysUnder("intent/")) != 0 {
		t.Fatalf("secret in a brief: %+v", r)
	}
}

func TestM2_3_OwnerNitMustBeWellFormed(t *testing.T) {
	bad := map[string]string{
		"not json":      "{",
		"no text":       `{"schema":"chimera.nit/v1","url":"https://app.example.com/","selector":"#a","viewport":{"w":1,"h":1,"dpr":1},"text":"  "}`,
		"long text":     nitText(strings.Repeat("é", MaxText+1)),
		"relative url":  `{"url":"/orders","text":"t"}`,
		"script url":    `{"url":"javascript:alert(1)","text":"t"}`,
		"long selector": `{"url":"https://app.example.com/","selector":"` + strings.Repeat("a", MaxSelector+1) + `","text":"t"}`,
		"bad viewport":  `{"url":"https://app.example.com/","viewport":{"w":-1,"h":1,"dpr":1},"text":"t"}`,
		"other schema":  `{"schema":"chimera.nit/v9","url":"https://app.example.com/","text":"t"}`,
	}
	for name, body := range bad {
		f := newFixture(t, nil)
		r := f.owner(body)
		if r.Code != http.StatusBadRequest || r.Status != StatusInvalid || r.Reason == "" {
			t.Fatalf("%s: %+v", name, r)
		}
		f.untouched(name)
		if len(f.inbox.Entries()) != 0 {
			t.Fatalf("%s: kept", name)
		}
	}
	f := newFixture(t, nil)
	if r := f.owner(nitText(strings.Repeat("é", MaxText))); r.Status != StatusFolio {
		t.Fatalf("text at the limit: %+v", r)
	}
}

func TestM2_3_MethodRouteSizeAndCORS(t *testing.T) {
	f := newFixture(t, func(o *Options, _ *Deps) { o.AllowedOrigins = []string{"https://app.example.com"} })
	do := func(method, path, origin, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:1"
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		f.h.ServeHTTP(rec, req)
		return rec
	}
	for _, path := range []string{"/", "/v1/inlet", "/v1/inlet/nit/", "/v1/inlet/nits", "/healthz", "/chimera-nit.js"} {
		if rec := do(http.MethodPost, path, "", "x"); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d", path, rec.Code)
		}
		if rec := do(http.MethodGet, path, "", ""); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d", path, rec.Code)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		rec := do(m, Path, "", "")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST, OPTIONS" {
			t.Errorf("%s: %d Allow=%q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	// Body cap: 16 KiB is accepted, one byte more is refused before anything is appended.
	if rec := do(http.MethodPost, Path, "", strings.Repeat("a", MaxBody)); rec.Code != http.StatusAccepted {
		t.Fatalf("at the cap: %d", rec.Code)
	}
	if rec := do(http.MethodPost, Path, "", strings.Repeat("a", MaxBody+1)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over the cap: %d", rec.Code)
	}
	if n := len(f.inbox.Entries()); n != 1 {
		t.Fatalf("%d entries after an oversized body", n)
	}
	// Preflight: only for allowed origins, echoing the exact origin.
	rec := do(http.MethodOptions, Path, "https://app.example.com", "")
	hd := rec.Header()
	if rec.Code != http.StatusNoContent || hd.Get("Access-Control-Allow-Origin") != "https://app.example.com" || hd.Get("Access-Control-Allow-Credentials") != "true" ||
		hd.Get("Access-Control-Allow-Headers") != "Content-Type" || hd.Get("Vary") != "Origin" || hd.Get("Access-Control-Allow-Methods") != "POST" {
		t.Fatalf("preflight: %d %v", rec.Code, hd)
	}
	for _, origin := range []string{"https://evil.example", "", "https://app.example.com.evil.example", "http://app.example.com", "https://app.example.com:8443", "null"} {
		rec := do(http.MethodOptions, Path, origin, "")
		if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("preflight from %q: %d %v", origin, rec.Code, rec.Header())
		}
	}
	// The POST itself carries the same headers for an allowed origin, and none otherwise.
	rec = do(http.MethodPost, Path, "https://app.example.com", "x")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || rec.Header().Get("Access-Control-Allow-Credentials") != "true" || rec.Header().Get("Vary") != "Origin" {
		t.Fatalf("POST CORS: %v", rec.Header())
	}
	before := len(f.inbox.Entries())
	for _, origin := range []string{"https://evil.example", "https://app.example.com:8443", "null"} {
		rec = do(http.MethodPost, Path, origin, "x")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"status":"forbidden-origin"`) || rec.Header().Get("Access-Control-Allow-Origin") != "" ||
			rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("POST from %q: %d %s %v", origin, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	if len(f.inbox.Entries()) != before {
		t.Fatal("a refused origin was appended to the inbox")
	}
	f.untouched("routes")
}

func TestM2_3_OptionsFromConfigRefusesAnInletThatCannotVerifyOwners(t *testing.T) {
	full := func() *config.Config {
		c := &config.Config{}
		c.Tenant.OwnerEmails = []string{testOwner}
		c.Inlet = config.Inlet{Repo: testRepo, Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://id.example.com/jwks.json", TokenHeader: "X-Edge-Jwt",
			TokenCookie: "edge_session", Debounce: "90s", DailyCap: 7, PreviewOrigins: []string{"https://*.preview.example.com"}, BotActors: []string{"bot@example.com"},
			TriagePerMinute: 9, AllowedOrigins: []string{"https://app.example.com"}, FolioBranch: "folio/nits", Target: "main",
			EmailVerified: "if-present", ClientIPHeader: "X-Edge-Client-IP",
			Classifier: config.Harness{Command: []string{"example-classifier", "--json"}, Timeout: "45s"}}
		c.Verifiers = map[string]config.Verifier{"default": {Command: []string{"go", "test", "./..."}, Timeout: "10m"}, "strict": {Command: []string{"make", "verify"}}}
		return c
	}
	o, err := OptionsFromConfig(full())
	if err != nil {
		t.Fatal(err)
	}
	if o.Repo != testRepo || o.Issuer != testIssuer || o.Audience != testAudience || o.JWKSURL == "" || o.TokenHeader != "X-Edge-Jwt" || o.TokenCookie != "edge_session" ||
		o.Debounce != 90*time.Second || o.DailyCap != 7 || o.TriagePerMinute != 9 || o.FolioBranch != "folio/nits" || o.Target != "main" ||
		o.EmailVerified != "if-present" || o.ClientIPHeader != "X-Edge-Client-IP" ||
		o.ClassifierTimeout != 45*time.Second || strings.Join(o.ClassifierCommand, " ") != "example-classifier --json" ||
		strings.Join(o.Verifier.Command, " ") != "go test ./..." || len(o.OwnerEmails) != 1 || len(o.PreviewOrigins) != 1 || len(o.BotActors) != 1 || len(o.AllowedOrigins) != 1 {
		t.Fatalf("%+v", o)
	}
	// Defaults, and fallbacks to the land and forge blocks.
	c := full()
	c.Inlet.Debounce, c.Inlet.DailyCap, c.Inlet.TriagePerMinute, c.Inlet.FolioBranch, c.Inlet.Classifier.Timeout = "", 0, 0, "", ""
	c.Inlet.Repo, c.Inlet.Target, c.Forge.Repo, c.Land.Target, c.Land.Verifier = "", "", "acme/gadget", "trunk", "strict"
	c.Inlet.JWKSURL, c.Inlet.JWKSFile = "", "/etc/chimera/jwks.json"
	o, err = OptionsFromConfig(c)
	if err != nil || o.Debounce != DefaultDebounce || o.DailyCap != DefaultDailyCap || o.TriagePerMinute != DefaultTriagePerMinute || o.FolioBranch != DefaultFolioBranch ||
		o.ClassifierTimeout != DefaultClassifierTimeout || o.Repo != "acme/gadget" || o.Target != "trunk" || strings.Join(o.Verifier.Command, " ") != "make verify" || o.JWKSFile == "" {
		t.Fatalf("%+v %v", o, err)
	}
	for name, breakIt := range map[string]func(*config.Config){
		"inlet.issuer":          func(c *config.Config) { c.Inlet.Issuer = "" },
		"inlet.audience":        func(c *config.Config) { c.Inlet.Audience = "" },
		"inlet.email_verified":  func(c *config.Config) { c.Inlet.EmailVerified = "never" },
		"inlet.folio_branch":    func(c *config.Config) { c.Inlet.FolioBranch = "main" },
		"inlet.allowed_origins": func(c *config.Config) { c.Inlet.AllowedOrigins = []string{"https://*.example.com"} },
		"inlet.preview_origins": func(c *config.Config) { c.Inlet.PreviewOrigins = []string{"pr-*.example.com"} },
		"inlet.jwks_url":        func(c *config.Config) { c.Inlet.JWKSURL = "http://id.example.com/jwks.json" },
		"jwks_file":             func(c *config.Config) { c.Inlet.JWKSURL = "" },
		"tenant.owner_emails":   func(c *config.Config) { c.Tenant.OwnerEmails = []string{" "} },
		"inlet.repo":            func(c *config.Config) { c.Inlet.Repo = "" },
		"inlet.target":          func(c *config.Config) { c.Inlet.Target = "" },
		"inlet.debounce":        func(c *config.Config) { c.Inlet.Debounce = "soon" },
		"classifier.timeout":    func(c *config.Config) { c.Inlet.Classifier.Timeout = "-1s" },
	} {
		c := full()
		breakIt(c)
		if _, err := OptionsFromConfig(c); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	// New refuses the same things, and a handler with nowhere to route.
	keys(t)
	fk := forge.NewFake()
	deps := Deps{Store: objstore.NewDir(t.TempDir()), Forge: fk, Classifier: &fakeClassifier{}, FolioPR: &BranchPR{}}
	ok := Options{Repo: testRepo, OwnerEmails: []string{testOwner}, Issuer: testIssuer, Audience: testAudience, JWKS: testJWKS, Target: "main"}
	if _, err := New(ok, deps); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Options, *Deps){
		"repo":                  func(o *Options, _ *Deps) { o.Repo = "" },
		"issuer":                func(o *Options, _ *Deps) { o.Issuer = "" },
		"audience":              func(o *Options, _ *Deps) { o.Audience = "" },
		"email_verified":        func(o *Options, _ *Deps) { o.EmailVerified = "sometimes" },
		"owner email":           func(o *Options, _ *Deps) { o.OwnerEmails = []string{"\u212Aim@example.com"} },
		"same branch":           func(o *Options, _ *Deps) { o.FolioBranch = "refs/heads/main" },
		"wildcards":             func(o *Options, _ *Deps) { o.AllowedOrigins = []string{"*"} },
		"scheme://host":         func(o *Options, _ *Deps) { o.AllowedOrigins = []string{"https://app.example.com/app"} },
		"without a path":        func(o *Options, _ *Deps) { o.PreviewOrigins = []string{"https://preview.example.com/app"} },
		"http:// or https://":   func(o *Options, _ *Deps) { o.PreviewOrigins = []string{"*.preview.example.com"} },
		"port must be a number": func(o *Options, _ *Deps) { o.PreviewOrigins = []string{"https://*.example.com:*"} },
		"owner":                 func(o *Options, _ *Deps) { o.OwnerEmails = nil },
		"jwks":                  func(o *Options, _ *Deps) { o.JWKS = nil },
		"jwks: ":                func(o *Options, _ *Deps) { o.JWKS = []byte(`{"keys":[{"kty":"oct","k":"AAAA"}]}`) },
		"jwks file":             func(o *Options, _ *Deps) { o.JWKS, o.JWKSFile = nil, "/nonexistent/jwks.json" },
		"target":                func(o *Options, _ *Deps) { o.Target = "" },
		"store":                 func(_ *Options, d *Deps) { d.Store = nil },
		"forge":                 func(_ *Options, d *Deps) { d.Forge = nil },
		"folio":                 func(_ *Options, d *Deps) { d.FolioPR = nil },
		"classifier":            func(_ *Options, d *Deps) { d.Classifier = nil },
	} {
		o, d := ok, deps
		mut(&o, &d)
		if _, err := New(o, d); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(name)) {
			t.Errorf("New without %s: err=%v", name, err)
		}
	}
}
