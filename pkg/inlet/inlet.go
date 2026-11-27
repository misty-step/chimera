// Package inlet turns authenticated feedback into Intent (PRODUCT.md §2.6).
// It is one endpoint, POST /v1/inlet/nit, served by Handler.
//
// The order of work per request is the security property:
//
//  1. No token: the raw body is appended to the rate-limited triage inbox.
//     Nothing is parsed, verified, classified, or pushed.
//  2. A token that does not verify, or whose verified email is not an owner's,
//     is treated exactly like no token.
//  3. An owner nit passes the origin loop guard, then the daily cap, and only
//     then reaches the classifier — the only model call there is.
//  4. A Folio violation becomes a task Intent (a reconcile order); the Folio
//     is untouched. New or changed intent joins the one open Folio-only pull
//     request, behind the path fence and the debounce window.
package inlet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/objstore"
)

// Path is the one route the inlet serves.
const Path = "/v1/inlet/nit"

// Schema identifies every response body.
const Schema = "chimera.inlet/v1"

// MaxBody caps a request body; larger requests get 413.
const MaxBody = 16 << 10

// Defaults applied by New.
const (
	DefaultDebounce        = 10 * time.Minute
	DefaultDailyCap        = 20
	DefaultTriagePerMinute = 6
)

// Response statuses.
const (
	StatusTask        = "task"         // 201: a reconcile order was created
	StatusFolio       = "folio"        // 202: joined the Folio-only pull request
	StatusDropped     = "dropped"      // 202: the loop guard dropped it
	StatusCapped      = "capped"       // 429: the daily cap is spent
	StatusTriage      = "triage"       // 202: appended to the triage inbox
	StatusRateLimited = "rate-limited" // 429: the triage inbox refused it
	StatusInvalid     = "invalid"      // 400: an owner's nit is malformed
)

// Response is the body of every answer.
type Response struct {
	Schema  string `json:"schema"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Intent  string `json:"intent,omitempty"`
	Clause  string `json:"clause,omitempty"`
	Branch  string `json:"branch,omitempty"`
	Ruling  string `json:"ruling,omitempty"`
	Pending int    `json:"pending,omitempty"`
}

// Options configure a Handler. OptionsFromConfig builds them from chimera.yaml.
type Options struct {
	Repo        string   // repository the nits are about
	OwnerEmails []string // verified emails that make a bearer an owner

	Issuer   string // required "iss" of the edge token
	Audience string // required "aud"; empty skips the check
	JWKS     []byte // a JWKS document; wins over JWKSFile and JWKSURL
	JWKSFile string
	JWKSURL  string

	TokenHeader string // edge header carrying the token, besides Authorization: Bearer
	TokenCookie string // edge session cookie carrying the token
	// ClientIPHeader names a header the edge sets to the client address, for
	// the triage rate limit; empty means the connection's remote address.
	ClientIPHeader string

	Debounce        time.Duration // window before the Folio PR is updated
	DailyCap        int           // owner nits classified per repo per UTC day
	TriagePerMinute int           // triage appends per client per minute
	PreviewOrigins  []string      // origins of Chimera's own previews (loop guard)
	BotActors       []string      // actors that are bots (loop guard)
	AllowedOrigins  []string      // cross-origin pages that may post (CORS)

	FolioBranch string               // head of the one open Folio-only PR
	Target      string               // branch the Folio PR proposes to change
	Verifier    capsule.TaskVerifier // verifier a reconcile order names

	ClassifierCommand []string // used when Deps.Classifier is nil
	ClassifierTimeout time.Duration
}

// Deps are the services a Handler needs.
type Deps struct {
	Store      objstore.Store // daily-cap slots, task Intents, the default inbox
	Forge      forge.Forge    // the target's head, for a reconcile order's base
	Classifier Classifier     // nil means CommandClassifier from the options
	Inbox      Inbox          // nil means StoreInbox
	FolioPR    FolioPR        // the one open Folio-only pull request
	// Folio reads the Folio the classifier judges against; nil means the
	// classifier is given an empty snapshot.
	Folio      func(ctx context.Context) (FolioSnapshot, error)
	Now        func() time.Time // nil means time.Now
	HTTPClient *http.Client     // fetches JWKSURL; nil means a 10s-timeout client
	// AfterFunc schedules the debounce flush; nil means time.AfterFunc. A
	// test passes a no-op and calls Handler.Tick.
	AfterFunc func(d time.Duration, f func()) (stop func())
	// Log receives one line per background failure; nil discards them.
	Log func(format string, args ...any)
}

// Handler serves POST /v1/inlet/nit.
type Handler struct {
	opts       Options
	owners     map[string]bool
	verifier   *Verifier
	limiter    *limiter
	coalescer  *Coalescer
	store      objstore.Store
	forge      forge.Forge
	classifier Classifier
	inbox      Inbox
	folio      func(ctx context.Context) (FolioSnapshot, error)
	now        func() time.Time
	log        func(format string, args ...any)

	// ownerMu serializes classification, so each nit is judged against the
	// Folio as the previous one left it.
	ownerMu sync.Mutex
	capMu   sync.Mutex
	capDay  string
	capNext int
}

// New builds a Handler. It refuses to start an inlet that could not tell an
// owner from anyone else, or that has nowhere to route an owner's nit.
func New(opts Options, deps Deps) (*Handler, error) {
	if strings.TrimSpace(opts.Repo) == "" {
		return nil, fmt.Errorf("inlet: repo is required")
	}
	if opts.Issuer == "" {
		return nil, fmt.Errorf("inlet: issuer is required")
	}
	owners := map[string]bool{}
	for _, e := range opts.OwnerEmails {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			owners[e] = true
		}
	}
	if len(owners) == 0 {
		return nil, fmt.Errorf("inlet: no owner emails configured")
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("inlet: target is required")
	}
	if deps.Store == nil || deps.Forge == nil || deps.FolioPR == nil {
		return nil, fmt.Errorf("inlet: store, forge, and folio pull request are required")
	}
	h := &Handler{opts: opts, owners: owners, store: deps.Store, forge: deps.Forge, classifier: deps.Classifier, inbox: deps.Inbox,
		folio: deps.Folio, now: deps.Now, log: deps.Log}
	if h.now == nil {
		h.now = time.Now
	}
	if h.log == nil {
		h.log = func(string, ...any) {}
	}
	var keys KeySource
	switch {
	case len(opts.JWKS) > 0:
		set, err := ParseJWKS(opts.JWKS)
		if err != nil {
			return nil, fmt.Errorf("inlet: %w", err)
		}
		keys = set
	case opts.JWKSFile != "":
		raw, err := os.ReadFile(opts.JWKSFile)
		if err != nil {
			return nil, fmt.Errorf("inlet: jwks file unreadable")
		}
		set, err := ParseJWKS(raw)
		if err != nil {
			return nil, fmt.Errorf("inlet: %w", err)
		}
		keys = set
	case opts.JWKSURL != "":
		keys = &RemoteKeys{URL: opts.JWKSURL, Client: deps.HTTPClient, Now: h.now}
	default:
		return nil, fmt.Errorf("inlet: no jwks configured")
	}
	h.verifier = &Verifier{Issuer: opts.Issuer, Audience: opts.Audience, Keys: keys, Now: h.now}
	if h.classifier == nil {
		if len(opts.ClassifierCommand) == 0 {
			return nil, fmt.Errorf("inlet: no classifier configured")
		}
		h.classifier = CommandClassifier{Argv: opts.ClassifierCommand, Timeout: opts.ClassifierTimeout}
	}
	if h.inbox == nil {
		h.inbox = &StoreInbox{Store: deps.Store, Repo: opts.Repo}
	}
	if h.opts.Debounce <= 0 {
		h.opts.Debounce = DefaultDebounce
	}
	if h.opts.DailyCap <= 0 {
		h.opts.DailyCap = DefaultDailyCap
	}
	if h.opts.TriagePerMinute <= 0 {
		h.opts.TriagePerMinute = DefaultTriagePerMinute
	}
	if h.opts.FolioBranch == "" {
		h.opts.FolioBranch = DefaultFolioBranch
	}
	h.limiter = newLimiter(h.opts.TriagePerMinute)
	after := deps.AfterFunc
	if after == nil {
		after = func(d time.Duration, f func()) func() {
			t := time.AfterFunc(d, f)
			return func() { t.Stop() }
		}
	}
	h.coalescer = &Coalescer{PR: deps.FolioPR, Window: h.opts.Debounce, Now: h.now, AfterFunc: after, OnFlush: func(_ Update, err error) {
		if err != nil {
			h.log("inlet: folio pull request not updated: %v", err)
		}
	}}
	return h, nil
}

// Tick flushes the Folio batch if its debounce window has elapsed at now.
func (h *Handler) Tick(ctx context.Context, now time.Time) (bool, error) {
	return h.coalescer.Tick(ctx, now)
}

// Flush updates the Folio pull request now with every waiting proposal.
func (h *Handler) Flush(ctx context.Context) (Update, error) { return h.coalescer.Flush(ctx) }

// Pending reports how many proposals wait for the debounce window.
func (h *Handler) Pending() int { return h.coalescer.Pending() }

func (h *Handler) write(w http.ResponseWriter, code int, res Response) {
	res.Schema = Schema
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(res)
}

// cors answers for origins in AllowedOrigins only, echoing the exact origin.
func (h *Handler) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	if origin == "" || !matchAnyOrigin(h.opts.AllowedOrigins, origin) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	return true
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		h.write(w, http.StatusNotFound, Response{Status: "not-found"})
		return
	}
	switch r.Method {
	case http.MethodPost:
	case http.MethodOptions:
		if !h.cors(w, r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.Header().Set("Allow", "POST, OPTIONS")
		h.write(w, http.StatusMethodNotAllowed, Response{Status: "method-not-allowed"})
		return
	}
	h.cors(w, r)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: "unreadable body"})
		return
	}
	if len(body) > MaxBody {
		h.write(w, http.StatusRequestEntityTooLarge, Response{Status: "too-large"})
		return
	}
	token := h.token(r)
	if token == "" {
		// No credentials: append and stop. Not one byte of the body is parsed.
		h.triage(w, r, body)
		return
	}
	id, err := h.verifier.Verify(r.Context(), token)
	if err != nil || !h.owners[id.Email] {
		// Indistinguishable from the anonymous answer: no oracle.
		h.triage(w, r, body)
		return
	}
	h.owner(w, r, body, id)
}

// token finds the edge token: Authorization: Bearer, then the configured
// header, then the configured cookie.
func (h *Handler) token(r *http.Request) string {
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "Bearer ") {
		if t := strings.TrimSpace(a[7:]); t != "" {
			return t
		}
	}
	if h.opts.TokenHeader != "" {
		if t := strings.TrimSpace(r.Header.Get(h.opts.TokenHeader)); t != "" {
			return t
		}
	}
	if h.opts.TokenCookie != "" {
		if c, err := r.Cookie(h.opts.TokenCookie); err == nil {
			return strings.TrimSpace(c.Value)
		}
	}
	return ""
}

func (h *Handler) client(r *http.Request) string {
	if h.opts.ClientIPHeader != "" {
		if v := strings.TrimSpace(strings.Split(r.Header.Get(h.opts.ClientIPHeader), ",")[0]); v != "" {
			return v
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// triage is the whole path for everyone who is not an owner: a rate-limit
// check and one append.
func (h *Handler) triage(w http.ResponseWriter, r *http.Request, body []byte) {
	now := h.now()
	if !h.limiter.allow(h.client(r), now) {
		w.Header().Set("Retry-After", "60")
		h.write(w, http.StatusTooManyRequests, Response{Status: StatusRateLimited})
		return
	}
	if err := h.inbox.Append(r.Context(), Entry{Schema: EntrySchema, ReceivedAt: now.UTC(), Body: body}); err != nil {
		h.write(w, http.StatusServiceUnavailable, Response{Status: "unavailable"})
		return
	}
	h.write(w, http.StatusAccepted, Response{Status: StatusTriage})
}

// keep puts an owner nit that could not be routed into the triage inbox, so
// a failure downstream never loses what an owner said.
func (h *Handler) keep(w http.ResponseWriter, r *http.Request, body []byte, reason string) {
	if err := h.inbox.Append(r.Context(), Entry{Schema: EntrySchema, ReceivedAt: h.now().UTC(), Owner: true, Reason: reason, Body: body}); err != nil {
		h.write(w, http.StatusServiceUnavailable, Response{Status: "unavailable"})
		return
	}
	h.write(w, http.StatusAccepted, Response{Status: StatusTriage, Reason: reason})
}

// NitKey is the object-store key of the n-th owner nit of a UTC day. Its
// existence is the claim on one unit of the daily cap.
func NitKey(repo, day string, n int) string {
	return fmt.Sprintf("inlet/%s/nits/%s/%04d.json", repo, day, n)
}

// DecisionKey is the object-store key of what became of that nit.
func DecisionKey(repo, day string, n int) string {
	return fmt.Sprintf("inlet/%s/nits/%s/%04d.decision.json", repo, day, n)
}

// claim takes one unit of the day's cap by creating the next free slot
// object. The conditional PUT decides, so handlers sharing a store share
// the cap.
func (h *Handler) claim(ctx context.Context, now time.Time, nit Nit) (n int, ok bool, err error) {
	day := now.UTC().Format("2006-01-02")
	raw, err := json.Marshal(struct {
		Schema     string    `json:"schema"`
		ReceivedAt time.Time `json:"received_at"`
		Actor      string    `json:"actor"`
		Nit        Nit       `json:"nit"`
	}{"chimera.inlet.nit/v1", now.UTC(), "owner", nit})
	if err != nil {
		return 0, false, fmt.Errorf("nit: cannot encode")
	}
	h.capMu.Lock()
	defer h.capMu.Unlock()
	if h.capDay != day {
		h.capDay, h.capNext = day, 1
	}
	for h.capNext <= h.opts.DailyCap {
		n := h.capNext
		created, err := h.store.Put(ctx, NitKey(h.opts.Repo, day, n), raw)
		if err != nil {
			return 0, false, err
		}
		h.capNext++
		if created {
			return n, true, nil
		}
	}
	return 0, false, nil
}

func (h *Handler) record(ctx context.Context, day string, n int, res Response, d Decision) {
	raw, err := json.Marshal(struct {
		Schema   string   `json:"schema"`
		Response Response `json:"response"`
		Kind     string   `json:"kind,omitempty"`
		Summary  string   `json:"summary,omitempty"`
	}{"chimera.inlet.decision/v1", res, d.Kind, oneLine(d.Summary, 200)})
	if err == nil {
		if _, err := h.store.Put(ctx, DecisionKey(h.opts.Repo, day, n), raw); err != nil {
			h.log("inlet: decision for nit %s-%04d not recorded: %v", day, n, err)
		}
	}
}

// owner routes a verified owner's nit: loop guard, daily cap, classifier.
func (h *Handler) owner(w http.ResponseWriter, r *http.Request, body []byte, id Identity) {
	ctx := r.Context()
	var nit Nit
	if err := json.Unmarshal(body, &nit); err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: "body is not a nit"})
		return
	}
	if err := nit.Validate(); err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: err.Error()})
		return
	}
	// Origin loop guard: Chimera does not answer its own previews or bots.
	if matchAnyOrigin(h.opts.PreviewOrigins, r.Header.Get("Origin")) || matchAnyOrigin(h.opts.PreviewOrigins, nit.URL) ||
		isBot(h.opts.BotActors, id.Email) || isBot(h.opts.BotActors, id.Subject) {
		h.write(w, http.StatusAccepted, Response{Status: StatusDropped, Reason: "loop-guard"})
		return
	}

	h.ownerMu.Lock()
	defer h.ownerMu.Unlock()
	now := h.now()
	day := now.UTC().Format("2006-01-02")
	n, ok, err := h.claim(ctx, now, nit)
	if err != nil {
		h.write(w, http.StatusServiceUnavailable, Response{Status: "unavailable"})
		return
	}
	if !ok {
		w.Header().Set("Retry-After", "3600")
		h.write(w, http.StatusTooManyRequests, Response{Status: StatusCapped})
		return
	}
	fail := func(reason string, d Decision) {
		h.record(ctx, day, n, Response{Schema: Schema, Status: StatusTriage, Reason: reason}, d)
		h.keep(w, r, body, reason)
	}

	var snapshot FolioSnapshot
	if h.folio != nil {
		if snapshot, err = h.folio(ctx); err != nil {
			fail("folio-unavailable", Decision{})
			return
		}
		// What earlier nits proposed inside this window is part of the Folio
		// the next one is judged against.
		if c, ok := h.coalescer.Proposed("PRODUCT.md"); ok {
			snapshot.Product = string(c)
		}
		if c, ok := h.coalescer.Proposed("DESIGN.md"); ok {
			snapshot.Design = string(c)
		}
	}
	decision, err := h.classifier.Classify(ctx, nit, snapshot)
	if err != nil {
		fail("classifier", Decision{})
		return
	}
	if err := decision.Validate(); err != nil {
		if errors.Is(err, errFence) {
			fail("path-fence", Decision{Kind: decision.Kind})
		} else {
			fail("decision", Decision{Kind: decision.Kind})
		}
		return
	}
	if strings.TrimSpace(decision.Summary) == "" {
		decision.Summary = nit.Text
	}

	switch decision.Kind {
	case KindViolation:
		base, err := h.forge.Head(ctx, h.opts.Target)
		if err != nil {
			fail("target-unavailable", decision)
			return
		}
		brief := strings.TrimSpace(decision.Brief)
		if brief == "" {
			brief = strings.TrimSpace(nit.Text)
		}
		intent, err := capsule.PutTask(ctx, h.store, capsule.TaskManifest{
			Brief: brief + "\n\n" + nitContext(nit), Repo: h.opts.Repo, BaseSHA: string(base), Verifier: h.opts.Verifier,
			Clause: strings.TrimSpace(decision.Clause), Acceptance: decision.Acceptance,
		})
		if err != nil {
			fail("store", decision)
			return
		}
		res := Response{Status: StatusTask, Intent: intent, Clause: strings.TrimSpace(decision.Clause)}
		h.record(ctx, day, n, res, decision)
		h.write(w, http.StatusCreated, res)
	case KindIntent:
		nid := fmt.Sprintf("%s-%04d", now.UTC().Format("20060102"), n)
		ruling := "folio/rulings/nit-" + nid + ".md"
		p := Proposal{ID: nid, ReceivedAt: now.UTC(), Summary: oneLine(decision.Summary, 200),
			Files: []ProposalFile{{Path: ruling, Content: rulingFile(nid, now, nit, decision)}}}
		for _, e := range decision.Edits {
			f := ProposalFile{Path: e.Path, Content: []byte(e.Content)}
			if h.folio != nil {
				switch e.Path {
				case "PRODUCT.md":
					f.Seen = sum([]byte(snapshot.Product))
				case "DESIGN.md":
					f.Seen = sum([]byte(snapshot.Design))
				}
			}
			p.Files = append(p.Files, f)
		}
		// Belt and braces: the fence was checked by Validate; check what is
		// actually about to be queued, ruling included.
		for _, f := range p.Files {
			if !InFence(f.Path) {
				fail("path-fence", decision)
				return
			}
		}
		pending := h.coalescer.Add(p)
		res := Response{Status: StatusFolio, Branch: forge.Branch(h.opts.FolioBranch), Ruling: ruling, Pending: pending}
		h.record(ctx, day, n, res, decision)
		h.write(w, http.StatusAccepted, res)
	}
}

// nitContext renders where a nit was raised, for a brief or a ruling.
func nitContext(n Nit) string {
	return fmt.Sprintf("Context:\n- url: %q\n- selector: %q\n- viewport: %dx%d @%gx\n", n.URL, n.Selector, n.Viewport.W, n.Viewport.H, n.Viewport.DPR)
}

// rulingFile renders an owner nit as an owner ruling (folio/rulings/*.md is
// a T0 document, PRODUCT.md §2.3). It names the owner only as "owner".
func rulingFile(id string, at time.Time, n Nit, d Decision) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Owner nit %s\n\n", id)
	fmt.Fprintf(&b, "- received: %s\n- actor: owner\n", at.UTC().Format(time.RFC3339))
	if c := strings.TrimSpace(d.Clause); c != "" {
		fmt.Fprintf(&b, "- clause: %s\n", oneLine(c, 200))
	}
	fmt.Fprintf(&b, "- url: %q\n- selector: %q\n- viewport: %dx%d @%gx\n", n.URL, n.Selector, n.Viewport.W, n.Viewport.H, n.Viewport.DPR)
	fmt.Fprintf(&b, "\n## Summary\n\n%s\n\n## Text\n\n%s\n", oneLine(d.Summary, 200), strings.TrimSpace(n.Text))
	return []byte(b.String())
}
