// Package inlet turns authenticated feedback into Intent (PRODUCT.md §2.6).
// It is one endpoint, POST /v1/inlet/nit, served by Handler.
//
// The order of work per request is the security property:
//
//  0. Before anything else, and the same for everyone: the body must be
//     declared application/json (so a cross-site page cannot post without a
//     preflight) and an Origin, when present, must be the inlet's own or one
//     named in AllowedOrigins. A session the browser attaches is never enough.
//  1. The token is read from headers alone. No token: the request is
//     rate-limited, and only then is its body read and appended to the triage
//     inbox. Nothing is parsed, verified, classified, or pushed.
//  2. A token that does not verify, or whose verified email is not an owner's,
//     is treated exactly like no token. Verifying never leaves the process.
//  3. An owner nit passes the origin loop guard, then the daily cap, and only
//     then reaches the classifier — the only model call there is.
//  4. A Folio violation becomes a task Intent (a reconcile order); the Folio
//     is untouched. New or changed intent joins the one open Folio-only pull
//     request, behind the path fence and the debounce window.
//
// The handler bounds what it reads (MaxBody) but sets no deadlines: read and
// write timeouts belong to the http.Server that hosts it.
package inlet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
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

	StatusUnsupported     = "unsupported-media-type" // 415: the body is not declared application/json
	StatusForbiddenOrigin = "forbidden-origin"       // 403: a page that may not post here
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
	Audience string // required "aud" of the edge token
	JWKS     []byte // a JWKS document; wins over JWKSFile and JWKSURL
	JWKSFile string
	JWKSURL  string // https (http on loopback only); loaded at start, refreshed in the background
	// EmailVerified is "required" (the default: the token must carry
	// email_verified: true) or "if-present" (an absent claim is accepted, for
	// edges that assert the email by issuance). A present claim that is not
	// true always refuses.
	EmailVerified string

	TokenHeader string // edge header carrying the token, besides Authorization: Bearer
	TokenCookie string // edge session cookie carrying the token
	// ClientIPHeader names a header the trusted edge sets (or appends) the
	// client address to, for the triage rate limit; its rightmost address is
	// used. Empty means the connection's remote address.
	ClientIPHeader string

	Debounce        time.Duration // window before the Folio PR is updated
	DailyCap        int           // owner nits classified per repo per UTC day
	TriagePerMinute int           // triage appends per client per minute
	PreviewOrigins  []string      // origins of Chimera's own previews (loop guard)
	BotActors       []string      // actors that are bots (loop guard)
	AllowedOrigins  []string      // exact origins of other pages that may post (CORS); no wildcards

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
	Folio func(ctx context.Context) (FolioSnapshot, error)
	// Gate is the secret gate run over everything bound for Git or a task
	// Intent; nil means the built-in rules alone.
	Gate       *secretscan.Scanner
	Now        func() time.Time // nil means time.Now
	HTTPClient *http.Client     // fetches JWKSURL; nil means the default transport
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
	allowed    []origin
	previews   []previewPattern
	verifier   *Verifier
	remote     *RemoteKeys
	limiter    *limiter
	coalescer  *Coalescer
	store      objstore.Store
	forge      forge.Forge
	classifier Classifier
	inbox      Inbox
	gate       *secretscan.Scanner
	folio      func(ctx context.Context) (FolioSnapshot, error)
	now        func() time.Time
	log        func(format string, args ...any)

	// ownerMu serializes classification, so each nit is judged against the
	// Folio as the previous one left it.
	ownerMu sync.Mutex
	capMu   sync.Mutex
	capDay  string
	capNext int
	// bodies keeps the request body of every proposal still waiting, so a
	// proposal the pull request refuses can be put in the triage inbox.
	bodyMu sync.Mutex
	bodies map[string][]byte
}

// New builds a Handler. It refuses to start an inlet that could not tell an
// owner from anyone else, or that has nowhere to route an owner's nit. With
// a JWKS URL it loads the keys before returning and fails if it cannot.
// Proposals an earlier process accepted but had not yet pushed are queued
// again from the store.
func New(opts Options, deps Deps) (*Handler, error) {
	if strings.TrimSpace(opts.Repo) == "" {
		return nil, fmt.Errorf("inlet: repo is required")
	}
	if opts.Issuer == "" {
		return nil, fmt.Errorf("inlet: issuer is required")
	}
	if opts.Audience == "" {
		return nil, fmt.Errorf("inlet: audience is required; a token minted for another party must not make an owner")
	}
	switch opts.EmailVerified {
	case "", "required", "if-present":
	default:
		return nil, fmt.Errorf("inlet: email_verified must be required or if-present")
	}
	owners := map[string]bool{}
	for _, e := range opts.OwnerEmails {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		email, ok := asciiEmail(e)
		if !ok {
			return nil, fmt.Errorf("inlet: an owner email is not a plain ASCII address")
		}
		owners[email] = true
	}
	if len(owners) == 0 {
		return nil, fmt.Errorf("inlet: no owner emails configured")
	}
	if opts.Target == "" {
		return nil, fmt.Errorf("inlet: target is required")
	}
	if opts.FolioBranch == "" {
		opts.FolioBranch = DefaultFolioBranch
	}
	if forge.Branch(opts.FolioBranch) == forge.Branch(opts.Target) {
		return nil, fmt.Errorf("inlet: folio branch and target are the same branch; a pull request cannot propose to itself")
	}
	if deps.Store == nil || deps.Forge == nil || deps.FolioPR == nil {
		return nil, fmt.Errorf("inlet: store, forge, and folio pull request are required")
	}
	h := &Handler{opts: opts, owners: owners, store: deps.Store, forge: deps.Forge, classifier: deps.Classifier, inbox: deps.Inbox,
		gate: deps.Gate, folio: deps.Folio, now: deps.Now, log: deps.Log, bodies: map[string][]byte{}}
	if h.now == nil {
		h.now = time.Now
	}
	if h.log == nil {
		h.log = func(string, ...any) {}
	}
	if h.gate == nil {
		h.gate = secretscan.New(nil)
	}
	for _, entry := range opts.AllowedOrigins {
		o, err := parseAllowedOrigin(entry)
		if err != nil {
			return nil, fmt.Errorf("inlet: %w", err)
		}
		h.allowed = append(h.allowed, o)
	}
	for _, entry := range opts.PreviewOrigins {
		p, err := parsePreviewPattern(entry)
		if err != nil {
			return nil, fmt.Errorf("inlet: %w", err)
		}
		h.previews = append(h.previews, p)
	}
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
	h.limiter = newLimiter(h.opts.TriagePerMinute)

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
		// The keys are loaded here, once, and refreshed in the background:
		// no request ever reaches the identity provider.
		h.remote = &RemoteKeys{URL: opts.JWKSURL, Client: deps.HTTPClient, Now: h.now, Log: h.log}
		if err := h.remote.Load(context.Background()); err != nil {
			return nil, fmt.Errorf("inlet: %w; owners cannot be verified", err)
		}
		keys = h.remote
	default:
		return nil, fmt.Errorf("inlet: no jwks configured")
	}
	h.verifier = &Verifier{Issuer: opts.Issuer, Audience: opts.Audience, Keys: keys, EmailVerifiedIfPresent: opts.EmailVerified == "if-present", Now: h.now}

	after := deps.AfterFunc
	if after == nil {
		after = func(d time.Duration, f func()) func() {
			t := time.AfterFunc(d, f)
			return func() { t.Stop() }
		}
	}
	h.coalescer = &Coalescer{PR: deps.FolioPR, Window: h.opts.Debounce, Now: h.now, AfterFunc: after, OnSettled: h.settled,
		OnFlush: func(_ Update, err error) {
			if err != nil {
				h.log("inlet: folio pull request not updated: %v", err)
			}
		}}
	if err := h.reload(context.Background()); err != nil {
		return nil, err
	}
	if h.remote != nil {
		h.remote.Start()
	}
	return h, nil
}

// Close stops the handler's background work: the JWKS refresh and the
// scheduled flush. Proposals still waiting stay in the store and are queued
// again by the next New.
func (h *Handler) Close() {
	if h.remote != nil {
		h.remote.Close()
	}
	h.coalescer.Close()
}

// PendingKey is the object-store key of a proposal accepted for the Folio
// pull request. It is written before the owner is answered.
func PendingKey(repo, id string) string { return fmt.Sprintf("inlet/%s/pending/%s.json", repo, id) }

// FlushedKey is the object-store key that says a pending proposal left the
// queue: carried into the pull request, or refused by it.
func FlushedKey(repo, id string) string { return fmt.Sprintf("inlet/%s/flushed/%s.json", repo, id) }

type pendingRecord struct {
	Schema   string   `json:"schema"`
	Proposal Proposal `json:"proposal"`
	Body     []byte   `json:"body"` // the nit as accepted, for the triage inbox if the pull request refuses it
}

type flushedRecord struct {
	Schema  string `json:"schema"`
	State   string `json:"state"` // pushed | refused
	Reason  string `json:"reason,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Head    string `json:"head,omitempty"`
	Capsule string `json:"capsule,omitempty"`
	At      string `json:"at"`
}

// persist writes a proposal to the store before it is queued: what an owner
// was told is accepted survives a restart (PRODUCT.md §0.2).
func (h *Handler) persist(ctx context.Context, p Proposal, body []byte) error {
	raw, err := json.Marshal(pendingRecord{Schema: "chimera.inlet.pending/v1", Proposal: p, Body: body})
	if err != nil {
		return fmt.Errorf("proposal: cannot encode")
	}
	_, err = h.store.Put(ctx, PendingKey(h.opts.Repo, p.ID), raw)
	return err
}

// reload queues every proposal that was accepted and never settled.
func (h *Handler) reload(ctx context.Context) error {
	pendingPrefix := fmt.Sprintf("inlet/%s/pending/", h.opts.Repo)
	flushedPrefix := fmt.Sprintf("inlet/%s/flushed/", h.opts.Repo)
	pending, err := h.store.List(ctx, pendingPrefix)
	if err != nil {
		return fmt.Errorf("inlet: pending proposals unreadable: %w", err)
	}
	if len(pending) == 0 {
		return nil
	}
	flushed, err := h.store.List(ctx, flushedPrefix)
	if err != nil {
		return fmt.Errorf("inlet: pending proposals unreadable: %w", err)
	}
	done := map[string]bool{}
	for _, k := range flushed {
		done[strings.TrimPrefix(k, flushedPrefix)] = true
	}
	sort.Strings(pending)
	for _, k := range pending {
		if done[strings.TrimPrefix(k, pendingPrefix)] {
			continue
		}
		raw, err := h.store.Get(ctx, k)
		if err != nil {
			return fmt.Errorf("inlet: pending proposals unreadable: %w", err)
		}
		var rec pendingRecord
		if json.Unmarshal(raw, &rec) != nil || rec.Proposal.ID == "" {
			h.log("inlet: pending proposal %s is malformed; left in the store", strings.TrimPrefix(k, pendingPrefix))
			continue
		}
		h.bodyMu.Lock()
		h.bodies[rec.Proposal.ID] = rec.Body
		h.bodyMu.Unlock()
		h.coalescer.Add(rec.Proposal)
	}
	return nil
}

// settled records what left the queue: proposals the pull request now
// carries, and proposals it refused — those go to the triage inbox with the
// reason, so what an owner said is never lost.
func (h *Handler) settled(up Update, landed, refused []Proposal) {
	ctx := context.Background()
	at := h.now().UTC()
	mark := func(id string, rec flushedRecord) {
		rec.Schema, rec.At = "chimera.inlet.flushed/v1", at.Format(time.RFC3339)
		raw, err := json.Marshal(rec)
		if err == nil {
			_, err = h.store.Put(ctx, FlushedKey(h.opts.Repo, id), raw)
		}
		if err != nil {
			h.log("inlet: proposal %s not marked settled: %v", id, err)
		}
		h.bodyMu.Lock()
		delete(h.bodies, id)
		h.bodyMu.Unlock()
	}
	for _, p := range landed {
		mark(p.ID, flushedRecord{State: "pushed", Head: string(up.Change.Head), Capsule: up.Capsule})
	}
	why := map[string]Refusal{}
	for _, r := range up.Refused {
		why[r.ID] = r
	}
	for _, p := range refused {
		r := why[p.ID]
		h.bodyMu.Lock()
		body := h.bodies[p.ID]
		h.bodyMu.Unlock()
		if err := h.inbox.Append(ctx, Entry{Schema: EntrySchema, ReceivedAt: at, Owner: true, Reason: r.Reason, Body: body}); err != nil {
			h.log("inlet: refused proposal %s not kept in the triage inbox: %v", p.ID, err)
			continue // stays pending in the store; the next start tries again
		}
		h.log("inlet: proposal %s refused by the folio pull request: %s", p.ID, r.Reason)
		mark(p.ID, flushedRecord{State: "refused", Reason: r.Reason, Detail: r.Detail})
	}
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

func (h *Handler) allowedOrigin(o origin) bool {
	for _, a := range h.allowed {
		if a == o {
			return true
		}
	}
	return false
}

// cors answers for origins in AllowedOrigins only, echoing the exact origin.
func (h *Handler) cors(w http.ResponseWriter, r *http.Request) bool {
	raw := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	o, ok := parseOrigin(raw)
	if raw == "" || !ok || !h.allowedOrigin(o) {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", raw)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	return true
}

// mayPost is the cross-site request fence. A browser attaches the owner's
// edge session to any request for the inlet's origin, whoever wrote the page
// that sent it; so a request that names an Origin must name the inlet's own
// or one the operator listed, and a request the browser itself calls
// cross-site must come from a listed origin.
func (h *Handler) mayPost(r *http.Request) bool {
	raw := r.Header.Get("Origin")
	if raw == "" {
		// No Origin: not a cross-origin browser request, unless the browser says so.
		return !strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site")
	}
	o, ok := parseOrigin(raw)
	if !ok {
		return false // "null", or anything that is not an origin
	}
	if h.allowedOrigin(o) {
		return true
	}
	return sameOrigin(o, r.Host) && !strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site")
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
	// Step 0, identical for everyone and decided before any credential is
	// looked at, so neither answer says anything about a token.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		h.write(w, http.StatusUnsupportedMediaType, Response{Status: StatusUnsupported})
		return
	}
	if !h.mayPost(r) {
		h.write(w, http.StatusForbidden, Response{Status: StatusForbiddenOrigin})
		return
	}
	// The token lives in headers: who is asking is settled before one byte
	// of the body is read.
	owner := false
	var id Identity
	if token := h.token(r); token != "" {
		var err error
		id, err = h.verifier.Verify(r.Context(), token)
		owner = err == nil && h.owners[id.Email]
	}
	if !owner {
		// No credentials, or none that make an owner — indistinguishable.
		h.triage(w, r)
		return
	}
	body, ok := h.read(w, r)
	if !ok {
		return
	}
	h.owner(w, r, body, id)
}

// read returns the request body, at most MaxBody bytes of it.
func (h *Handler) read(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		h.write(w, http.StatusRequestEntityTooLarge, Response{Status: "too-large"})
		return nil, false
	case err != nil:
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: "unreadable body"})
		return nil, false
	}
	return body, true
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

// triage is the whole path for everyone who is not an owner: a rate-limit
// check, then the body is read, then one append.
func (h *Handler) triage(w http.ResponseWriter, r *http.Request) {
	now := h.now()
	if !h.limiter.allow(clientAddr(r, h.opts.ClientIPHeader), now) {
		w.Header().Set("Retry-After", "60")
		h.write(w, http.StatusTooManyRequests, Response{Status: StatusRateLimited})
		return
	}
	body, ok := h.read(w, r)
	if !ok {
		return
	}
	if err := h.inbox.Append(r.Context(), Entry{Schema: EntrySchema, ReceivedAt: now.UTC(), Body: body}); err != nil {
		h.write(w, http.StatusServiceUnavailable, Response{Status: "unavailable"})
		return
	}
	h.write(w, http.StatusAccepted, Response{Status: StatusTriage})
}

// keep puts an owner nit that could not be routed into the triage inbox, so
// a failure downstream never loses what an owner said — not even when the
// owner has hung up meanwhile.
func (h *Handler) keep(w http.ResponseWriter, r *http.Request, body []byte, reason string) {
	ctx := context.WithoutCancel(r.Context())
	if err := h.inbox.Append(ctx, Entry{Schema: EntrySchema, ReceivedAt: h.now().UTC(), Owner: true, Reason: reason, Body: body}); err != nil {
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
func (h *Handler) owner(w http.ResponseWriter, r *http.Request, raw []byte, id Identity) {
	// What is written from here on outlives the request: an owner who hangs
	// up mid-classification has still said what they said.
	ctx := r.Context()
	durable := context.WithoutCancel(ctx)
	var nit Nit
	if err := json.Unmarshal(raw, &nit); err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: "body is not a nit"})
		return
	}
	if err := nit.Validate(); err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: err.Error()})
		return
	}
	// A query or fragment can carry a token (a magic link, a signed URL): it
	// is cut off here, before the nit is stored anywhere.
	page := "/"
	if u, err := url.Parse(nit.URL); err == nil {
		u.RawQuery, u.ForceQuery, u.Fragment, u.RawFragment, u.User = "", false, "", "", nil
		nit.URL = u.String()
		if p := u.EscapedPath(); p != "" {
			page = p
		}
	}
	body, err := json.Marshal(nit)
	if err != nil {
		h.write(w, http.StatusBadRequest, Response{Status: StatusInvalid, Reason: "body is not a nit"})
		return
	}
	// Origin loop guard: Chimera does not answer its own previews or bots.
	if matchPreview(h.previews, r.Header.Get("Origin")) || matchPreview(h.previews, nit.URL) ||
		isBot(h.opts.BotActors, id.Email) || isBot(h.opts.BotActors, id.Subject) {
		h.write(w, http.StatusAccepted, Response{Status: StatusDropped, Reason: "loop-guard"})
		return
	}

	h.ownerMu.Lock()
	defer h.ownerMu.Unlock()
	now := h.now()
	day := now.UTC().Format("2006-01-02")
	n, ok, err := h.claim(durable, now, nit)
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
		h.record(durable, day, n, Response{Schema: Schema, Status: StatusTriage, Reason: reason}, d)
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
		manifest := capsule.TaskManifest{
			Brief: brief + "\n\n" + nitContext(page, nit), Repo: h.opts.Repo, BaseSHA: string(base), Verifier: h.opts.Verifier,
			Clause: strings.TrimSpace(decision.Clause), Acceptance: decision.Acceptance,
		}
		// A task Intent is evidence like any other: nothing secret-shaped
		// goes into the store behind a content address.
		if len(h.gate.Scan("task.yaml", manifest.Bytes())) > 0 {
			fail("secret-gate", decision)
			return
		}
		intent, err := capsule.PutTask(durable, h.store, manifest)
		if err != nil {
			fail("store", decision)
			return
		}
		res := Response{Status: StatusTask, Intent: intent, Clause: strings.TrimSpace(decision.Clause)}
		h.record(durable, day, n, res, decision)
		h.write(w, http.StatusCreated, res)
	case KindIntent:
		nid := fmt.Sprintf("%s-%04d", now.UTC().Format("20060102"), n)
		ruling := "folio/rulings/nit-" + nid + ".md"
		p := Proposal{ID: nid, ReceivedAt: now.UTC(), Summary: oneLine(decision.Summary, 200),
			Files: []ProposalFile{{Path: ruling, Content: rulingFile(nid, now, page, nit, decision)}}}
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
		// actually about to be queued, ruling included. And everything bound
		// for Git passes the secret gate now, while the owner can still be told.
		gated := len(h.gate.Scan("summary", []byte(p.Summary))) > 0
		for _, f := range p.Files {
			if !InFence(f.Path) {
				fail("path-fence", decision)
				return
			}
			gated = gated || len(h.gate.Scan(f.Path, f.Content)) > 0
		}
		if gated {
			fail("secret-gate", decision)
			return
		}
		// Accepted means durable: the proposal is in the store before the
		// owner hears 202, so a restart inside the window loses nothing.
		if err := h.persist(durable, p, body); err != nil {
			fail("store", decision)
			return
		}
		h.bodyMu.Lock()
		h.bodies[p.ID] = body
		h.bodyMu.Unlock()
		pending := h.coalescer.Add(p)
		res := Response{Status: StatusFolio, Branch: forge.Branch(h.opts.FolioBranch), Ruling: ruling, Pending: pending}
		h.record(durable, day, n, res, decision)
		h.write(w, http.StatusAccepted, res)
	}
}

// nitContext renders where a nit was raised, for a brief or a ruling. Only
// the page's path is named: the origin identifies the operator, and neither
// a brief nor a ruling may (PRODUCT.md §0.4).
func nitContext(page string, n Nit) string {
	return fmt.Sprintf("Context:\n- path: %q\n- selector: %q\n- viewport: %dx%d @%gx\n", page, n.Selector, n.Viewport.W, n.Viewport.H, n.Viewport.DPR)
}

// rulingFile renders an owner nit as an owner ruling (folio/rulings/*.md is
// a T0 document, PRODUCT.md §2.3). It names the owner only as "owner" and
// the page only by its path.
func rulingFile(id string, at time.Time, page string, n Nit, d Decision) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Owner nit %s\n\n", id)
	fmt.Fprintf(&b, "- received: %s\n- actor: owner\n", at.UTC().Format(time.RFC3339))
	if c := strings.TrimSpace(d.Clause); c != "" {
		fmt.Fprintf(&b, "- clause: %s\n", oneLine(c, 200))
	}
	fmt.Fprintf(&b, "- path: %q\n- selector: %q\n- viewport: %dx%d @%gx\n", page, n.Selector, n.Viewport.W, n.Viewport.H, n.Viewport.DPR)
	fmt.Fprintf(&b, "\n## Summary\n\n%s\n\n## Text\n\n%s\n", oneLine(d.Summary, 200), strings.TrimSpace(n.Text))
	return []byte(b.String())
}
