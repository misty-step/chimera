package inlet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chimera/pkg/forge"
	"chimera/pkg/objstore"
)

const (
	testIssuer   = "https://id.example.com"
	testAudience = "chimera-inlet"
	testOwner    = "owner@example.com"
	testRepo     = "acme/widget"
)

// Keys are generated once per test binary; nothing here is a real credential.
var (
	keyOnce                sync.Once
	rsaKey, otherRSA       *rsa.PrivateKey
	ecKey                  *ecdsa.PrivateKey
	edPub                  ed25519.PublicKey
	edKey                  ed25519.PrivateKey
	testJWKS, testJWKSOnly []byte
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func keys(t *testing.T) {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			panic(err)
		}
		if edPub, edKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			panic(err)
		}
		rsaJWK := map[string]string{"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256",
			"n": enc(rsaKey.N.Bytes()), "e": enc([]byte{1, 0, 1})}
		x, y := make([]byte, 32), make([]byte, 32)
		ecKey.X.FillBytes(x)
		ecKey.Y.FillBytes(y)
		ecJWK := map[string]string{"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": enc(x), "y": enc(y)}
		edJWK := map[string]string{"kty": "OKP", "kid": "ed-1", "crv": "Ed25519", "x": enc(edPub)}
		ignored := map[string]string{"kty": "oct", "kid": "sym-1", "k": enc([]byte("not-used"))}
		testJWKS, _ = json.Marshal(map[string]any{"keys": []any{rsaJWK, ecJWK, edJWK, ignored}})
		testJWKSOnly, _ = json.Marshal(map[string]any{"keys": []any{edJWK}})
	})
}

// clock is an injected, advanceable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	return c.t
}

// claims returns valid owner claims at now; tests override fields.
func claims(now time.Time, over map[string]any) map[string]any {
	c := map[string]any{"iss": testIssuer, "aud": testAudience, "sub": "user-1", "email": testOwner, "email_verified": true,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// mint signs a token. key selects the algorithm's signer; alg and kid are
// written to the header as given, so a test can lie in the header.
func mint(t *testing.T, alg, kid string, key any, c map[string]any) string {
	t.Helper()
	header := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(c)
	signed := enc(hb) + "." + enc(cb)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		r, s, e := ecdsa.Sign(rand.Reader, k, sum[:])
		err = e
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(signed))
	case []byte: // raw signature bytes, for forged tokens
		sig = k
	case nil:
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + enc(sig)
}

func ownerToken(t *testing.T, now time.Time) string {
	t.Helper()
	keys(t)
	return mint(t, "RS256", "rsa-1", rsaKey, claims(now, nil))
}

// fakeClassifier counts calls and answers with decide.
type fakeClassifier struct {
	mu     sync.Mutex
	calls  int
	seen   []FolioSnapshot
	decide func(Nit) (Decision, error)
}

func (f *fakeClassifier) Classify(_ context.Context, nit Nit, folio FolioSnapshot) (Decision, error) {
	f.mu.Lock()
	f.calls++
	f.seen = append(f.seen, folio)
	decide := f.decide
	f.mu.Unlock()
	if decide == nil {
		return Decision{Kind: KindIntent, Summary: "s"}, nil
	}
	return decide(nit)
}

func (f *fakeClassifier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
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

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	productV1 = "# Product\n\n**[UI-1] Totals use tabular figures.**\n"
	designV1  = "# Design\n\nFocus rings are 2px accent.\n"
)

// folioRepo is a repository with a Folio and code beside it, on branch main.
func folioRepo(t *testing.T) (dir string, head forge.SHA) {
	t.Helper()
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	writeFile(t, dir, "PRODUCT.md", productV1)
	writeFile(t, dir, "DESIGN.md", designV1)
	writeFile(t, dir, "folio/assets/mark.svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n")
	writeFile(t, dir, "cmd/chimera/main.go", "package main\n\nfunc main() {}\n")
	writeFile(t, dir, "go.mod", "module widget\n")
	writeFile(t, dir, "AGENTS.md", "# agents\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "fixture")
	return dir, forge.SHA(git(t, dir, "rev-parse", "HEAD"))
}

// fixture is a Handler wired to fakes: a real repository, the in-memory
// forge, a directory store, a counting classifier, and an injected clock.
type fixture struct {
	t          *testing.T
	h          *Handler
	opts       Options
	forge      *forge.Fake
	store      *objstore.Dir
	inbox      *MemInbox
	classifier *fakeClassifier
	clock      *clock
	repo       string
	head       forge.SHA
	pr         *BranchPR
}

func newFixture(t *testing.T, tweak func(*Options, *Deps)) *fixture {
	t.Helper()
	keys(t)
	f := &fixture{t: t, forge: forge.NewFake(), inbox: &MemInbox{}, classifier: &fakeClassifier{}, clock: newClock()}
	f.repo, f.head = folioRepo(t)
	f.forge.SetRef("main", f.head)
	f.store = objstore.NewDir(filepath.Join(t.TempDir(), "store"))
	f.pr = &BranchPR{RepoDir: f.repo, Forge: f.forge, Target: "main", Now: f.clock.Now}
	f.opts = Options{Repo: testRepo, OwnerEmails: []string{"Owner@Example.com"}, Issuer: testIssuer, Audience: testAudience, JWKS: testJWKS,
		Target: "main", PreviewOrigins: []string{"https://*.preview.example.com", "http://127.0.0.1:9001"}, BotActors: []string{"bot@example.com"}}
	deps := Deps{Store: f.store, Forge: f.forge, Classifier: f.classifier, Inbox: f.inbox, FolioPR: f.pr, Now: f.clock.Now,
		Folio: GitFolio(f.repo, f.forge, "", "main"), AfterFunc: func(time.Duration, func()) func() { return func() {} }}
	if tweak != nil {
		tweak(&f.opts, &deps)
	}
	h, err := New(f.opts, deps)
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

const goodNit = `{"schema":"chimera.nit/v1","url":"https://app.example.com/orders?page=2","selector":"#total","viewport":{"w":1440,"h":900,"dpr":2},"text":"Total should use tabular figures."}`

type reply struct {
	Code int
	Response
	Header http.Header
}

// post sends one request. A non-empty token goes in Authorization: Bearer.
func (f *fixture) post(body, token string, edit func(*http.Request)) reply {
	f.t.Helper()
	return send(f.t, f.h, body, token, edit)
}

func send(t *testing.T, h http.Handler, body, token string, edit func(*http.Request)) reply {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, Path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:40000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if edit != nil {
		edit(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	r := reply{Code: rec.Code, Header: rec.Header()}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &r.Response); err != nil {
			t.Fatalf("response is not JSON: %q", rec.Body.String())
		}
		if r.Schema != Schema {
			t.Fatalf("response schema %q", r.Schema)
		}
	}
	return r
}

func (f *fixture) owner(body string) reply {
	f.t.Helper()
	return f.post(body, ownerToken(f.t, f.clock.Now()), nil)
}

func (f *fixture) keysUnder(prefix string) []string {
	f.t.Helper()
	keys, err := f.store.List(context.Background(), prefix)
	if err != nil {
		f.t.Fatal(err)
	}
	return keys
}

// pushes counts the pushes that moved a ref.
func (f *fixture) pushes() int {
	n := 0
	for _, p := range f.forge.Pushes() {
		if p.Err == nil {
			n++
		}
	}
	return n
}

func nitText(text string) string {
	b, _ := json.Marshal(Nit{Schema: NitSchema, URL: "https://app.example.com/orders", Selector: "main > p:nth-of-type(2)", Viewport: Viewport{W: 390, H: 844, DPR: 3}, Text: text})
	return string(b)
}
