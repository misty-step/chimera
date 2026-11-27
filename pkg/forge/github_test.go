package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ghFake is a loopback fake of the slice of the GitHub REST API the adapter
// uses, for acme/widget. It enforces the bearer token and the fast-forward
// rule on ref updates.
type ghFake struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	token       string
	refs        map[string]string
	parents     map[string]string // sha → parent
	requests    []string          // "METHOD /path?query"
	bodies      []string
	statuses    []map[string]string
	pulls       []map[string]any
	comments    []string // "issue 7: text" | "commit <sha>: text"
	pageSize    int
	beforePatch func()
	failStatus  int    // answer the next request with this status
	foreignNext string // Link target to hand out instead of the real one
}

func newGHFake(t *testing.T) *ghFake {
	t.Helper()
	gh := &ghFake{t: t, token: "test-" + string(randSHA(t)), refs: map[string]string{}, parents: map[string]string{}, pageSize: 100}
	gh.srv = httptest.NewServer(gh)
	t.Cleanup(gh.srv.Close)
	return gh
}

func (gh *ghFake) client() *GitHub {
	return &GitHub{API: gh.srv.URL, Repo: "acme/widget", Token: gh.token}
}

func (gh *ghFake) fail(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": msg})
}

func (gh *ghFake) ancestor(old, new string) bool {
	for s, n := new, 0; s != "" && n < 1000; s, n = gh.parents[s], n+1 {
		if s == old {
			return true
		}
	}
	return false
}

func refJSON(ref, sha string) map[string]any {
	return map[string]any{"ref": ref, "object": map[string]string{"sha": sha, "type": "commit"}}
}

func (gh *ghFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	gh.mu.Lock()
	hook := gh.beforePatch
	gh.mu.Unlock()
	if r.Method == http.MethodPatch && hook != nil {
		hook()
	}
	gh.mu.Lock()
	defer gh.mu.Unlock()
	gh.requests = append(gh.requests, r.Method+" "+r.URL.RequestURI())
	gh.bodies = append(gh.bodies, string(raw))
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+gh.token {
		gh.fail(w, http.StatusUnauthorized, "Bad credentials")
		return
	}
	if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") == "" || r.Header.Get("User-Agent") != "chimera" {
		gh.fail(w, http.StatusBadRequest, "missing API headers")
		return
	}
	if gh.failStatus != 0 {
		status := gh.failStatus
		gh.failStatus = 0
		gh.fail(w, status, "Server Error")
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, "/repos/acme/widget/")
	if !ok {
		gh.fail(w, http.StatusNotFound, "Not Found")
		return
	}
	var body map[string]any
	if len(raw) > 0 && json.Unmarshal(raw, &body) != nil {
		gh.fail(w, http.StatusBadRequest, "Problems parsing JSON")
		return
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(path, "git/ref/"):
		ref := "refs/" + strings.TrimPrefix(path, "git/ref/")
		sha, ok := gh.refs[ref]
		if !ok {
			gh.fail(w, http.StatusNotFound, "Not Found")
			return
		}
		json.NewEncoder(w).Encode(refJSON(ref, sha))
	case r.Method == http.MethodGet && strings.HasPrefix(path, "git/matching-refs/"):
		prefix := "refs/" + strings.TrimPrefix(path, "git/matching-refs/")
		var names []string
		for ref := range gh.refs {
			if strings.HasPrefix(ref, prefix) {
				names = append(names, ref)
			}
		}
		sort.Strings(names)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		lo := (page - 1) * gh.pageSize
		hi := lo + gh.pageSize
		if lo > len(names) {
			lo = len(names)
		}
		if hi < len(names) {
			next := fmt.Sprintf("%s%s?per_page=%d&page=%d", gh.srv.URL, r.URL.Path, gh.pageSize, page+1)
			if gh.foreignNext != "" {
				next = gh.foreignNext
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next", <%s%s?page=99>; rel="last"`, next, gh.srv.URL, r.URL.Path))
		} else {
			hi = len(names)
		}
		out := []map[string]any{}
		for _, ref := range names[lo:hi] {
			out = append(out, refJSON(ref, gh.refs[ref]))
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && path == "git/refs":
		ref, sha := str("ref"), str("sha")
		if !strings.HasPrefix(ref, "refs/") || strings.Count(ref, "/") < 2 || sha == "" {
			gh.fail(w, http.StatusUnprocessableEntity, "Reference name must start with 'refs/' and have at least two slashes")
			return
		}
		if _, exists := gh.refs[ref]; exists {
			gh.fail(w, http.StatusUnprocessableEntity, "Reference already exists")
			return
		}
		gh.refs[ref] = sha
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(refJSON(ref, sha))
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "git/refs/"):
		ref := "refs/" + strings.TrimPrefix(path, "git/refs/")
		cur, ok := gh.refs[ref]
		if !ok {
			gh.fail(w, http.StatusUnprocessableEntity, "Reference does not exist")
			return
		}
		if force, _ := body["force"].(bool); !force && !gh.ancestor(cur, str("sha")) {
			gh.fail(w, http.StatusUnprocessableEntity, "Update is not a fast forward")
			return
		}
		gh.refs[ref] = str("sha")
		json.NewEncoder(w).Encode(refJSON(ref, str("sha")))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "git/refs/"):
		ref := "refs/" + strings.TrimPrefix(path, "git/refs/")
		if _, ok := gh.refs[ref]; !ok {
			gh.fail(w, http.StatusUnprocessableEntity, "Reference does not exist")
			return
		}
		delete(gh.refs, ref)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "statuses/"):
		st := map[string]string{"sha": strings.TrimPrefix(path, "statuses/")}
		for k := range body {
			st[k] = str(k)
		}
		gh.statuses = append(gh.statuses, st)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{}"))
	case r.Method == http.MethodGet && path == "pulls":
		out := []map[string]any{}
		for _, p := range gh.pulls {
			if r.URL.Query().Get("state") == "open" && "acme:"+p["head"].(string) == r.URL.Query().Get("head") {
				out = append(out, map[string]any{"number": p["number"]})
			}
		}
		json.NewEncoder(w).Encode(out)
	case r.Method == http.MethodPost && path == "pulls":
		p := map[string]any{"number": 40 + len(gh.pulls), "head": str("head"), "base": str("base"), "title": str("title"), "body": str("body")}
		gh.pulls = append(gh.pulls, p)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(p)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "issues/") && strings.HasSuffix(path, "/comments"):
		gh.comments = append(gh.comments, "issue "+strings.TrimSuffix(strings.TrimPrefix(path, "issues/"), "/comments")+": "+str("body"))
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{}"))
	case r.Method == http.MethodPost && strings.HasPrefix(path, "commits/") && strings.HasSuffix(path, "/comments"):
		gh.comments = append(gh.comments, "commit "+strings.TrimSuffix(strings.TrimPrefix(path, "commits/"), "/comments")+": "+str("body"))
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("{}"))
	default:
		gh.fail(w, http.StatusNotFound, "Not Found")
	}
}

func (gh *ghFake) reset() {
	gh.mu.Lock()
	defer gh.mu.Unlock()
	gh.requests, gh.bodies = nil, nil
}

func (gh *ghFake) seen() []string {
	gh.mu.Lock()
	defer gh.mu.Unlock()
	return append([]string{}, gh.requests...)
}

func TestM2_2_GitHubAdapterMapsTheFiveMethodsOntoREST(t *testing.T) {
	ctx := context.Background()
	s, gh := githubSubject(t)
	f := s.forge
	c1 := s.commit(Zero)
	c2 := s.commit(c1)

	// Head and the three shapes of Push.
	if err := f.Push(ctx, "main", Zero, c1); err != nil {
		t.Fatal(err)
	}
	if err := f.Push(ctx, "main", c1, c2); err != nil {
		t.Fatal(err)
	}
	if err := f.Push(ctx, QueueRef("main", 1, "feature/x"), Zero, c2); err != nil {
		t.Fatal(err)
	}
	if err := f.Push(ctx, QueueRef("main", 1, "feature/x"), c2, Zero); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"POST /repos/acme/widget/git/refs",
		"GET /repos/acme/widget/git/ref/heads/main",
		"PATCH /repos/acme/widget/git/refs/heads/main",
		"POST /repos/acme/widget/git/refs",
		"GET /repos/acme/widget/git/ref/chimera/land/main/00000001/feature/x",
		"DELETE /repos/acme/widget/git/refs/chimera/land/main/00000001/feature/x",
	}
	if got := gh.seen(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(got, "\n"))
	}
	gh.mu.Lock()
	if gh.bodies[0] != fmt.Sprintf(`{"ref":"refs/heads/main","sha":"%s"}`, c1) || gh.bodies[2] != fmt.Sprintf(`{"force":false,"sha":"%s"}`, c2) {
		t.Fatalf("bodies: %q", gh.bodies)
	}
	gh.mu.Unlock()

	// Report is a commit status; a long title is cut to 140 characters.
	gh.reset()
	long := strings.Repeat("é", 200)
	if err := f.Report(ctx, c2, Check{Name: "chimera/land", State: Pass, Title: "landed on main", URL: "https://ci.example.com/run/1"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Report(ctx, c2, Check{Name: "chimera/land", State: Fail, Title: long}); err != nil {
		t.Fatal(err)
	}
	if err := f.Report(ctx, c2, Check{Name: "chimera/trail", State: Pending, Title: "owner review\nneeded"}); err != nil {
		t.Fatal(err)
	}
	gh.mu.Lock()
	st := gh.statuses
	gh.mu.Unlock()
	if len(st) != 3 || st[0]["sha"] != string(c2) || st[0]["state"] != "success" || st[0]["context"] != "chimera/land" || st[0]["description"] != "landed on main" ||
		st[0]["target_url"] != "https://ci.example.com/run/1" || st[1]["state"] != "failure" || len([]rune(st[1]["description"])) != 140 ||
		st[2]["state"] != "pending" || st[2]["description"] != "owner review needed" || st[2]["target_url"] != "" {
		t.Fatalf("statuses: %+v", st)
	}

	// Notify: a comment on the branch's open pull request…
	gh.mu.Lock()
	gh.pulls = append(gh.pulls, map[string]any{"number": 7, "head": "feature/x", "base": "main"})
	gh.mu.Unlock()
	queued := Change{ID: "1/feature/x", Ref: QueueRef("main", 1, "feature/x"), Seq: 1, Branch: "feature/x", Head: c2, Target: "main"}
	if err := f.Notify(ctx, queued, "evicted: conflict in greet.sh"); err != nil {
		t.Fatal(err)
	}
	// …a commit comment for a queued change whose branch has no pull request…
	orphan := queued
	orphan.Branch = "no-pr"
	if err := f.Notify(ctx, orphan, "evicted: verifier failed"); err != nil {
		t.Fatal(err)
	}
	// …and a new pull request for a proposal: not queued, with a target.
	proposal := Change{Branch: "chimera/folio", Head: c2, Target: "main"}
	if err := f.Notify(ctx, proposal, "folio: 2 owner nits\n\nfolio/rulings/nit-1.md\nfolio/rulings/nit-2.md\n"); err != nil {
		t.Fatal(err)
	}
	// A second notification for the proposal finds the pull request it opened.
	if err := f.Notify(ctx, proposal, "folio: 3 owner nits"); err != nil {
		t.Fatal(err)
	}
	gh.mu.Lock()
	comments, pulls := gh.comments, gh.pulls
	gh.mu.Unlock()
	if strings.Join(comments, "|") != "issue 7: evicted: conflict in greet.sh|commit "+string(c2)+": evicted: verifier failed|issue 41: folio: 3 owner nits" {
		t.Fatalf("comments: %q", comments)
	}
	if len(pulls) != 2 || pulls[1]["head"] != "chimera/folio" || pulls[1]["base"] != "main" || pulls[1]["title"] != "folio: 2 owner nits" ||
		pulls[1]["body"] != "folio/rulings/nit-1.md\nfolio/rulings/nit-2.md" {
		t.Fatalf("pulls: %+v", pulls)
	}
	if got := gh.seen(); !strings.Contains(strings.Join(got, "\n"), "GET /repos/acme/widget/pulls?head=acme%3Afeature%2Fx&per_page=1&state=open") {
		t.Fatalf("requests:\n%s", strings.Join(got, "\n"))
	}
}

func TestM2_2_GitHubQueueFollowsPaginationOnlyWithinTheAPI(t *testing.T) {
	ctx := context.Background()
	s, gh := githubSubject(t)
	f := s.forge
	c1 := s.commit(Zero)
	for i := 5; i >= 1; i-- {
		if err := f.Push(ctx, QueueRef("main", i, fmt.Sprintf("b%d", i)), Zero, c1); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Push(ctx, QueueRef("mainline", 1, "other"), Zero, c1); err != nil {
		t.Fatal(err)
	}
	gh.mu.Lock()
	gh.pageSize = 2
	gh.mu.Unlock()
	gh.reset()
	q, err := f.Queue(ctx, "main")
	if err != nil || len(q) != 5 {
		t.Fatalf("%+v %v", q, err)
	}
	for i, c := range q {
		if c.Seq != i+1 || c.Branch != fmt.Sprintf("b%d", i+1) {
			t.Fatalf("queue[%d] = %+v", i, c)
		}
	}
	if got := gh.seen(); len(got) != 3 || got[0] != "GET /repos/acme/widget/git/matching-refs/chimera/land/main?per_page=100" || !strings.HasSuffix(got[2], "page=3") {
		t.Fatalf("requests: %q", got)
	}
	// A cursor that points off the API is refused: the token goes nowhere else.
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte("[]")) }))
	defer other.Close()
	gh.mu.Lock()
	gh.foreignNext = other.URL + "/repos/acme/widget/git/matching-refs/chimera/land/main?page=2"
	gh.mu.Unlock()
	if _, err := f.Queue(ctx, "main"); err == nil || !strings.Contains(err.Error(), "pagination left the forge API") || hits != 0 {
		t.Fatalf("foreign cursor: %v (hits %d)", err, hits)
	}
}

func TestM2_2_GitHubPushIsStaleWhenTheRefMovesBetweenReadAndWrite(t *testing.T) {
	ctx := context.Background()
	s, gh := githubSubject(t)
	f := s.forge
	base := s.commit(Zero)
	mine := s.commit(base)
	theirs := s.commit(base)
	if err := f.Push(ctx, "main", Zero, base); err != nil {
		t.Fatal(err)
	}
	// Another writer lands between the adapter's read and its PATCH: the
	// server's fast-forward rule refuses, and the adapter reports ErrStale.
	gh.mu.Lock()
	gh.beforePatch = func() {
		gh.mu.Lock()
		gh.refs["refs/heads/main"] = string(theirs)
		gh.beforePatch = nil
		gh.mu.Unlock()
	}
	gh.mu.Unlock()
	if err := f.Push(ctx, "main", base, mine); !errors.Is(err, ErrStale) {
		t.Fatalf("push across a concurrent writer: %v", err)
	}
	if got, _ := f.Head(ctx, "main"); got != theirs {
		t.Fatalf("head %s, want the other writer's %s", got, theirs)
	}
	// Retried from the new head, as a lander does, it lands.
	rebased := s.commit(theirs)
	if err := f.Push(ctx, "main", theirs, rebased); err != nil {
		t.Fatal(err)
	}
}

func TestM2_2_GitHubErrorsNameTheCallAndNeverTheToken(t *testing.T) {
	ctx := context.Background()
	s, gh := githubSubject(t)
	c1 := s.commit(Zero)
	bad := gh.client()
	bad.Token = "wrong-" + gh.token
	_, err := bad.Head(ctx, "main")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || err.Error() != "GET /repos/acme/widget/git/ref/heads/main: status 401: Bad credentials" {
		t.Fatalf("bad token: %v", err)
	}
	if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNotFound) {
		t.Fatal("a refusal is neither unavailable nor not-found")
	}
	// A transient status and a dead server are both "unavailable", and say nothing more.
	f := gh.client()
	gh.mu.Lock()
	gh.failStatus = http.StatusBadGateway
	gh.mu.Unlock()
	if err := f.Push(ctx, "main", Zero, c1); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrStale) {
		t.Fatalf("502: %v", err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	gone := &GitHub{API: dead.URL, Repo: "acme/widget", Token: gh.token}
	for name, call := range map[string]func() error{
		"head":   func() error { _, err := gone.Head(ctx, "main"); return err },
		"push":   func() error { return gone.Push(ctx, "main", Zero, c1) },
		"queue":  func() error { _, err := gone.Queue(ctx, "main"); return err },
		"report": func() error { return gone.Report(ctx, c1, Check{Name: "chimera/land", State: Pass}) },
		"notify": func() error { return gone.Notify(ctx, Change{Branch: "x", Head: c1}, "m") },
	} {
		err := call()
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s against a dead forge: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), gh.token) || strings.Contains(err.Error(), "Bearer") || strings.Contains(err.Error(), dead.URL)) {
			t.Errorf("%s error leaks the request: %v", name, err)
		}
	}
	if _, err := (&GitHub{API: gh.srv.URL, Repo: "widget", Token: gh.token}).Head(ctx, "main"); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("repo without an owner: %v", err)
	}
	if (&GitHub{}).base() != "https://api.github.com" {
		t.Fatal("default API root")
	}
}
