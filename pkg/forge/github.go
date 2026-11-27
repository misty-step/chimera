package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultGitHubAPI is the REST root of the public service.
const DefaultGitHubAPI = "https://api.github.com"

// GitHub is the first Forge adapter (PRODUCT.md §2.5): the REST API over
// net/http, no SDK. The token is sent only to API and never appears in an
// error; over plain http it is sent only to a loopback address.
//
// What is atomic and what is not. GitHub has no compare-and-swap on a ref,
// so Push composes one:
//
//   - create (old is Zero): POST git/refs is atomic on the server; an
//     existing ref answers 422 and Push returns ErrStale.
//   - update: Push reads the ref and returns ErrStale unless it is at old,
//     then PATCHes it with force=false. The read and the write are two
//     requests; what closes the window is the server's fast-forward rule. A
//     lander's new commit is a descendant of old and of nothing newer, so if
//     another writer moved the ref forward in between, the PATCH is not a
//     fast-forward, answers 422, and Push returns ErrStale. A ref rewound in
//     the window to an ancestor of old would be accepted; protect the branch
//     against force pushes to exclude that.
//   - delete (new is Zero): read, compare, DELETE. The window between read
//     and delete is not fenced by the server. It is used only for queue and
//     staging refs, where the worst outcome is a change dequeued at a commit
//     newer than the one read.
type GitHub struct {
	API    string       // REST root; "" means DefaultGitHubAPI
	Repo   string       // "owner/name"
	Token  string       // bearer token; never logged
	Client *http.Client // nil means a client with a 30s timeout
}

var githubClient = &http.Client{Timeout: 30 * time.Second}

// APIError is a refusal from the forge: the method, path, status, and the
// forge's own message. It never carries a header.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s %s: status %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("%s %s: status %d: %s", e.Method, e.Path, e.Status, e.Message)
}

// Is reports ErrUnavailable for transient statuses.
func (e *APIError) Is(target error) bool {
	return target == ErrUnavailable && (e.Status >= 500 || e.Status == http.StatusTooManyRequests)
}

type unavailableError struct{ method, path string }

func (e *unavailableError) Error() string {
	return fmt.Sprintf("%s %s: no answer from the forge", e.method, e.path)
}
func (e *unavailableError) Is(target error) bool { return target == ErrUnavailable }

func (g *GitHub) base() string {
	if g.API == "" {
		return DefaultGitHubAPI
	}
	return strings.TrimRight(g.API, "/")
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// repoPath builds /repos/<owner>/<name>/<rest>; rest is already escaped.
func (g *GitHub) repoPath(rest string) string {
	return "/repos/" + escapePath(g.Repo) + "/" + rest
}

// do sends one request. out, when non-nil, receives the decoded 2xx body.
// It returns the status and the Link header's rel="next" URL.
func (g *GitHub) do(ctx context.Context, method, pathAndQuery string, body, out any) (status int, next string, err error) {
	path, _, _ := strings.Cut(pathAndQuery, "?")
	if g.Repo == "" || !strings.Contains(g.Repo, "/") {
		return 0, "", fmt.Errorf("forge.repo must be owner/name")
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.base()+pathAndQuery, rd)
	if err != nil {
		return 0, "", fmt.Errorf("%s %s: invalid request", method, path)
	}
	if g.Token != "" && req.URL.Scheme != "https" && !loopback(req.URL.Hostname()) {
		// A bearer token is never sent in the clear.
		return 0, "", fmt.Errorf("%s %s: forge.api must be https; the token was not sent", method, path)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "chimera")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := g.Client
	if client == nil {
		client = githubClient
	}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, "", ctx.Err()
		}
		// The transport error may quote the URL; it never leaves this function.
		return 0, "", &unavailableError{method: method, path: path}
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &msg)
		return resp.StatusCode, "", &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: oneLine(msg.Message)}
	}
	if rerr != nil {
		return resp.StatusCode, "", &unavailableError{method: method, path: path}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, "", fmt.Errorf("%s %s: malformed response", method, path)
		}
	}
	return resp.StatusCode, nextLink(resp.Header.Get("Link")), nil
}

// loopback reports whether host is this machine: the only place a token may
// travel over plain http (a local test double).
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:199]) + "…"
	}
	return s
}

// nextLink extracts the rel="next" target of a Link header.
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		target, params, ok := strings.Cut(strings.TrimSpace(part), ";")
		if !ok || !strings.Contains(params, `rel="next"`) {
			continue
		}
		return strings.Trim(strings.TrimSpace(target), "<>")
	}
	return ""
}

func statusOf(err error) int {
	if ae, ok := err.(*APIError); ok {
		return ae.Status
	}
	return 0
}

type ghRef struct {
	Ref    string `json:"ref"`
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

func refPath(ref string) string { return escapePath(strings.TrimPrefix(RefName(ref), "refs/")) }

// Head implements Forge.
func (g *GitHub) Head(ctx context.Context, ref string) (SHA, error) {
	var r ghRef
	_, _, err := g.do(ctx, http.MethodGet, g.repoPath("git/ref/"+refPath(ref)), nil, &r)
	if statusOf(err) == http.StatusNotFound {
		return Zero, ErrNotFound
	}
	if err != nil {
		return Zero, err
	}
	if r.Ref != RefName(ref) || SHA(r.Object.SHA).IsZero() {
		return Zero, ErrNotFound // a prefix match is not the ref
	}
	return SHA(r.Object.SHA), nil
}

// Push implements Forge; see the type's comment for what is atomic.
func (g *GitHub) Push(ctx context.Context, ref string, old, new SHA) error {
	ref = RefName(ref)
	switch {
	case old.IsZero() && new.IsZero():
		return fmt.Errorf("push %s: nothing to do", ref)
	case old.IsZero():
		_, _, err := g.do(ctx, http.MethodPost, g.repoPath("git/refs"), map[string]string{"ref": ref, "sha": string(new)}, nil)
		if ae, ok := err.(*APIError); ok && ae.Status == http.StatusUnprocessableEntity && strings.Contains(strings.ToLower(ae.Message), "already exists") {
			return ErrStale
		}
		return err
	}
	cur, err := g.Head(ctx, ref)
	if err == ErrNotFound {
		return ErrStale
	}
	if err != nil {
		return err
	}
	if !Same(cur, old) {
		return ErrStale
	}
	if new.IsZero() {
		_, _, err := g.do(ctx, http.MethodDelete, g.repoPath("git/refs/"+refPath(ref)), nil, nil)
		if s := statusOf(err); s == http.StatusNotFound || s == http.StatusUnprocessableEntity {
			return ErrStale
		}
		return err
	}
	_, _, err = g.do(ctx, http.MethodPatch, g.repoPath("git/refs/"+refPath(ref)), map[string]any{"sha": string(new), "force": false}, nil)
	if ae, ok := err.(*APIError); ok {
		msg := strings.ToLower(ae.Message)
		if ae.Status == http.StatusNotFound || (ae.Status == http.StatusUnprocessableEntity && strings.Contains(msg, "fast forward")) {
			return ErrStale
		}
	}
	return err
}

// Queue implements Forge: the queue refs of target, in FIFO order.
func (g *GitHub) Queue(ctx context.Context, target string) ([]Change, error) {
	prefix := strings.TrimSuffix(strings.TrimPrefix(QueueRefPrefix(target), "refs/"), "/")
	next := g.repoPath("git/matching-refs/"+escapePath(prefix)) + "?per_page=100"
	refs := map[string]SHA{}
	for page := 0; next != ""; page++ {
		if page >= 1000 {
			return nil, fmt.Errorf("queue %s: listing does not end", Branch(target))
		}
		var batch []ghRef
		_, link, err := g.do(ctx, http.MethodGet, next, nil, &batch)
		if err != nil {
			return nil, err
		}
		for _, r := range batch {
			refs[r.Ref] = SHA(r.Object.SHA)
		}
		next = ""
		if link != "" {
			// Follow the forge's cursor only within the API it came from; the
			// token is never sent anywhere else.
			rest, ok := strings.CutPrefix(link, g.base())
			if !ok || !strings.HasPrefix(rest, "/") {
				return nil, fmt.Errorf("queue %s: pagination left the forge API", Branch(target))
			}
			next = rest
		}
	}
	return QueueFromRefs(target, refs), nil
}

// Report implements Forge as a commit status: the check's name is the
// status context, its title the description (140 characters at most).
func (g *GitHub) Report(ctx context.Context, sha SHA, check Check) error {
	state := "pending"
	switch check.State {
	case Pass:
		state = "success"
	case Fail:
		state = "failure"
	}
	desc := []rune(strings.Join(strings.Fields(check.Title), " "))
	if len(desc) > 140 {
		desc = append(desc[:139], '…')
	}
	body := map[string]string{"state": state, "context": check.Name, "description": string(desc)}
	if check.URL != "" {
		body["target_url"] = check.URL
	}
	_, _, err := g.do(ctx, http.MethodPost, g.repoPath("statuses/"+url.PathEscape(string(sha))), body, nil)
	return err
}

// Notify implements Forge. The message goes to the open pull request whose
// head is the change's branch, as a comment. When none is open:
//
//   - a change that is not queued (Ref is empty) and names a Target is a
//     proposal, and Notify opens its pull request: the first line of msg is
//     the title, the rest the body. Inlet's one Folio-only PR is opened this
//     way, since the five-method surface has no other verb for it;
//   - any other change gets a commit comment on its Head, so an evicted
//     change always hears the reason on its owning branch.
func (g *GitHub) Notify(ctx context.Context, c Change, msg string) error {
	owner, _, _ := strings.Cut(g.Repo, "/")
	branch := Branch(c.Branch)
	if branch != "" {
		var pulls []struct {
			Number int `json:"number"`
		}
		q := url.Values{"state": {"open"}, "head": {owner + ":" + branch}, "per_page": {"1"}}
		if _, _, err := g.do(ctx, http.MethodGet, g.repoPath("pulls")+"?"+q.Encode(), nil, &pulls); err != nil {
			return err
		}
		if len(pulls) > 0 {
			_, _, err := g.do(ctx, http.MethodPost, g.repoPath(fmt.Sprintf("issues/%d/comments", pulls[0].Number)), map[string]string{"body": msg}, nil)
			return err
		}
		if c.Ref == "" && c.Target != "" {
			title, body, _ := strings.Cut(strings.TrimSpace(msg), "\n")
			_, _, err := g.do(ctx, http.MethodPost, g.repoPath("pulls"),
				map[string]string{"title": strings.TrimSpace(title), "body": strings.TrimSpace(body), "head": branch, "base": Branch(c.Target)}, nil)
			return err
		}
	}
	if c.Head.IsZero() {
		return fmt.Errorf("notify %s: no open pull request and no commit to comment on", branch)
	}
	_, _, err := g.do(ctx, http.MethodPost, g.repoPath("commits/"+url.PathEscape(string(c.Head))+"/comments"), map[string]string{"body": msg}, nil)
	return err
}
