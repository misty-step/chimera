// Package obslint audits a repository for production observability and
// auto-triage readiness (PRODUCT.md [M2-4]).
//
// The audit is a deterministic, read-only walk of one directory. It first
// detects deployable surfaces — a web app, an edge worker, or an HTTP service —
// and, when there is at least one, checks three baseline invariants:
//
//  1. health: a real /healthz or /api/health route that reports status and a
//     release identity read at runtime, not a hardcoded stub;
//  2. telemetry: worker observability configuration (observability.enabled),
//     or server-side error forwarding whose sink is supplied by runtime env;
//     never a committed DSN, and never telemetry switched off;
//  3. client (web surfaces only): browser error, unhandledrejection, and
//     securitypolicyviolation listeners that forward events, through a
//     same-origin beacon when a strict connect-src 'self' CSP applies.
//
// Every check is a lexical rule over file contents, so the same tree always
// yields the same findings. Test code, fixtures, examples, dependency and
// build-output directories are not part of the audit.
package obslint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Status of an audit.
const (
	StatusPass          = "pass"
	StatusFail          = "fail"
	StatusNotApplicable = "not-applicable"
)

// Surface kinds.
const (
	SurfaceWeb     = "web"
	SurfaceWorker  = "worker"
	SurfaceService = "service"
)

// Rule IDs. Each finding carries exactly one.
const (
	RuleHealthMissing     = "health-missing"       // no /healthz or /api/health route
	RuleHealthStub        = "health-stub"          // the route exists but reports no runtime release identity
	RuleTelemetryMissing  = "telemetry-missing"    // no worker observability and no env-wired error sink
	RuleTelemetryDisabled = "telemetry-disabled"   // observability.enabled is false somewhere
	RuleSinkCommitted     = "sink-committed"       // a DSN is committed instead of supplied by runtime env
	RuleClientError       = "client-error-missing" // no browser "error" listener
	RuleClientRejection   = "client-rejection-missing"
	RuleClientCSP         = "client-csp-missing" // no "securitypolicyviolation" listener
	RuleClientForward     = "client-forward-missing"
	RuleBeaconCrossOrigin = "beacon-cross-origin" // strict connect-src 'self' but events go off-origin
	RuleUnreadable        = "unreadable"          // --strict: a directory or file could not be read
	RuleTruncated         = "truncated"           // --strict: the scan stopped at a limit
)

// Rules lists every rule ID that observability.allow may name.
var Rules = []string{
	RuleHealthMissing, RuleHealthStub, RuleTelemetryMissing, RuleTelemetryDisabled, RuleSinkCommitted,
	RuleClientError, RuleClientRejection, RuleClientCSP, RuleClientForward, RuleBeaconCrossOrigin,
}

// AllowAll in observability.allow opts the whole repository out.
const AllowAll = "*"

// KnownAllow reports whether a is a valid observability.allow entry.
func KnownAllow(a string) bool {
	if a == AllowAll {
		return true
	}
	for _, r := range Rules {
		if r == a {
			return true
		}
	}
	return false
}

// Default scan limits. A scan that reaches one is truncated.
const (
	DefaultMaxFiles = 50000
	DefaultMaxBytes = 4 << 20
)

// Options tune one audit.
type Options struct {
	// Allow is observability.allow: rule IDs whose findings are waived, or
	// AllowAll to opt the repository out entirely.
	Allow []string
	// MaxFiles and MaxBytes bound the scan; zero means the defaults.
	MaxFiles int
	MaxBytes int64
}

// Finding is one unmet invariant, located at path:line:col (1-based; 0:0 when
// the finding concerns a whole file or directory).
type Finding struct {
	Path      string `json:"path"`
	Line      int    `json:"line"`
	Col       int    `json:"col"`
	Rule      string `json:"rule"`
	Invariant string `json:"invariant"` // health | telemetry | client | scan
	Detail    string `json:"detail"`
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d:%d %s", f.Path, f.Line, f.Col, f.Rule) }

// Surface is a detected deployable surface and the evidence for it.
type Surface struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Line int    `json:"line"`
}

// Report is the result of one audit. Findings excludes waived and scan
// problems; Problems holds unreadable entries and truncations, which fail the
// audit only under --strict.
type Report struct {
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	Files    int       `json:"files"`
	Surfaces []Surface `json:"surfaces"`
	Findings []Finding `json:"findings"`
	Waived   int       `json:"waived"`
	Problems []Finding `json:"-"`
}

// ErrNotDir is returned when the audited path is not a directory.
var ErrNotDir = errors.New("not a directory")

type file struct {
	rel  string // slash-separated, relative to the audited root
	data []byte
}

// Audit walks root and returns its report. It returns an error only when root
// itself cannot be audited at all (missing, not a directory, unreadable).
func Audit(root string, opts Options) (*Report, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, ErrNotDir
	}
	if _, err := os.ReadDir(root); err != nil {
		return nil, err
	}
	return AuditFS(os.DirFS(root), opts)
}

// AuditFS audits the tree rooted at fsys's ".".
func AuditFS(fsys fs.FS, opts Options) (*Report, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = DefaultMaxFiles
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	for _, a := range opts.Allow {
		if a == AllowAll {
			// Opted out: nothing is read, so nothing can fail.
			return &Report{Status: StatusNotApplicable, Reason: "opted out by observability.allow",
				Surfaces: []Surface{}, Findings: []Finding{}}, nil
		}
	}
	files, problems := collect(fsys, opts)
	rep := &Report{Files: len(files), Surfaces: []Surface{}, Findings: []Finding{}, Problems: problems}

	a := analyze(files)
	rep.Surfaces = a.surfaces
	if len(a.surfaces) == 0 {
		rep.Status, rep.Reason = StatusNotApplicable, "no web, worker, or service surface"
		return rep, nil
	}
	allowed := map[string]bool{}
	for _, r := range opts.Allow {
		allowed[r] = true
	}
	for _, f := range a.check() {
		if allowed[f.Rule] {
			rep.Waived++
			continue
		}
		rep.Findings = append(rep.Findings, f)
	}
	Sort(rep.Findings)
	rep.Status = StatusPass
	if len(rep.Findings) > 0 {
		rep.Status = StatusFail
	}
	return rep, nil
}

// Sort orders findings by path, line, column, then rule.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Col != b.Col {
			return a.Col < b.Col
		}
		return a.Rule < b.Rule
	})
}

// skipDirs are never part of the audit: VCS metadata, dependencies, build
// output, caches, and code that is not deployed (tests, fixtures, examples).
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true, "bower_components": true,
	"dist": true, "build": true, "out": true, ".next": true, ".nuxt": true, ".svelte-kit": true, ".output": true,
	".wrangler": true, ".vercel": true, ".netlify": true, ".turbo": true, ".cache": true, "coverage": true,
	"target": true, "__pycache__": true, ".venv": true, "venv": true,
	"test": true, "tests": true, "__tests__": true, "testdata": true, "fixtures": true, "__fixtures__": true,
	"__mocks__": true, "e2e": true, "example": true, "examples": true,
}

// scanExt are the file types the audit reads.
var scanExt = map[string]bool{
	".go": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".cts": true,
	".jsx": true, ".tsx": true, ".svelte": true, ".vue": true, ".astro": true, ".html": true, ".htm": true,
	".py": true, ".rb": true, ".rs": true, ".json": true, ".jsonc": true, ".toml": true, ".yaml": true, ".yml": true,
}

var scanNames = map[string]bool{"_headers": true, "Procfile": true}

func isTestFile(name string) bool {
	if strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, "_test.py") || strings.HasPrefix(name, "test_") {
		return true
	}
	parts := strings.Split(name, ".")
	for _, p := range parts[1:] {
		if p == "test" || p == "spec" || p == "stories" {
			return true
		}
	}
	return false
}

func collect(fsys fs.FS, opts Options) ([]file, []Finding) {
	var files []file
	var problems []Finding
	truncated := false
	_ = fs.WalkDir(fsys, ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			shown := rel
			if d != nil && d.IsDir() || rel == "." {
				shown = strings.TrimSuffix(rel, "/") + "/"
			}
			problems = append(problems, Finding{Path: shown, Rule: RuleUnreadable, Invariant: "scan", Detail: "cannot read: " + errText(err)})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if rel != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !scanExt[strings.ToLower(path.Ext(name))] && !scanNames[name] || isTestFile(name) {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // links are not followed
		}
		if !d.Type().IsRegular() {
			problems = append(problems, Finding{Path: rel, Rule: RuleUnreadable, Invariant: "scan", Detail: "cannot read: not a regular file"})
			return nil
		}
		if len(files) >= opts.MaxFiles {
			if !truncated {
				truncated = true
				problems = append(problems, Finding{Path: "./", Rule: RuleTruncated, Invariant: "scan", Detail: fmt.Sprintf("stopped after %d files", opts.MaxFiles)})
			}
			return fs.SkipAll
		}
		data, short, err := readLimited(fsys, rel, opts.MaxBytes)
		if err != nil {
			problems = append(problems, Finding{Path: rel, Rule: RuleUnreadable, Invariant: "scan", Detail: "cannot read: " + errText(err)})
			return nil
		}
		if short {
			problems = append(problems, Finding{Path: rel, Rule: RuleTruncated, Invariant: "scan", Detail: fmt.Sprintf("read the first %d bytes only", opts.MaxBytes)})
		}
		files = append(files, file{rel: rel, data: data})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	Sort(problems)
	return files, problems
}

func readLimited(fsys fs.FS, p string, max int64) ([]byte, bool, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > max {
		return data[:max], true, nil
	}
	return data, false, nil
}

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// --- lexical rules -------------------------------------------------------
//
// Patterns are written with character classes (`[.]`, `[(]`) where a plain
// escape would let this file's own source text match them; the repository
// that ships the lint must audit as not-applicable.

var (
	// Surfaces.
	reGoServer   = regexp.MustCompile(`\bhttp[.]ListenAndServe(?:TLS)?[(]|&?http[.]Server[{]|[.]ListenAndServe(?:TLS)?[(]`)
	reNodeServer = regexp.MustCompile(`\b(?:express|fastify|Fastify)\(\s*\)|\bnew Hono\b|\bcreateServer\(|\bBun\.serve\(|\bDeno\.serve\(|\b(?:app|server)\.listen\(`)
	rePyServer   = regexp.MustCompile(`\bFlask\(__name__|\bFastAPI\(|\buvicorn\.run\(|\bweb\.run_app\(`)
	reProcfile   = regexp.MustCompile(`(?m)^web:`)
	reWebDep     = regexp.MustCompile(`"(?:next|nuxt|vite|astro|@sveltejs/kit|svelte|react-dom|vue|preact|solid-js|@remix-run/[a-z-]+|gatsby|parcel|webpack|@angular/core|lit|htmx\.org)"\s*:`)

	// Invariant 1: health.
	reHealthRoute = regexp.MustCompile("[\"'`](?:(?:GET|HEAD) )?(/healthz|/api/health)/?[\"'`]")
	reStatusWord  = regexp.MustCompile(`(?i)\bstatus\b`)
	reRuntimeSrc  = regexp.MustCompile(`(?i)\bprocess\.env\b|\bos\.Getenv\(|\bos\.LookupEnv\(|\bos\.environ\b|\bos\.getenv\(|\bimport\.meta\.env\b|\bDeno\.env\b|\benv\.[A-Za-z_]|\benv\[|\bENV\[|\bstd::env::var\(`)
	reReleaseWord = regexp.MustCompile(`(?i)release|commit|git_?sha|revision|version|build_?id|deploy_?id`)
	reBuildInfo   = regexp.MustCompile(`\bdebug\.ReadBuildInfo\(|vcs\.revision|CF_VERSION_METADATA`)

	// Invariant 2: telemetry.
	reSinkInit = regexp.MustCompile(`\bSentry\.init\(|\bsentry\.Init\(|\bsentry_sdk\.init\(|\bwithSentry\(|\bSentry\.withSentry\(|\bsentry\.NewClient\(|/envelope[/]|\bOTLP[A-Za-z]*Exporter\b|\botlptrace[a-z]*\.New\(|\bNodeSDK\(`)
	reSinkEnv  = regexp.MustCompile(`(?i)(?:process\.env|os\.Getenv\(|os\.LookupEnv\(|os\.environ|os\.getenv\(|import\.meta\.env|Deno\.env|\benv)[^\n]{0,48}(?:dsn|sentry|otel_exporter|otlp|sink|telemetry)`)
	reDSN      = regexp.MustCompile(`\bhttps?://[0-9a-f]{32}(?::[0-9a-f]{32})?@[A-Za-z0-9.-]+(?::\d+)?/\d+\b`)

	// Invariant 3: client capture.
	reListener = regexp.MustCompile("addEventListener\\(\\s*[\"'`](error|unhandledrejection|securitypolicyviolation)[\"'`]|\\bon(error|unhandledrejection|securitypolicyviolation)\\s*=[^=]")
	reForward  = regexp.MustCompile("\\bsendBeacon\\(\\s*([\"'`][^\"'`]*[\"'`])?|\\bfetch\\(\\s*([\"'`][^\"'`]*[\"'`])?")
	reCSPLine  = regexp.MustCompile(`(?i)\b(?:default|connect)-src\b[^\n]*`)
)

var clientExt = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".jsx": true, ".tsx": true,
	".svelte": true, ".vue": true, ".astro": true, ".html": true, ".htm": true,
}

var codeExt = map[string]bool{
	".go": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".cts": true,
	".jsx": true, ".tsx": true, ".svelte": true, ".vue": true, ".astro": true, ".py": true, ".rb": true, ".rs": true,
}

// webRoots are directories whose index.html marks a deployed web surface.
var webRoots = map[string]bool{".": true, "public": true, "static": true, "src": true, "app": true, "www": true, "site": true, "web": true}

type analysis struct {
	files    []file
	surfaces []Surface
	web      bool
	worker   bool
	wrangler []file
}

func analyze(files []file) *analysis {
	a := &analysis{files: files}
	for _, f := range files {
		name := path.Base(f.rel)
		ext := strings.ToLower(path.Ext(name))
		switch {
		case name == "wrangler.toml" || name == "wrangler.json" || name == "wrangler.jsonc":
			a.wrangler = append(a.wrangler, f)
			a.add(SurfaceWorker, f.rel, 1)
			if wranglerServesAssets(f) {
				a.add(SurfaceWeb, f.rel, 1)
			}
		case name == "package.json":
			if line, ok := firstLine(f.data, reWebDep); ok {
				a.add(SurfaceWeb, f.rel, line)
			}
		case name == "index.html" && webRoots[path.Dir(f.rel)]:
			a.add(SurfaceWeb, f.rel, 1)
		case name == "Procfile":
			if line, ok := firstLine(f.data, reProcfile); ok {
				a.add(SurfaceService, f.rel, line)
			}
		case name == "fly.toml":
			a.add(SurfaceService, f.rel, 1)
		case ext == ".go":
			if line, ok := firstLine(f.data, reGoServer); ok {
				a.add(SurfaceService, f.rel, line)
			}
		case ext == ".js" || ext == ".mjs" || ext == ".cjs" || ext == ".ts" || ext == ".mts" || ext == ".cts":
			if line, ok := firstLine(f.data, reNodeServer); ok {
				a.add(SurfaceService, f.rel, line)
			}
		case ext == ".py":
			if line, ok := firstLine(f.data, rePyServer); ok {
				a.add(SurfaceService, f.rel, line)
			}
		}
	}
	sort.SliceStable(a.surfaces, func(i, j int) bool {
		if a.surfaces[i].Kind != a.surfaces[j].Kind {
			return a.surfaces[i].Kind < a.surfaces[j].Kind
		}
		return a.surfaces[i].Path < a.surfaces[j].Path
	})
	return a
}

func (a *analysis) add(kind, p string, line int) {
	for _, s := range a.surfaces {
		if s.Kind == kind && s.Path == p {
			return
		}
	}
	a.surfaces = append(a.surfaces, Surface{Kind: kind, Path: p, Line: line})
	switch kind {
	case SurfaceWeb:
		a.web = true
	case SurfaceWorker:
		a.worker = true
	}
}

// anchor is where a finding about a missing thing is reported: the first
// detected surface of the preferred kinds, else the first surface.
func (a *analysis) anchor(kinds ...string) (string, int) {
	for _, k := range kinds {
		for _, s := range a.surfaces {
			if s.Kind == k {
				return s.Path, s.Line
			}
		}
	}
	return a.surfaces[0].Path, a.surfaces[0].Line
}

func (a *analysis) check() []Finding {
	var out []Finding
	out = append(out, a.checkHealth()...)
	out = append(out, a.checkTelemetry()...)
	if a.web {
		out = append(out, a.checkClient()...)
	}
	return out
}

// healthWindow is how many lines from the route, or from the handler it
// names, may hold the status and release identity it reports.
const healthWindow = 15

// Invariant 1: a real health route.
func (a *analysis) checkHealth() []Finding {
	var stub *Finding
	for _, f := range a.files {
		if !codeExt[strings.ToLower(path.Ext(f.rel))] {
			continue
		}
		lns := bytes.Split(f.data, []byte("\n"))
		for _, loc := range reHealthRoute.FindAllIndex(f.data, -1) {
			line, col := lineCol(f.data, loc[0]+1)
			if realHealth(lns, line-1) {
				return nil
			}
			// The route may name its handler: mux.HandleFunc("/healthz", health).
			rest := string(lns[line-1][min(loc[1]-lineStart(f.data, loc[1]), len(lns[line-1])):])
			if m := reHandlerRef.FindStringSubmatch(rest); m != nil {
				name := m[1][strings.LastIndex(m[1], ".")+1:]
				def := regexp.MustCompile(`^\s*(?:func(?:\s*\([^)]*\))?|(?:export\s+)?(?:async\s+)?function|def|async\s+def|(?:export\s+)?(?:const|let|var))\s+` + regexp.QuoteMeta(name) + `\b`)
				for i, ln := range lns {
					if def.Match(ln) && realHealth(lns, i) {
						return nil
					}
				}
			}
			if stub == nil {
				stub = &Finding{Path: f.rel, Line: line, Col: col, Rule: RuleHealthStub, Invariant: "health",
					Detail: "health route reports no status with a release identity read at runtime"}
			}
		}
	}
	if stub != nil {
		return []Finding{*stub}
	}
	p, line := a.anchor(SurfaceService, SurfaceWorker, SurfaceWeb)
	return []Finding{{Path: p, Line: line, Col: 1, Rule: RuleHealthMissing, Invariant: "health",
		Detail: "no /healthz or /api/health route"}}
}

var reHandlerRef = regexp.MustCompile(`^[^,]*,\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\)`)

func lineStart(data []byte, off int) int { return bytes.LastIndexByte(data[:off], '\n') + 1 }

// realHealth reports whether lines [from, from+healthWindow) report a status
// and a release identity read from the runtime: a line that reads env and
// names a release, or Go build info.
func realHealth(lns [][]byte, from int) bool {
	status, release := false, false
	for i := from; i < len(lns) && i < from+healthWindow; i++ {
		ln := lns[i]
		status = status || reStatusWord.Match(ln)
		release = release || reBuildInfo.Match(ln) || reRuntimeSrc.Match(ln) && reReleaseWord.Match(ln)
	}
	return status && release
}

// Invariant 2: production telemetry and server error capture.
func (a *analysis) checkTelemetry() []Finding {
	var out []Finding
	enabled := false
	for _, w := range a.wrangler {
		st := wranglerObservability(w)
		if st.enabled {
			enabled = true
		}
		for _, at := range st.disabled {
			out = append(out, Finding{Path: w.rel, Line: at[0], Col: at[1], Rule: RuleTelemetryDisabled, Invariant: "telemetry",
				Detail: "observability.enabled is false"})
		}
	}
	forwarded := false
	for _, f := range a.files {
		if loc := reDSN.FindIndex(f.data); loc != nil {
			line, col := lineCol(f.data, loc[0])
			out = append(out, Finding{Path: f.rel, Line: line, Col: col, Rule: RuleSinkCommitted, Invariant: "telemetry",
				Detail: "an error-sink DSN is committed; supply it from runtime env"})
		}
		if codeExt[strings.ToLower(path.Ext(f.rel))] && reSinkInit.Match(f.data) && reSinkEnv.Match(f.data) {
			forwarded = true
		}
	}
	if !enabled && !forwarded {
		p, line := a.anchor(SurfaceWorker, SurfaceService, SurfaceWeb)
		detail := "no observability.enabled and no server error forwarding to an env-supplied sink"
		out = append(out, Finding{Path: p, Line: line, Col: 1, Rule: RuleTelemetryMissing, Invariant: "telemetry", Detail: detail})
	}
	return out
}

// Invariant 3: client error and CSP capture.
func (a *analysis) checkClient() []Finding {
	seen := map[string]bool{}
	forward := false
	var targets []string
	var targetAt Finding
	strict := false
	strictAt := Finding{}
	for _, f := range a.files {
		ext := strings.ToLower(path.Ext(f.rel))
		if path.Base(f.rel) == "_headers" || clientExt[ext] || codeExt[ext] {
			if line, col, ok := strictCSP(f.data); ok && !strict {
				strict = true
				strictAt = Finding{Path: f.rel, Line: line, Col: col}
			}
		}
		if !clientExt[ext] {
			continue
		}
		ms := reListener.FindAllSubmatch(f.data, -1)
		if len(ms) == 0 {
			continue
		}
		for _, m := range ms {
			ev := string(m[1])
			if ev == "" {
				ev = string(m[2])
			}
			seen[ev] = true
		}
		for _, m := range reForward.FindAllSubmatchIndex(f.data, -1) {
			forward = true
			for _, g := range []int{2, 4} {
				if m[g] >= 0 {
					lit := string(f.data[m[g]+1 : m[g+1]-1])
					targets = append(targets, lit)
					if targetAt.Path == "" && !sameOrigin(lit) {
						line, col := lineCol(f.data, m[0])
						targetAt = Finding{Path: f.rel, Line: line, Col: col}
					}
				}
			}
		}
	}
	p, line := a.anchor(SurfaceWeb)
	var out []Finding
	for _, c := range []struct{ ev, rule string }{
		{"error", RuleClientError},
		{"unhandledrejection", RuleClientRejection},
		{"securitypolicyviolation", RuleClientCSP},
	} {
		if !seen[c.ev] {
			out = append(out, Finding{Path: p, Line: line, Col: 1, Rule: c.rule, Invariant: "client",
				Detail: fmt.Sprintf("no browser %q listener", c.ev)})
		}
	}
	if len(seen) > 0 && !forward {
		out = append(out, Finding{Path: p, Line: line, Col: 1, Rule: RuleClientForward, Invariant: "client",
			Detail: "browser listeners forward nothing (no sendBeacon or fetch beside them)"})
	}
	if strict && forward && len(targets) > 0 {
		same := false
		for _, t := range targets {
			if sameOrigin(t) {
				same = true
			}
		}
		if !same {
			f := targetAt
			if f.Path == "" {
				f = strictAt
			}
			f.Rule, f.Invariant = RuleBeaconCrossOrigin, "client"
			f.Detail = fmt.Sprintf("strict connect-src 'self' (%s:%d) but events are sent off-origin; use a same-origin beacon", strictAt.Path, strictAt.Line)
			out = append(out, f)
		}
	}
	return out
}

// sameOrigin reports whether a literal request target is a same-origin path.
func sameOrigin(t string) bool {
	return strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//")
}

// strictCSP finds a policy whose effective connect-src is exactly 'self'.
func strictCSP(data []byte) (int, int, bool) {
	for _, loc := range reCSPLine.FindAllIndex(data, -1) {
		policy := string(data[loc[0]:loc[1]])
		// The policy text ends at the closing quote of the string or attribute holding it.
		if i := strings.IndexAny(policy, "\"`"); i >= 0 {
			policy = policy[:i]
		}
		dirs := map[string][]string{}
		for _, d := range strings.Split(policy, ";") {
			fs := strings.Fields(strings.ToLower(d))
			if len(fs) == 0 {
				continue
			}
			if _, dup := dirs[fs[0]]; !dup {
				dirs[fs[0]] = fs[1:]
			}
		}
		src, ok := dirs["connect-src"]
		if !ok {
			src, ok = dirs["default-src"]
		}
		if ok && len(src) == 1 && strings.Trim(src[0], "',") == "self" {
			line, col := lineCol(data, loc[0])
			return line, col, true
		}
	}
	return 0, 0, false
}

// --- wrangler configuration ----------------------------------------------

type obsState struct {
	enabled  bool     // top-level observability.enabled = true
	disabled [][2]int // line, col of every observability.enabled = false (any environment)
}

func wranglerObservability(f file) obsState {
	if strings.HasSuffix(f.rel, ".toml") {
		return tomlObservability(f.data)
	}
	return jsonObservability(f.data)
}

func wranglerServesAssets(f file) bool {
	if strings.HasSuffix(f.rel, ".toml") {
		return reTOMLAssets.Match(f.data)
	}
	var m map[string]any
	if json.Unmarshal(stripJSONC(f.data), &m) != nil {
		return false
	}
	_, a := m["assets"]
	_, s := m["site"]
	return a || s
}

var (
	reTOMLAssets  = regexp.MustCompile(`(?m)^\s*(?:\[assets\]|\[site\]|assets\s*=|site\s*=)`)
	reTOMLArray   = regexp.MustCompile(`^\s*\[\[`)
	reTOMLTable   = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9_."-]+)\s*\]\s*(?:#.*)?$`)
	reTOMLEnabled = regexp.MustCompile(`^\s*((?:[A-Za-z0-9_-]+\.)*)enabled\s*=\s*(true|false)\b`)
	reTOMLInline  = regexp.MustCompile(`^\s*((?:[A-Za-z0-9_-]+\.)*)observability\s*=\s*\{[^}]*\benabled\s*=\s*(true|false)\b`)
)

func tomlObservability(data []byte) obsState {
	var st obsState
	table := ""
	for i, raw := range strings.Split(string(data), "\n") {
		ln := raw
		if j := strings.Index(ln, "#"); j >= 0 && !strings.Contains(ln[:j], "\"") {
			ln = ln[:j]
		}
		if reTOMLArray.MatchString(ln) {
			table = "[[array]]"
			continue
		}
		if m := reTOMLTable.FindStringSubmatch(ln); m != nil {
			table = strings.ReplaceAll(m[1], "\"", "")
			continue
		}
		key, val := "", ""
		if m := reTOMLInline.FindStringSubmatch(ln); m != nil {
			key, val = join(table, m[1]+"observability"), m[2]
		} else if m := reTOMLEnabled.FindStringSubmatch(ln); m != nil {
			key, val = strings.TrimSuffix(join(table, m[1]), "."), m[2]
		} else {
			continue
		}
		key = strings.TrimSuffix(key, ".")
		if key != "observability" && !(strings.HasPrefix(key, "env.") && strings.HasSuffix(key, ".observability")) {
			continue
		}
		switch {
		case val == "false":
			st.disabled = append(st.disabled, [2]int{i + 1, strings.LastIndex(ln, "false") + 1})
		case key == "observability":
			st.enabled = true
		}
	}
	return st
}

func join(table, dotted string) string {
	if table == "" {
		return dotted
	}
	return table + "." + dotted
}

func jsonObservability(data []byte) obsState {
	var st obsState
	clean := stripJSONC(data)
	var m map[string]any
	if json.Unmarshal(clean, &m) != nil {
		return st // unparsable: telemetry is not proven, so telemetry-missing follows
	}
	if o, ok := m["observability"].(map[string]any); ok {
		if e, ok := o["enabled"].(bool); ok && e {
			st.enabled = true
		}
	}
	st.disabled = jsonDisabledLines(clean)
	return st
}

// jsonDisabledLines returns the line of every `"enabled": false` that sits
// directly inside an "observability" object (top level or any environment).
// clean has its comments stripped with line breaks preserved.
func jsonDisabledLines(clean []byte) [][2]int {
	var out [][2]int
	key := []byte(`"observability"`)
	for off := 0; ; {
		i := bytes.Index(clean[off:], key)
		if i < 0 {
			break
		}
		i += off + len(key)
		off = i
		j := skipSpace(clean, i)
		if j >= len(clean) || clean[j] != ':' {
			continue
		}
		j = skipSpace(clean, j+1)
		if j >= len(clean) || clean[j] != '{' {
			continue
		}
		depth := 0
		for k := j; k < len(clean); k++ {
			switch c := clean[k]; {
			case c == '"':
				end := k + 1
				for end < len(clean) && clean[end] != '"' {
					if clean[end] == '\\' {
						end++
					}
					end++
				}
				if depth == 1 && string(clean[k:min(end+1, len(clean))]) == `"enabled"` {
					v := skipSpace(clean, end+1)
					if v < len(clean) && clean[v] == ':' {
						v = skipSpace(clean, v+1)
						if bytes.HasPrefix(clean[v:], []byte("false")) {
							l, c := lineCol(clean, v)
							out = append(out, [2]int{l, c})
						}
					}
				}
				k = end
			case c == '{' || c == '[':
				depth++
			case c == '}' || c == ']':
				depth--
			}
			if depth == 0 {
				break
			}
		}
	}
	return out
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// stripJSONC removes // and /* */ comments outside strings and trailing commas.
func stripJSONC(data []byte) []byte {
	var out bytes.Buffer
	inStr, esc := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out.WriteByte(c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out.WriteByte(c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				if data[i] == '\n' {
					out.WriteByte('\n')
				}
				i++
			}
			i++
		default:
			out.WriteByte(c)
		}
	}
	return regexp.MustCompile(`,(\s*[}\]])`).ReplaceAll(out.Bytes(), []byte("$1"))
}

// --- helpers -------------------------------------------------------------

func firstLine(data []byte, re *regexp.Regexp) (int, bool) {
	loc := re.FindIndex(data)
	if loc == nil {
		return 0, false
	}
	l, _ := lineCol(data, loc[0])
	return l, true
}

// lineCol converts a byte offset to a 1-based line and column (in bytes).
func lineCol(data []byte, off int) (int, int) {
	if off > len(data) {
		off = len(data)
	}
	line := 1 + bytes.Count(data[:off], []byte("\n"))
	col := off - bytes.LastIndexByte(data[:off], '\n')
	return line, col
}
