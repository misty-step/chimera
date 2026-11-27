package obslint

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fixture copies testdata/<name> into a fresh directory and applies edits:
// "path" → content ("" deletes the file).
func fixture(t *testing.T, name string, edits map[string]string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", name)
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return write(filepath.Join(dst, rel), string(data))
	})
	if err != nil {
		t.Fatal(err)
	}
	for p, body := range edits {
		abs := filepath.Join(dst, filepath.FromSlash(p))
		if body == "" {
			if err := os.Remove(abs); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := write(abs, body); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func write(p, body string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(body), 0o644)
}

// replaced returns testdata/<name>/<file> with old replaced by new, failing
// the test if old does not occur.
func replaced(t *testing.T, name, file, old, new string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name, filepath.FromSlash(file)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%s/%s does not contain %q", name, file, old)
	}
	return strings.ReplaceAll(string(data), old, new)
}

func audit(t *testing.T, dir string, opts Options) *Report {
	t.Helper()
	rep, err := Audit(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func lines(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.String())
	}
	return out
}

func TestM2_4_PassingWebWorkerWithSameOriginBeacon(t *testing.T) {
	rep := audit(t, fixture(t, "webworker", nil), Options{})
	if rep.Status != StatusPass || len(rep.Findings) != 0 || len(rep.Problems) != 0 {
		t.Fatalf("%+v", rep)
	}
	want := []Surface{{SurfaceWeb, "public/index.html", 1}, {SurfaceWeb, "wrangler.jsonc", 1}, {SurfaceWorker, "wrangler.jsonc", 1}}
	if !reflect.DeepEqual(rep.Surfaces, want) {
		t.Fatalf("surfaces %+v", rep.Surfaces)
	}
}

func TestM2_4_GoServiceWithEnvSuppliedSinkPasses(t *testing.T) {
	rep := audit(t, fixture(t, "goservice", nil), Options{})
	if rep.Status != StatusPass || !reflect.DeepEqual(rep.Surfaces, []Surface{{SurfaceService, "main.go", 21}}) {
		t.Fatalf("%+v", rep)
	}
}

func TestM2_4_MissingHealthTelemetryOrCSPForwardingFails(t *testing.T) {
	worker := func(old, new string) map[string]string {
		return map[string]string{"src/worker.ts": replaced(t, "webworker", "src/worker.ts", old, new)}
	}
	client := func(old, new string) map[string]string {
		return map[string]string{"public/errors.js": replaced(t, "webworker", "public/errors.js", old, new)}
	}
	wrangler := func(old, new string) map[string]string {
		return map[string]string{"wrangler.jsonc": replaced(t, "webworker", "wrangler.jsonc", old, new)}
	}
	cases := []struct {
		name  string
		fix   string
		edits map[string]string
		want  []string
	}{
		{"no health route", "webworker", worker(`"/api/health"`, `"/api/status"`),
			[]string{"wrangler.jsonc:1:1 health-missing"}},
		{"hardcoded health stub", "webworker",
			worker(`environment: env.ENVIRONMENT, release: env.RELEASE });`, `release: "v1.2.3" });`),
			[]string{"src/worker.ts:18:29 health-stub"}},
		{"telemetry absent", "webworker", merge(noForward(t), wrangler(`"enabled": true,
    "logs"`, `"logs"`)), []string{"wrangler.jsonc:1:1 telemetry-missing"}},
		{"telemetry switched off", "webworker", wrangler(`"enabled": true,
    "logs"`, `"enabled": false,
    "logs"`), []string{"wrangler.jsonc:8:16 telemetry-disabled"}},
		{"telemetry switched off, nothing forwarded", "webworker", merge(noForward(t), wrangler(`"enabled": true,
    "logs"`, `"enabled": false,
    "logs"`)), []string{"wrangler.jsonc:8:16 telemetry-disabled", "wrangler.jsonc:1:1 telemetry-missing"}},
		{"telemetry off in one environment", "webworker", wrangler(`"observability": { "enabled": true },`, `"observability": { "enabled": false },`),
			[]string{"wrangler.jsonc:13:37 telemetry-disabled"}},
		{"no securitypolicyviolation listener", "webworker", client(`document.addEventListener("securitypolicyviolation"`, `document.addEventListener("visibilitychange"`),
			[]string{"public/index.html:1:1 client-csp-missing"}},
		{"no browser listeners at all", "webworker", map[string]string{"public/errors.js": "console.log('hi');\n"},
			[]string{"public/index.html:1:1 client-csp-missing", "public/index.html:1:1 client-error-missing", "public/index.html:1:1 client-rejection-missing"}},
		{"listeners that forward nothing", "webworker", client(`    if (!navigator.sendBeacon("/api/client-errors", body)) {
      fetch(BEACON, { method: "POST", body, keepalive: true });
    }`, `    console.log(body);`),
			[]string{"public/index.html:1:1 client-forward-missing"}},
		{"cross-origin forwarding under connect-src 'self'", "webworker", client(`    if (!navigator.sendBeacon("/api/client-errors", body)) {
      fetch(BEACON, { method: "POST", body, keepalive: true });
    }`, `    fetch("https://errors.example.com/api/1/store/", { method: "POST", body });`),
			[]string{"public/errors.js:10:5 beacon-cross-origin"}},
		{"committed DSN", "goservice", map[string]string{"main.go": replaced(t, "goservice", "main.go", `os.Getenv("SENTRY_DSN")`,
			`"https://`+strings.Repeat("ab", 16)+`@o1.ingest.example.com/42"`)},
			[]string{"main.go:16:51 sink-committed", "main.go:21:1 telemetry-missing"}},
		{"service without error forwarding", "goservice", map[string]string{"main.go": replaced(t, "goservice", "main.go", `sentry.Init(`, `setup(`)},
			[]string{"main.go:21:1 telemetry-missing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := audit(t, fixture(t, tc.fix, tc.edits), Options{})
			got := lines(rep.Findings)
			want := append([]string{}, tc.want...)
			sortStrings(want, rep.Findings)
			if rep.Status != StatusFail || !reflect.DeepEqual(got, want) {
				t.Fatalf("status %s\n got %q\nwant %q", rep.Status, got, want)
			}
		})
	}
}

// sortStrings orders want the way Sort orders findings, so cases can list
// expectations in any order.
func sortStrings(want []string, _ []Finding) {
	fs := make([]Finding, len(want))
	for i, w := range want {
		loc, rule, _ := strings.Cut(w, " ")
		parts := strings.Split(loc, ":")
		fs[i] = Finding{Path: parts[0], Line: atoi(parts[1]), Col: atoi(parts[2]), Rule: rule}
	}
	Sort(fs)
	for i, f := range fs {
		want[i] = f.String()
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// noForward removes the worker's server-side error forwarding.
func noForward(t *testing.T) map[string]string {
	return map[string]string{"src/worker.ts": replaced(t, "webworker", "src/worker.ts", "/envelope/", "/store/")}
}

func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func TestM2_4_WorkerTelemetryIsObservabilityOrForwarding(t *testing.T) {
	// PRODUCT.md [M2-4] invariant 2 is satisfied by either one.
	noObs := map[string]string{"wrangler.jsonc": replaced(t, "webworker", "wrangler.jsonc", `"enabled": true,
    "logs"`, `"logs"`)}
	if rep := audit(t, fixture(t, "webworker", noObs), Options{}); rep.Status != StatusPass {
		t.Fatalf("env-wired forwarding alone: %q", lines(rep.Findings))
	}
	if rep := audit(t, fixture(t, "webworker", noForward(t)), Options{}); rep.Status != StatusPass {
		t.Fatalf("observability.enabled alone: %q", lines(rep.Findings))
	}
}

func TestM2_4_PureCLILibraryIsNotApplicable(t *testing.T) {
	rep := audit(t, fixture(t, "library", nil), Options{})
	if rep.Status != StatusNotApplicable || len(rep.Surfaces) != 0 || len(rep.Findings) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestM2_4_TestsDependenciesAndBuildOutputAreNotAudited(t *testing.T) {
	server := "package main\n\nimport \"net/http\"\n\nfunc main() { http.ListenAndServe(\":0\", nil) }\n"
	dir := fixture(t, "library", map[string]string{
		"server_test.go":                server,
		"testdata/srv/main.go":          server,
		"examples/srv/main.go":          server,
		"node_modules/x/index.js":       "require('http').createServer(() => {}).listen(0)\n",
		"dist/index.html":               "<!doctype html>\n",
		"web/app.spec.ts":               "app.listen(0)\n",
		".wrangler/tmp/wrangler.jsonc":  "{}\n",
		"internal/fake/fake_server.txt": server,
	})
	if rep := audit(t, dir, Options{}); rep.Status != StatusNotApplicable {
		t.Fatalf("%+v", rep)
	}
}

func TestM2_4_RepositoryItselfIsNotApplicable(t *testing.T) {
	rep := audit(t, filepath.Join("..", ".."), Options{})
	if rep.Status != StatusNotApplicable || len(rep.Problems) != 0 {
		t.Fatalf("chimera audits itself as %s: surfaces %+v problems %+v", rep.Status, rep.Surfaces, rep.Problems)
	}
}

func TestM2_4_AllowOptOutIsHonored(t *testing.T) {
	broken := map[string]string{"src/worker.ts": replaced(t, "webworker", "src/worker.ts", `"/api/health"`, `"/api/status"`)}
	if rep := audit(t, fixture(t, "webworker", broken), Options{Allow: []string{AllowAll}}); rep.Status != StatusNotApplicable || rep.Reason != "opted out by observability.allow" {
		t.Fatalf("%+v", rep)
	}
	rep := audit(t, fixture(t, "webworker", broken), Options{Allow: []string{RuleHealthMissing}})
	if rep.Status != StatusPass || rep.Waived != 1 {
		t.Fatalf("%+v", rep)
	}
	if !KnownAllow(AllowAll) || !KnownAllow(RuleClientCSP) || KnownAllow("health") || KnownAllow(RuleUnreadable) {
		t.Fatal("KnownAllow")
	}
}

func TestM2_4_WranglerTOML(t *testing.T) {
	base := map[string]string{"wrangler.jsonc": "", "wrangler.toml": `name = "acme-widget"
main = "src/worker.ts"

[assets]
directory = "./public"

[observability]
enabled = true

[observability.logs]
enabled = false

[[routes]]
pattern = "widget.example.com/*"
`}
	if rep := audit(t, fixture(t, "webworker", base), Options{}); rep.Status != StatusPass || len(rep.Surfaces) != 3 {
		t.Fatalf("%+v", rep)
	}
	for name, tc := range map[string]struct{ toml, want string }{
		"assets only":    {`name = "acme-widget"` + "\n[assets]\ndirectory = \"./public\"\n", "wrangler.toml:1:1 telemetry-missing"},
		"off":            {"observability = { enabled = false }\n", "wrangler.toml:1:29 telemetry-disabled"},
		"dotted off":     {"observability.enabled = true\n\n[env.production.observability]\nenabled = false # muted\n", "wrangler.toml:4:11 telemetry-disabled"},
		"env inline off": {"[observability]\nenabled = true\n[env.production]\nobservability = { enabled = false }\n", "wrangler.toml:4:29 telemetry-disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			rep := audit(t, fixture(t, "webworker", merge(noForward(t), map[string]string{"wrangler.jsonc": "", "wrangler.toml": tc.toml})), Options{})
			found := false
			for _, f := range rep.Findings {
				if f.String() == tc.want {
					found = true
				}
			}
			if rep.Status != StatusFail || !found {
				t.Fatalf("want %s in %q", tc.want, lines(rep.Findings))
			}
		})
	}
}

func TestM2_4_StrictCSPDetection(t *testing.T) {
	for policy, strict := range map[string]bool{
		`default-src 'self'`:                                true,
		`default-src 'self'; connect-src 'self'`:            true,
		`default-src 'none'; connect-src 'self'; img-src *`: true,
		`connect-src 'self' https://errors.example.com`:     false,
		`default-src 'self'; connect-src *`:                 false,
		`script-src 'self'`:                                 false,
	} {
		_, _, got := strictCSP([]byte(`<meta http-equiv="Content-Security-Policy" content="` + policy + `">`))
		if got != strict {
			t.Errorf("%s: strict=%v", policy, got)
		}
	}
	// Without a strict policy, off-origin forwarding is allowed.
	dir := fixture(t, "webworker", map[string]string{
		"public/_headers":   "/*\n  X-Frame-Options: DENY\n",
		"public/index.html": replaced(t, "webworker", "public/index.html", `default-src 'self'; connect-src 'self'`, `default-src 'self'; connect-src 'self' https://errors.example.com`),
		"public/errors.js":  replaced(t, "webworker", "public/errors.js", `navigator.sendBeacon("/api/client-errors", body)`, `navigator.sendBeacon("https://errors.example.com/b", body)`),
	})
	if rep := audit(t, dir, Options{}); rep.Status != StatusPass {
		t.Fatalf("%q", lines(rep.Findings))
	}
}

func TestM2_4_TruncatedScanIsAProblem(t *testing.T) {
	dir := fixture(t, "webworker", nil)
	rep := audit(t, dir, Options{MaxFiles: 2})
	if len(rep.Problems) != 1 || rep.Problems[0].String() != "./:0:0 truncated" {
		t.Fatalf("%+v", rep.Problems)
	}
	rep = audit(t, dir, Options{MaxBytes: 64})
	if got := lines(rep.Problems); len(got) != 5 || got[0] != "public/_headers:0:0 truncated" {
		t.Fatalf("%q", got)
	}
}

func TestM2_4_AuditIsDeterministic(t *testing.T) {
	dir := fixture(t, "webworker", map[string]string{"public/errors.js": "console.log(1)\n"})
	a, b := audit(t, dir, Options{}), audit(t, dir, Options{})
	if !reflect.DeepEqual(a, b) || len(a.Findings) != 3 {
		t.Fatalf("%+v\n%+v", a, b)
	}
}

func TestM2_4_AuditRefusesWhatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Audit(filepath.Join(dir, "missing"), Options{}); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o644)
	if _, err := Audit(f, Options{}); err != ErrNotDir {
		t.Fatalf("file: %v", err)
	}
}

// denyFS fails every Open of the named paths, as an unreadable file or
// directory does.
type denyFS struct {
	fs.FS
	deny map[string]bool
}

func (d denyFS) Open(name string) (fs.File, error) {
	if d.deny[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.FS.Open(name)
}

func TestM2_4_UnreadableEntriesAreProblems(t *testing.T) {
	dir := fixture(t, "webworker", nil)
	rep, err := AuditFS(denyFS{os.DirFS(dir), map[string]bool{"src": true, "public/errors.js": true}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"public/errors.js:0:0 unreadable", "src/:0:0 unreadable"}
	if got := lines(rep.Problems); !reflect.DeepEqual(got, want) {
		t.Fatalf("problems %q", got)
	}
	// What was not read cannot satisfy an invariant: the health route and the
	// browser listeners lived in the unreadable entries.
	if rep.Status != StatusFail || len(rep.Findings) == 0 {
		t.Fatalf("%+v", rep)
	}
	// Opting out reads nothing at all.
	rep, _ = AuditFS(denyFS{os.DirFS(dir), map[string]bool{"src": true}}, Options{Allow: []string{AllowAll}})
	if rep.Status != StatusNotApplicable || len(rep.Problems) != 0 {
		t.Fatalf("%+v", rep)
	}
}
