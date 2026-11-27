package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// obsFixture copies pkg/obslint/testdata/<name> into a fresh directory and
// applies edits ("" deletes a file).
func obsFixture(t *testing.T, name string, edits map[string]string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("..", "..", "pkg", "obslint", "testdata", name)
	files := map[string]string{}
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		data, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for p, body := range edits {
		if body == "" {
			delete(files, p)
			continue
		}
		files[p] = body
	}
	writeFiles(t, dst, files)
	return dst
}

func readFixture(t *testing.T, name, file string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "pkg", "obslint", "testdata", name, filepath.FromSlash(file)))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func decodeObs(t *testing.T, stdout string) obsResult {
	t.Helper()
	if strings.Count(stdout, "\n") != 1 {
		t.Fatalf("stdout is not one JSON line: %q", stdout)
	}
	var r obsResult
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("%v: %q", err, stdout)
	}
	if r.Schema != "chimera.lint/v1" || r.Check != "observability" {
		t.Fatalf("%+v", r)
	}
	return r
}

func TestM2_4_PassingWebWorkerRepoExits0(t *testing.T) {
	dir := obsFixture(t, "webworker", nil)
	r := run(t, dir, nil, "lint", "observability")
	if r.code != ExitOK || r.stdout != "" || r.stderr != "lint observability: PASS  5 files, surfaces web, worker, 0 findings, 0 waived\n" {
		t.Fatalf("%+v", r)
	}
	// <dir> as an argument, and --json.
	r = run(t, t.TempDir(), nil, "lint", "observability", dir, "--json")
	j := decodeObs(t, r.stdout)
	if r.code != ExitOK || j.Status != "pass" || len(j.Findings) != 0 || len(j.Surfaces) != 3 || j.Files != 5 {
		t.Fatalf("%+v %+v", r, j)
	}
	if r := run(t, dir, nil, "lint", "observability", "--strict"); r.code != ExitOK {
		t.Fatalf("--strict on a clean, readable repo: %+v", r)
	}
}

func TestM2_4_RepoMissingHealthTelemetryOrCSPForwardingExits1(t *testing.T) {
	worker := readFixture(t, "webworker", "src/worker.ts")
	wrangler := readFixture(t, "webworker", "wrangler.jsonc")
	errorsJS := readFixture(t, "webworker", "public/errors.js")
	cases := map[string]struct {
		edits map[string]string
		want  string
	}{
		"health": {map[string]string{"src/worker.ts": strings.Replace(worker, `"/api/health"`, `"/status"`, 1)},
			"wrangler.jsonc:1:1 health-missing\n"},
		"telemetry": {map[string]string{
			"src/worker.ts":  strings.Replace(worker, "/envelope/", "/store/", 1),
			"wrangler.jsonc": strings.Replace(wrangler, `"enabled": true,`+"\n", "", 1),
		}, "wrangler.jsonc:1:1 telemetry-missing\n"},
		"csp forwarding": {map[string]string{"public/errors.js": strings.Replace(errorsJS, `"securitypolicyviolation"`, `"visibilitychange"`, 1)},
			"public/index.html:1:1 client-csp-missing\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := obsFixture(t, "webworker", tc.edits)
			r := run(t, dir, nil, "lint", "observability")
			if r.code != ExitError || r.stdout != tc.want {
				t.Fatalf("%+v", r)
			}
			oneLowercaseErrorLine(t, nil, r.stderr)
			if !strings.HasPrefix(r.stderr, "chimera: lint observability: .: 1 findings (rule ") {
				t.Fatalf("%q", r.stderr)
			}
			// --json: one chimera.lint/v1 object carrying structured findings.
			r = run(t, filepath.Dir(dir), nil, "lint", "observability", filepath.Base(dir), "--json")
			j := decodeObs(t, r.stdout)
			if r.code != ExitError || j.Status != "fail" || len(j.Findings) != 1 {
				t.Fatalf("%+v %+v", r, j)
			}
			f := j.Findings[0]
			if want := filepath.Base(dir) + "/" + tc.want; f.String()+"\n" != want || f.Invariant == "" || f.Detail == "" {
				t.Fatalf("%+v, want %q", f, want)
			}
			oneLowercaseErrorLine(t, nil, r.stderr)
		})
	}
}

func TestM2_4_PureCLILibraryExits0NotApplicable(t *testing.T) {
	dir := obsFixture(t, "library", nil)
	r := run(t, dir, nil, "lint", "observability")
	if r.code != ExitOK || r.stdout != "" || r.stderr != "lint observability: not-applicable  2 files, no web, worker, or service surface\n" {
		t.Fatalf("%+v", r)
	}
	r = run(t, dir, nil, "lint", "observability", "--json", "--strict")
	if j := decodeObs(t, r.stdout); r.code != ExitOK || j.Status != "not-applicable" || j.Reason == "" || len(j.Surfaces) != 0 {
		t.Fatalf("%+v %+v", r, j)
	}
}

func TestM2_4_ObservabilityAllowOptOutIsHonored(t *testing.T) {
	broken := map[string]string{"public/errors.js": "console.log(1)\n"}
	dir := obsFixture(t, "webworker", broken)
	if r := run(t, dir, nil, "lint", "observability"); r.code != ExitError {
		t.Fatalf("before the opt-out: %+v", r)
	}
	// The audited repository's chimera.yaml opts it out.
	writeFiles(t, dir, map[string]string{"chimera.yaml": "observability:\n  allow: [\"*\"]\n"})
	r := run(t, t.TempDir(), nil, "lint", "observability", dir, "--json")
	j := decodeObs(t, r.stdout)
	if r.code != ExitOK || j.Status != "not-applicable" || j.Reason != "opted out by observability.allow" || len(j.Findings) != 0 {
		t.Fatalf("%+v %+v", r, j)
	}
	// Named rules are waived and counted; the rest still fail.
	writeFiles(t, dir, map[string]string{"chimera.yaml": "observability:\n  allow: [client-error-missing, client-rejection-missing]\n"})
	r = run(t, dir, nil, "lint", "observability")
	if r.code != ExitError || r.stdout != "public/index.html:1:1 client-csp-missing\n" {
		t.Fatalf("%+v", r)
	}
	writeFiles(t, dir, map[string]string{"chimera.yaml": "observability:\n  allow: [client-error-missing, client-rejection-missing, client-csp-missing]\n"})
	if r := run(t, dir, nil, "lint", "observability"); r.code != ExitOK || !strings.Contains(r.stderr, "0 findings, 3 waived") {
		t.Fatalf("%+v", r)
	}
	// --config names the file explicitly.
	cfg := writeConfig(t, "observability:\n  allow: [\"*\"]\n")
	os.Remove(filepath.Join(dir, "chimera.yaml"))
	if r := run(t, dir, nil, "--config", cfg, "lint", "observability"); r.code != ExitOK || !strings.Contains(r.stderr, "not-applicable") {
		t.Fatalf("--config: %+v", r)
	}
	// An unknown rule is invalid config: usage, nothing audited, value not echoed.
	writeFiles(t, dir, map[string]string{"chimera.yaml": "observability:\n  allow: [everything-please]\n"})
	r = run(t, dir, nil, "lint", "observability")
	if r.code != ExitUsage || r.stdout != "" || strings.Contains(r.stderr, "everything-please") || !strings.Contains(r.stderr, "observability.allow[0]: unknown rule") {
		t.Fatalf("%+v", r)
	}
}

func TestM2_4_StrictFailsClosedOnUnreadableDirectoryOrFile(t *testing.T) {
	type entry struct{ name, path, want string }
	// A FIFO with a scanned extension cannot be read as a file whatever the
	// process's privileges; mode 000 blocks reads only without root or
	// CAP_DAC_READ_SEARCH.
	entries := []entry{{"fifo", "public/pipe.js", "public/pipe.js:0:0 unreadable\n"}}
	if chmodBlocksReads(t) {
		entries = append(entries, entry{"file", "public/errors.js", "public/errors.js:0:0 unreadable\n"}, entry{"directory", "src", "src/:0:0 unreadable\n"})
	} else {
		t.Log("mode 000 does not block reads for this process; chmod cases skipped")
	}
	for _, tc := range entries {
		t.Run(tc.name, func(t *testing.T) {
			dir := obsFixture(t, "webworker", nil)
			p := filepath.Join(dir, filepath.FromSlash(tc.path))
			if tc.name == "fifo" {
				if err := mkfifo(p); err != nil {
					t.Skip("mkfifo:", err)
				}
			} else {
				if err := os.Chmod(p, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(p, 0o755) })
			}

			r := run(t, dir, nil, "lint", "observability", "--strict")
			if r.code != ExitError || !strings.Contains(r.stdout, tc.want) {
				t.Fatalf("--strict: %+v", r)
			}
			oneLowercaseErrorLine(t, nil, r.stderr)
			if r.stdout == tc.want && !strings.HasSuffix(r.stderr, "; make every entry readable, or run without --strict\n") {
				t.Fatalf("a scan problem cannot be waived; the hint must not say so: %q", r.stderr)
			}
			r = run(t, dir, nil, "lint", "observability", "--strict", "--json")
			j := decodeObs(t, r.stdout)
			if r.code != ExitError || j.Status != "fail" || len(j.Skipped) != 0 {
				t.Fatalf("--strict --json: %+v %+v", r, j)
			}
			// Without --strict the entry is skipped with a warning and is never
			// reported as a finding.
			r = run(t, dir, nil, "lint", "observability", "--json")
			j = decodeObs(t, r.stdout)
			if len(j.Skipped) != 1 || j.Skipped[0].Rule != "unreadable" || !strings.Contains(r.stderr, "--strict fails closed") {
				t.Fatalf("lenient: %+v %+v", r, j)
			}
			for _, f := range j.Findings {
				if f.Rule == "unreadable" {
					t.Fatalf("lenient run reported a scan problem as a finding: %+v", j)
				}
			}
		})
	}
	if !chmodBlocksReads(t) {
		return
	}
	// An unreadable audited directory is an error with or without --strict.
	dir := obsFixture(t, "library", nil)
	os.Chmod(dir, 0)
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	if r := run(t, t.TempDir(), nil, "lint", "observability", dir); r.code != ExitError || !strings.Contains(r.stderr, "cannot read directory: permission denied; nothing was audited") {
		t.Fatalf("%+v", r)
	}
}

func TestM2_4_StrictFailsClosedOnTruncatedScan(t *testing.T) {
	dir := obsFixture(t, "webworker", map[string]string{"public/bundle.js": strings.Repeat("x", 4<<20+1)})
	if r := run(t, dir, nil, "lint", "observability"); r.code != ExitOK || !strings.Contains(r.stderr, "warning: 1 entries not fully read (truncated)") {
		t.Fatalf("lenient: %+v", r)
	}
	r := run(t, dir, nil, "lint", "observability", "--strict")
	if r.code != ExitError || r.stdout != "public/bundle.js:0:0 truncated\n" {
		t.Fatalf("--strict: %+v", r)
	}
}

func TestM2_4_UsageErrorsExit2(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"lint", "observability", "a", "b"},
		{"lint", "observability", filepath.Join(dir, "missing")},
		{"lint", "observability", "--strict=yes"},
	} {
		r := run(t, dir, nil, args...)
		if r.code != ExitUsage {
			t.Fatalf("%v: %+v", args, r)
		}
		oneLowercaseErrorLine(t, args, r.stderr)
	}
	r := run(t, dir, nil, "lint", "observability", "missing", "--json")
	var env errorEnvelope
	if err := json.Unmarshal([]byte(r.stdout), &env); err != nil || env.Schema != "chimera.error/v1" || env.Code != ExitUsage {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestM2_4_OutputIsByteStable(t *testing.T) {
	dir := obsFixture(t, "webworker", map[string]string{"public/errors.js": "console.log(1)\n"})
	a := run(t, dir, nil, "lint", "observability", "--json")
	b := run(t, dir, nil, "lint", "observability", "--json")
	if a != b || a.code != ExitError {
		t.Fatalf("%+v\n%+v", a, b)
	}
}

func TestM1_1_ErrorLineKeepsAnAllCapsFirstWord(t *testing.T) {
	for in, want := range map[string]string{
		"GET cas/x: no answer from the store": "GET cas/x: no answer from the store",
		"PUT a: 412":                          "PUT a: 412",
		"Cannot read":                         "cannot read",
		"A file":                              "a file",
		"X":                                   "x",
		"":                                    "",
	} {
		if got := lower(in); got != want {
			t.Errorf("lower(%q) = %q, want %q", in, got, want)
		}
	}
}
