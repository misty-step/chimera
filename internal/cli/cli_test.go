package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type result struct {
	code           int
	stdout, stderr string
}

func genTerm(t *testing.T) string {
	t.Helper()
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "acme" + hex.EncodeToString(b)
}

// run invokes the CLI in dir with an isolated environment.
func run(t *testing.T, dir string, env map[string]string, args ...string) result {
	t.Helper()
	full := map[string]string{"HOME": t.TempDir(), "TERM": "xterm-256color"}
	for k, v := range env {
		full[k] = v
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), Invocation{
		Args: args, Dir: dir, Stdout: &out, Stderr: &errb,
		Env: func(k string) string { return full[k] },
	})
	return result{code, out.String(), errb.String()}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// fixtureRepo creates a git repository containing files and commits them.
func fixtureRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	writeFiles(t, dir, files)
	git(t, dir, "add", "-A")
	git(t, dir, "-c", "user.name=Example", "-c", "user.email=dev@example.com", "commit", "-q", "-m", "fixture")
	return dir
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		abs := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "chimera.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertNoTerm(t *testing.T, r result, term string) {
	t.Helper()
	all := strings.ToLower(r.stdout + r.stderr)
	if strings.Contains(all, strings.ToLower(term)) {
		t.Fatalf("output contains the tenant term:\nstdout=%q\nstderr=%q", r.stdout, r.stderr)
	}
}

func TestM1_1_FixtureWithTenantTermFails(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{
		"README.md":   "# widget\n",
		"pkg/a.go":    "package a\n\n// owned by " + strings.ToUpper(term) + ".\n",
		"docs/x.md":   "see https://" + term + ".example.com/x\n",
		"untracked.n": "",
	})
	writeFiles(t, repo, map[string]string{"scratch.txt": term}) // untracked: not scanned by default
	cfg := writeConfig(t, "tenant:\n  repos: ["+term+"/widget, "+term+"]\n")

	r := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg)
	if r.code != ExitError {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	want := "docs/x.md:1:13 tenant-term\npkg/a.go:3:13 tenant-term\n"
	if r.stdout != want {
		t.Fatalf("stdout=%q want %q", r.stdout, want)
	}
	if !strings.HasPrefix(r.stderr, "chimera: lint tenant-leak: 4 files: 2 findings (rule tenant-term); ") {
		t.Fatalf("stderr=%q", r.stderr)
	}
	assertNoTerm(t, r, term)

	j := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg, "--json")
	if j.code != ExitError {
		t.Fatalf("json code=%d", j.code)
	}
	var obj struct {
		Schema   string `json:"schema"`
		Code     int    `json:"code"`
		Command  string `json:"command"`
		Findings []struct {
			Path string `json:"path"`
			Line int    `json:"line"`
			Col  int    `json:"col"`
			Rule string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(j.stdout), &obj); err != nil {
		t.Fatalf("stdout is not one JSON object: %v: %q", err, j.stdout)
	}
	if obj.Schema != "chimera.error/v1" || obj.Code != 1 || obj.Command != "lint tenant-leak" || len(obj.Findings) != 2 {
		t.Fatalf("json=%+v", obj)
	}
	assertNoTerm(t, j, term)
}

func TestM1_1_CleanFixturePasses(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"README.md": "# widget for example.com\n", "a.go": "package a\n"})
	cfg := writeConfig(t, "tenant:\n  owner_emails: [owner@"+term+".test]\n  repos: ["+term+"/widget]\n")
	r := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg)
	if r.code != ExitOK || r.stdout != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "PASS") {
		t.Fatalf("stderr=%q", r.stderr)
	}
	q := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg, "-q")
	if q.code != ExitOK || q.stdout != "" || q.stderr != "" {
		t.Fatalf("-q: %+v", q)
	}
	j := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg, "--json")
	var obj map[string]any
	if err := json.Unmarshal([]byte(j.stdout), &obj); err != nil || obj["schema"] != "chimera.lint/v1" || j.code != 0 {
		t.Fatalf("json: code=%d %q err=%v", j.code, j.stdout, err)
	}
	assertNoTerm(t, j, term)
}

func TestM1_1_BinaryFilesAreScanned(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"img.bin": "\x89PNG\x00\x00\xff\n\x00" + term + "\x00\x01"})
	cfg := writeConfig(t, "tenant:\n  repos: ["+term+"]\n")
	r := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg)
	if r.code != ExitError || r.stdout != "img.bin:2:2 tenant-term\n" {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	assertNoTerm(t, r, term)
}

func TestM1_1_DenylistTermsMatchAndUnreadableDenylistFailsClosed(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"a.txt": "Contact " + term + " today\n"})
	deny := filepath.Join(t.TempDir(), "denylist.txt")
	if err := os.WriteFile(deny, []byte("# private\n\n"+term+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, "tenant:\n  denylist_file: "+deny+"\n")
	r := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg)
	if r.code != ExitError || r.stdout != "a.txt:1:9 denylist-term\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	assertNoTerm(t, r, term)

	missing := writeConfig(t, "tenant:\n  denylist_file: "+filepath.Join(t.TempDir(), "absent.txt")+"\n")
	m := run(t, repo, nil, "lint", "tenant-leak", "--config", missing)
	if m.code != ExitError || m.stdout != "" || !strings.Contains(m.stderr, "denylist file: unreadable") {
		t.Fatalf("missing denylist: %+v", m)
	}

	// A denylist path that exists but cannot be read as a file.
	dirDeny := writeConfig(t, "tenant:\n  denylist_file: "+t.TempDir()+"\n")
	d := run(t, repo, nil, "lint", "tenant-leak", "--config", dirDeny)
	if d.code != ExitError || d.stdout != "" || !strings.Contains(d.stderr, "denylist file: unreadable (is a directory)") {
		t.Fatalf("directory denylist: %+v", d)
	}

	if chmodBlocksReads(t) {
		if err := os.Chmod(deny, 0o000); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(deny, 0o600)
		u := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg)
		if u.code != ExitError || !strings.Contains(u.stderr, "permission denied") {
			t.Fatalf("unreadable denylist: %+v", u)
		}
		assertNoTerm(t, u, term)
	}
}

// chmodBlocksReads reports whether mode 000 actually prevents reads for this
// process (root and CAP_DAC_READ_SEARCH bypass it).
func chmodBlocksReads(t *testing.T) bool {
	p := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(p, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	_, err := os.ReadFile(p)
	return err != nil
}

func TestM1_1_UnreadableFileFailsClosed(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{"locked.txt": "x\n", "ok.txt": "y\n"})
	// Replace a tracked file with a directory: it exists but cannot be read as a file.
	p := filepath.Join(repo, "locked.txt")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p, 0o755); err != nil {
		t.Fatal(err)
	}
	r := run(t, repo, nil, "lint", "tenant-leak")
	if r.code != ExitError || r.stdout != "locked.txt:0:0 unreadable\n" || !strings.Contains(r.stderr, "(rule unreadable)") {
		t.Fatalf("%+v", r)
	}
}

func TestM1_1_DeletedTrackedFileScansIndexBlob(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"gone.txt": term + "\n"})
	if err := os.Remove(filepath.Join(repo, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	r := run(t, repo, map[string]string{"CHIMERA_TENANT_REPOS": term}, "lint", "tenant-leak")
	if r.code != ExitError || r.stdout != "gone.txt:1:1 tenant-term\n" {
		t.Fatalf("%+v", r)
	}
}

func TestM1_1_EnvTenantValuesAndSecretsJoinDenylist(t *testing.T) {
	term := genTerm(t)
	secret := genTerm(t) + "Zx9"
	repo := fixtureRepo(t, map[string]string{"a.txt": term + "@example.com\n", "b.txt": "k " + secret + "\n"})
	r := run(t, repo, map[string]string{
		"CHIMERA_TENANT_OWNER_EMAILS":  term + "@example.com",
		"CHIMERA_S3_SECRET_ACCESS_KEY": secret,
	}, "lint", "tenant-leak")
	if r.code != ExitError || r.stdout != "a.txt:1:1 tenant-term\nb.txt:1:3 configured-secret\n" {
		t.Fatalf("%+v", r)
	}
	assertNoTerm(t, r, term)
	assertNoTerm(t, r, secret)
}

func TestM1_1_ExplicitPathsAreScanned(t *testing.T) {
	term := genTerm(t)
	dir := t.TempDir() // not a git repository
	writeFiles(t, dir, map[string]string{"out/a.txt": term, "out/.git/x": term, "b.txt": "clean"})
	cfg := writeConfig(t, "tenant:\n  repos: ["+term+"]\n")
	r := run(t, dir, nil, "lint", "tenant-leak", "out", "b.txt", "missing.txt", "--config", cfg)
	want := "missing.txt:0:0 unreadable\nout/a.txt:1:1 tenant-term\n"
	if r.code != ExitError || r.stdout != want {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	n := run(t, dir, nil, "lint", "tenant-leak")
	if n.code != ExitError || !strings.Contains(n.stderr, "not a git repository") {
		t.Fatalf("outside a work tree: %+v", n)
	}
}

func TestM1_1_ConfigWithSecretIsLoadError(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{"a": "a"})
	secretLine := "store:\n  bucket: " + "AK" + "IA" + strings.Repeat("Q7", 8) + "\n"
	r := run(t, repo, nil, "lint", "tenant-leak", "--config", writeConfig(t, secretLine))
	if r.code != ExitUsage || !strings.Contains(r.stderr, "secret-shaped value in config (2:11 cloud-key)") {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(r.stderr, "Q7Q7") {
		t.Fatal("secret echoed")
	}
	u := run(t, repo, nil, "lint", "tenant-leak", "--config", writeConfig(t, "tenant:\n  owners: [x]\n"))
	if u.code != ExitUsage || !strings.Contains(u.stderr, "field owners not found") {
		t.Fatalf("unknown key: %+v", u)
	}
	m := run(t, repo, nil, "lint", "tenant-leak", "--config", "nope.yaml")
	if m.code != ExitUsage {
		t.Fatalf("missing explicit config: %+v", m)
	}
}

func TestM1_1_ExampleConfigLoadsAndItsDenylistFailsClosed(t *testing.T) {
	root, _ := filepath.Abs("../..")
	example := filepath.Join(root, "chimera.example.yaml")
	// The example names ~/.config/chimera/denylist.txt, absent in a fresh HOME.
	r := run(t, t.TempDir(), nil, "lint", "tenant-leak", "--config", example, filepath.Join(root, "LICENSE"))
	if r.code != ExitError || !strings.Contains(r.stderr, "denylist file: unreadable") {
		t.Fatalf("%+v", r)
	}
	home := t.TempDir()
	writeFiles(t, home, map[string]string{".config/chimera/denylist.txt": "# none\n"})
	ok := run(t, t.TempDir(), map[string]string{"HOME": home}, "lint", "tenant-leak", "--config", example, filepath.Join(root, "LICENSE"))
	if ok.code != ExitOK || !strings.Contains(ok.stderr, "4 terms") {
		t.Fatalf("%+v", ok)
	}
}

func TestM1_1_ConfigDiscoveryAndPrecedence(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"a.txt": term + "\n"})
	writeFiles(t, repo, map[string]string{"chimera.yaml": "tenant:\n  repos: [" + term + "]\n"}) // untracked
	if r := run(t, repo, nil, "lint", "tenant-leak"); r.code != ExitError {
		t.Fatalf("./chimera.yaml not discovered: %+v", r)
	}
	// env overrides file
	if r := run(t, repo, map[string]string{"CHIMERA_TENANT_REPOS": "other"}, "lint", "tenant-leak"); r.code != ExitOK {
		t.Fatalf("env did not override file: %+v", r)
	}
	// flag overrides discovery
	if r := run(t, repo, nil, "lint", "tenant-leak", "--config", writeConfig(t, "")); r.code != ExitOK {
		t.Fatalf("--config did not override discovery: %+v", r)
	}
	// XDG fallback
	other := fixtureRepo(t, map[string]string{"a.txt": term + "\n"})
	xdg := t.TempDir()
	writeFiles(t, xdg, map[string]string{"chimera/chimera.yaml": "tenant:\n  repos: [" + term + "]\n"})
	if r := run(t, other, map[string]string{"XDG_CONFIG_HOME": xdg}, "lint", "tenant-leak"); r.code != ExitError {
		t.Fatalf("XDG config not discovered: %+v", r)
	}
}

func TestM1_1_RepositoryPassesTenantLeakLint(t *testing.T) {
	root, _ := filepath.Abs("../..")
	r := run(t, root, nil, "lint", "tenant-leak")
	if r.code != ExitOK {
		t.Fatalf("repository has findings:\n%s%s", r.stdout, r.stderr)
	}
}

func TestM1_1_UsageErrorsExit2(t *testing.T) {
	dir := t.TempDir()
	cases := [][]string{
		{},
		{"frobnicate"},
		{"lint"},
		{"lint", "nope"},
		{"version", "--bogus"},
		{"version", "extra"},
		{"version", "--json=yes"},
		{"lint", "tenant-leak", "--config"},
		{"version", "-qh"},
	}
	for _, args := range cases {
		r := run(t, dir, nil, args...)
		if r.code != ExitUsage {
			t.Errorf("%v: code=%d stderr=%q", args, r.code, r.stderr)
		}
		if len(args) > 1 && r.stdout != "" {
			t.Errorf("%v: usage error wrote to stdout: %q", args, r.stdout)
		}
	}
	r := run(t, dir, nil, "frobnicate")
	if r.stderr != "chimera: frobnicate: unknown command; run 'chimera --help'\n" {
		t.Fatalf("stderr=%q", r.stderr)
	}
	j := run(t, dir, nil, "version", "--json", "--bogus")
	if j.code != ExitUsage || !strings.Contains(j.stdout, `"schema":"chimera.error/v1"`) || !strings.Contains(j.stdout, `"code":2`) {
		t.Fatalf("json usage error: %+v", j)
	}
}

func TestM1_1_HelpFitsIn24LinesAndComesFromTable(t *testing.T) {
	dir := t.TempDir()
	helps := [][]string{{"--help"}, {"-h"}, {"lint", "--help"}, {"ring0", "-h"}}
	for _, c := range commands {
		helps = append(helps, append(append([]string{}, c.Path...), "--help"))
	}
	for _, args := range helps {
		r := run(t, dir, nil, args...)
		if r.code != ExitOK || r.stderr != "" {
			t.Fatalf("%v: %+v", args, r)
		}
		if n := strings.Count(r.stdout, "\n"); n > 24 {
			t.Errorf("%v: %d lines", args, n)
		}
	}
	top := run(t, dir, nil, "--help").stdout
	for _, c := range commands {
		if !strings.Contains(top, c.name()) || !strings.Contains(top, c.Summary) {
			t.Errorf("top help missing %q", c.name())
		}
		h := run(t, dir, nil, append(append([]string{}, c.Path...), "--help")...).stdout
		for _, f := range c.Flags {
			if !strings.Contains(h, "--"+f.Long) {
				t.Errorf("%s help missing --%s", c.name(), f.Long)
			}
		}
	}
}

func TestM1_1_CommandTableFollowsGrammar(t *testing.T) {
	nouns := map[string]bool{"capsule": true, "ledger": true, "lane": true, "land": true, "lint": true, "ring0": true}
	verbs := map[string]bool{"run": true, "bench": true, "why": true, "preflight": true, "trail": true, "version": true}
	for _, c := range commands {
		switch len(c.Path) {
		case 1:
			if !verbs[c.Path[0]] {
				t.Errorf("%q is not a top-level verb", c.Path[0])
			}
		case 2:
			if !nouns[c.Path[0]] {
				t.Errorf("%q is not a noun", c.Path[0])
			}
		default:
			t.Errorf("bad path %v", c.Path)
		}
		for _, f := range append(append([]flagSpec{}, c.Flags...), globals...) {
			if f.Short != 0 && !strings.ContainsRune("Khq", rune(f.Short)) {
				t.Errorf("short flag -%c not allowed", f.Short)
			}
		}
	}
}

func TestM1_1_NoANSIOffTTY(t *testing.T) {
	term := genTerm(t)
	repo := fixtureRepo(t, map[string]string{"a.txt": term})
	cfg := writeConfig(t, "tenant:\n  repos: ["+term+"]\n")
	for _, args := range [][]string{
		{"--help"}, {"version"}, {"lint", "tenant-leak"}, {"lint", "tenant-leak", "--config", cfg}, {"nope"},
	} {
		r := run(t, repo, nil, args...)
		if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
			t.Errorf("%v: escape byte off a TTY", args)
		}
	}
	if colorAllowed(&bytes.Buffer{}, func(string) string { return "" }) {
		t.Error("buffer treated as TTY")
	}
	if colorAllowed(os.Stderr, func(k string) string { return map[string]string{"NO_COLOR": "1"}[k] }) {
		t.Error("NO_COLOR ignored")
	}
	if colorAllowed(os.Stderr, func(k string) string { return map[string]string{"TERM": "dumb"}[k] }) {
		t.Error("TERM=dumb ignored")
	}
}

func TestM1_1_VersionJSON(t *testing.T) {
	r := run(t, t.TempDir(), nil, "version", "--json")
	var v versionInfo
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil || r.code != 0 {
		t.Fatalf("%+v err=%v", r, err)
	}
	if v.Schema != "chimera.version/v1" || v.Module != modulePath || v.Go == "" || v.Version == "" {
		t.Fatalf("%+v", v)
	}
	h := run(t, t.TempDir(), nil, "version")
	if !strings.HasPrefix(h.stdout, "chimera ") || h.stderr != "" {
		t.Fatalf("%+v", h)
	}
}

// TestM1_1_VersionReportsVCSRevision builds the real binary inside a git work
// tree and checks the embedded revision.
func TestM1_1_VersionReportsVCSRevision(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	root, _ := filepath.Abs("../..")
	src := t.TempDir()
	cp := exec.Command("cp", "-r", filepath.Join(root, "go.mod"), filepath.Join(root, "go.sum"), filepath.Join(root, "cmd"), filepath.Join(root, "internal"), filepath.Join(root, "pkg"), src)
	if out, err := cp.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	git(t, src, "init", "-q", "-b", "main")
	git(t, src, "add", "-A")
	git(t, src, "-c", "user.name=Example", "-c", "user.email=dev@example.com", "commit", "-q", "-m", "build")
	revOut, err := exec.Command("git", "-C", src, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "chimera")
	build := exec.Command("go", "build", "-o", bin, "./cmd/chimera")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	out, err := exec.Command(bin, "version", "--json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var v versionInfo
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
	if v.Revision != strings.TrimSpace(string(revOut)) || v.Modified {
		t.Fatalf("version=%+v want revision %s", v, revOut)
	}
}
