package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/config"
)

type errorEnvelope struct {
	Schema   string `json:"schema"`
	Code     int    `json:"code"`
	Command  string `json:"command"`
	Message  string `json:"message"`
	Findings []any  `json:"findings"`
}

// oneLowercaseErrorLine asserts DESIGN.md §1.5: stderr is exactly one line,
// "chimera: …", with a lowercase message.
func oneLowercaseErrorLine(t *testing.T, args []string, stderr string) {
	t.Helper()
	if strings.Count(stderr, "\n") != 1 || !strings.HasPrefix(stderr, "chimera: ") {
		t.Fatalf("%v: stderr is not one error line: %q", args, stderr)
	}
	rest := strings.TrimPrefix(stderr, "chimera: ")
	if rest[:1] != strings.ToLower(rest[:1]) {
		t.Fatalf("%v: error line is not lowercase: %q", args, stderr)
	}
}

func TestM1_1_MissingCommandOrVerbIsOneLineUsageErrorAndJSONEnvelope(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"--json"}, {"lint", "--json"}, {"--json", "lint"}, {"capsule", "--json"}, {"-q", "--json"}} {
		r := run(t, dir, nil, args...)
		if r.code != ExitUsage {
			t.Fatalf("%v: code %d", args, r.code)
		}
		oneLowercaseErrorLine(t, args, r.stderr)
		var env errorEnvelope
		if strings.Count(r.stdout, "\n") != 1 {
			t.Fatalf("%v: stdout is not one JSON line: %q", args, r.stdout)
		}
		if err := json.Unmarshal([]byte(r.stdout), &env); err != nil {
			t.Fatalf("%v: stdout is not JSON: %v: %q", args, err, r.stdout)
		}
		if env.Schema != "chimera.error/v1" || env.Code != 2 || env.Findings == nil || env.Message == "" {
			t.Fatalf("%v: %+v", args, env)
		}
		if "chimera: "+env.Message+"\n" != r.stderr {
			t.Fatalf("%v: message %q does not match stderr %q", args, env.Message, r.stderr)
		}
		if !strings.HasPrefix(r.stdout, `{"schema":"chimera.error/v1","code":2,"command":"","message":"`) {
			t.Fatalf("%v: field order: %s", args, r.stdout)
		}
	}
	// Without --json: still one line on stderr, nothing on stdout, never the help text.
	for _, args := range [][]string{{}, {"lint"}, {"ring0"}, {"ledger"}, {"-q"}} {
		r := run(t, dir, nil, args...)
		if r.code != ExitUsage || r.stdout != "" {
			t.Fatalf("%v: %+v", args, r)
		}
		oneLowercaseErrorLine(t, args, r.stderr)
		if strings.Contains(r.stderr, "usage:") {
			t.Fatalf("%v: help text on stderr", args)
		}
	}
	if r := run(t, dir, nil); r.stderr != "chimera: missing command; run 'chimera --help'\n" {
		t.Fatalf("%q", r.stderr)
	}
	if r := run(t, dir, nil, "lint"); r.stderr != "chimera: lint: missing verb; run 'chimera lint --help'\n" {
		t.Fatalf("%q", r.stderr)
	}
}

func TestM1_1_GlobalFlagsParseBeforeCommandWords(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{"a.txt": "clean\n"})
	term := genTerm(t)
	cfg := writeConfig(t, "tenant:\n  repos: ["+term+"/widget]\n")

	r := run(t, repo, nil, "--json", "version")
	var v versionInfo
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil || r.code != ExitOK || v.Schema != "chimera.version/v1" || r.stderr != "" {
		t.Fatalf("--json version: %+v %v", r, err)
	}
	if r := run(t, repo, nil, "-q", "version"); r.code != ExitOK || !strings.HasPrefix(r.stdout, "chimera ") || r.stderr != "" {
		t.Fatalf("-q version: %+v", r)
	}
	r = run(t, repo, nil, "--config", cfg, "lint", "tenant-leak")
	if r.code != ExitOK || !strings.Contains(r.stderr, "2 terms, 0 findings") {
		t.Fatalf("--config <path> lint tenant-leak: %+v", r)
	}
	if r := run(t, repo, nil, "--config="+cfg, "-q", "--json", "lint", "tenant-leak"); r.code != ExitOK || r.stderr != "" || !strings.Contains(r.stdout, `"schema":"chimera.lint/v1"`) {
		t.Fatalf("--config=<path> -q --json lint tenant-leak: %+v", r)
	}
	// Before and after the command words mean the same thing.
	before := run(t, repo, nil, "--config", cfg, "--json", "lint", "tenant-leak")
	after := run(t, repo, nil, "lint", "tenant-leak", "--config", cfg, "--json")
	if before != after {
		t.Fatalf("flag position changes the result:\n%+v\n%+v", before, after)
	}
	// A leading flag still obeys the command's own table.
	if r := run(t, repo, nil, "--json", "ring0", "lock"); r.code != ExitUsage || !strings.Contains(r.stdout, `"code":2`) {
		t.Fatalf("--json ring0 lock: %+v", r)
	}
	for _, args := range [][]string{{"--config"}, {"--bogus", "version"}, {"--intent", "x", "version"}, {"-K", "3", "version"}} {
		r := run(t, repo, nil, args...)
		if r.code != ExitUsage {
			t.Fatalf("%v: %+v", args, r)
		}
		oneLowercaseErrorLine(t, args, r.stderr)
	}
}

func TestM1_1_HelpDoesNotExcuseAnUnknownCommand(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"--help", "frobnicate"}, {"-h", "frobnicate"}, {"frobnicate", "--help"}, {"--help", "lint", "nope"}, {"lint", "nope", "--help"}} {
		r := run(t, dir, nil, args...)
		if r.code != ExitUsage || r.stdout != "" {
			t.Fatalf("%v: %+v", args, r)
		}
		oneLowercaseErrorLine(t, args, r.stderr)
	}
	if r := run(t, dir, nil, "--help", "frobnicate"); r.stderr != "chimera: frobnicate: unknown command; run 'chimera --help'\n" {
		t.Fatalf("%q", r.stderr)
	}
	// Help for things that exist still exits 0 on stdout, in either position.
	for _, args := range [][]string{{"--help"}, {"--help", "version"}, {"version", "--help"}, {"--help", "lint"}, {"-h", "capsule", "push"}, {"--json", "--help"}} {
		r := run(t, dir, nil, args...)
		if r.code != ExitOK || r.stderr != "" || !strings.HasPrefix(r.stdout, "usage: chimera") {
			t.Fatalf("%v: %+v", args, r)
		}
	}
}

func TestM1_1_ModulePathIsTenantNeutral(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if first := strings.SplitN(string(data), "\n", 2)[0]; first != "module chimera" {
		t.Fatalf("go.mod: %q", first)
	}
	if modulePath != "chimera" {
		t.Fatalf("modulePath=%q", modulePath)
	}
}

func TestM1_1_TenantTermsIncludeEmailDomainsAndRepoOwners(t *testing.T) {
	term := genTerm(t)
	env := func(k string) string {
		return map[string]string{
			"CHIMERA_TENANT_OWNER_EMAILS": "owner@" + term + ".io, dev@example.com, ops@mail.example.org",
			"CHIMERA_TENANT_REPOS":        term + "-labs/widget, acme/widget, https://git.example.com/" + term + "-org/tool.git, solo",
		}[k]
	}
	cfg, err := config.Load(config.Options{Dir: t.TempDir()}, env)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tt := range cfg.TenantTerms() {
		have[tt.Value] = true
	}
	for _, want := range []string{term + ".io", term + "-labs", term + "-org", "owner@" + term + ".io", term + "-labs/widget", "acme/widget", "dev@example.com"} {
		if !have[want] {
			t.Errorf("missing term %q", want)
		}
	}
	for _, placeholder := range []string{"example.com", "mail.example.org", "acme", "widget", "tool", "solo/", "git.example.com"} {
		if have[placeholder] {
			t.Errorf("placeholder or non-owner %q became a term", placeholder)
		}
	}

	// End to end: the owner segment alone, and the email domain alone, are findings.
	repo := fixtureRepo(t, map[string]string{
		"go.mod":     "module forge.example.com/" + term + "-labs/widget\n",
		"SUPPORT.md": "mail support@" + strings.ToUpper(term) + ".io\n",
		"clean.md":   "acme and example.com are placeholders\n",
	})
	e := map[string]string{"CHIMERA_TENANT_OWNER_EMAILS": "owner@" + term + ".io", "CHIMERA_TENANT_REPOS": term + "-labs/tool"}
	r := run(t, repo, e, "lint", "tenant-leak")
	if r.code != ExitError || r.stdout != "SUPPORT.md:1:14 tenant-term\ngo.mod:1:26 tenant-term\n" {
		t.Fatalf("%+v", r)
	}
	assertNoTerm(t, r, term)
}
