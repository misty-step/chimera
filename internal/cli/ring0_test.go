package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM1_1_GlobMatching(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"verify/**", "verify/a.sh", true},
		{"verify/**", "verify/x/y/z.sh", true},
		{"verify/**", "verifyx/a.sh", false},
		{".github/workflows/**", ".github/workflows/ci.yml", true},
		{"**/*.lock", "a/b/c.lock", true},
		{"**/*.lock", "c.lock", true},
		{"*.yaml", "a/chimera.yaml", false},
		{"chimera.schema.json", "chimera.schema.json", true},
	}
	for _, c := range cases {
		if got := matchGlob(c.pat, c.name); got != c.want {
			t.Errorf("matchGlob(%q,%q)=%v", c.pat, c.name, got)
		}
	}
}

func TestM1_1_Ring0LockAndVerify(t *testing.T) {
	repo := fixtureRepo(t, map[string]string{
		"verify/check.sh":          "#!/bin/sh\nexit 0\n",
		".github/workflows/ci.yml": "on: push\n",
		"src/main.go":              "package main\n",
	})
	env := map[string]string{"CHIMERA_RING0_PATHS": "verify/**,.github/workflows/**,.chimera/**"}

	if r := run(t, repo, env, "ring0", "verify"); r.code != ExitError || !strings.Contains(r.stderr, "lock missing") {
		t.Fatalf("verify without lock must fail closed: %+v", r)
	}
	if r := run(t, repo, nil, "ring0", "lock"); r.code != ExitUsage {
		t.Fatalf("lock without ring0.paths: %+v", r)
	}
	if r := run(t, repo, env, "ring0", "lock"); r.code != ExitOK || r.stdout != "" {
		t.Fatalf("lock: %+v", r)
	}
	lock, err := os.ReadFile(filepath.Join(repo, LockPath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(lock), lockHeader+"\n# glob .chimera/**\n# glob .github/workflows/**\n# glob verify/**\n") ||
		strings.Contains(string(lock), "src/main.go") || strings.Count(string(lock), "  ") != 2 {
		t.Fatalf("lock=%q", lock)
	}
	if r := run(t, repo, env, "ring0", "verify"); r.code != ExitOK || r.stdout != "" || !strings.Contains(r.stderr, "PASS  2 files") {
		t.Fatalf("verify clean: %+v", r)
	}
	// The lock names its globs, so verify works without config too.
	if r := run(t, repo, nil, "ring0", "verify"); r.code != ExitOK {
		t.Fatalf("verify from lock globs: %+v", r)
	}
	// Non-Ring-0 edits do not matter.
	writeFiles(t, repo, map[string]string{"src/main.go": "package main // edited\n"})
	if r := run(t, repo, env, "ring0", "verify"); r.code != ExitOK {
		t.Fatalf("non-ring0 edit: %+v", r)
	}

	writeFiles(t, repo, map[string]string{"verify/check.sh": "#!/bin/sh\nexit 0 # always pass\n", "verify/new.sh": "true\n"})
	if err := os.Remove(filepath.Join(repo, ".github/workflows/ci.yml")); err != nil {
		t.Fatal(err)
	}
	r := run(t, repo, env, "ring0", "verify")
	want := "STATE     PATH\nmissing   .github/workflows/ci.yml\nmodified  verify/check.sh\nadded     verify/new.sh\n"
	if r.code != ExitError || r.stdout != want {
		t.Fatalf("code=%d stdout=%q stderr=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.HasPrefix(r.stderr, "chimera: ring0 verify: .chimera/ring0.lock: 3 changes since lock; ") {
		t.Fatalf("stderr=%q", r.stderr)
	}
	j := run(t, repo, env, "ring0", "verify", "--json")
	var obj struct {
		Schema   string        `json:"schema"`
		Findings []ring0Change `json:"findings"`
	}
	if err := json.Unmarshal([]byte(j.stdout), &obj); err != nil || j.code != ExitError || obj.Schema != "chimera.error/v1" || len(obj.Findings) != 3 {
		t.Fatalf("json: %+v %v", j, err)
	}

	// Narrowing ring0.paths after locking is itself a change.
	run(t, repo, env, "ring0", "lock")
	narrowed := map[string]string{"CHIMERA_RING0_PATHS": "verify/**"}
	g := run(t, repo, narrowed, "ring0", "verify")
	if g.code != ExitError || !strings.Contains(g.stdout, "glob-removed  .chimera/**") {
		t.Fatalf("glob change: %+v", g)
	}

	// A tampered lock refuses to decide.
	writeFiles(t, repo, map[string]string{LockPath: lockHeader + "\nnot-a-hash  verify/check.sh\n"})
	if r := run(t, repo, env, "ring0", "verify"); r.code != ExitError || !strings.Contains(r.stderr, "malformed entry") {
		t.Fatalf("tampered lock: %+v", r)
	}
}
