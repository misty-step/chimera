package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func envOf(m map[string]string) Env { return func(k string) string { return m[k] } }

func TestM1_1_ExampleConfigParses(t *testing.T) {
	cfg, err := Load(Options{File: filepath.Join("..", "..", "chimera.example.yaml")}, envOf(map[string]string{"HOME": "/home/example"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tenant.DenylistFile != "/home/example/.config/chimera/denylist.txt" {
		t.Errorf("denylist_file=%q", cfg.Tenant.DenylistFile)
	}
	if len(cfg.Ring0.Paths) != 3 || cfg.Store.Region != "auto" || cfg.Harnesses["example-agent"].Command[2] != "{{.PromptFile}}" {
		t.Errorf("cfg=%+v", cfg)
	}
	if cfg.Prices["example-model"].OutputPerMTok != 4 {
		t.Errorf("prices=%+v", cfg.Prices)
	}
	terms := map[string]bool{}
	for _, tm := range cfg.TenantTerms() {
		terms[tm.Value] = true
	}
	for _, want := range []string{"owner@example.com", "acme/widget", "acme-capsules", "s3.example.com"} {
		if !terms[want] {
			t.Errorf("tenant term %q missing", want)
		}
	}
}

func TestM1_1_SecretsComeOnlyFromEnvAndAreNeverEchoed(t *testing.T) {
	secret := "Zx9-" + strings.Repeat("k", 8)
	cfg, err := Load(Options{Dir: t.TempDir()}, envOf(map[string]string{"CHIMERA_S3_SECRET_ACCESS_KEY": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Redacted("CHIMERA_S3_SECRET_ACCESS_KEY") != "<set>" || cfg.Redacted("CHIMERA_S3_ACCESS_KEY_ID") != "<unset>" {
		t.Fatal("redaction")
	}
}

func TestM1_1_InvalidConfigIsLoadError(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"abs-ring0.yaml": "ring0:\n  paths: [/etc/**]\n",
		"bad-url.yaml":   "store:\n  endpoint: not a url\n",
		"unknown.yaml":   "nope: 1\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(Options{File: p}, envOf(nil))
		var le *LoadError
		if !errors.As(err, &le) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}
