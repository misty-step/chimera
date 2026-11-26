// Package config loads Chimera's declarative runtime configuration.
//
// Precedence: flags > CHIMERA_* environment > chimera.yaml (./chimera.yaml, then
// $XDG_CONFIG_HOME/chimera/chimera.yaml). Secrets come only from the
// environment; a config file containing a secret-shaped value is a load error.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/misty-step/chimera/pkg/secretscan"
)

// FileName is the config file Chimera discovers.
const FileName = "chimera.yaml"

// Config mirrors chimera.example.yaml. Unknown keys are a load error.
type Config struct {
	Tenant    Tenant                    `yaml:"tenant"`
	Store     Store                     `yaml:"store"`
	Ledger    Ledger                    `yaml:"ledger"`
	Ring0     Ring0                     `yaml:"ring0"`
	Runners   map[string]map[string]any `yaml:"runners"`
	Harnesses map[string]Harness        `yaml:"harnesses"`
	Prices    map[string]Price          `yaml:"prices"`

	// Path is the file the config was read from; empty when none was found.
	Path string `yaml:"-"`
	// Secrets holds CHIMERA_* secret values from the environment. Never print
	// these; use Redacted.
	Secrets map[string]string `yaml:"-"`
}

type Tenant struct {
	OwnerEmails  []string `yaml:"owner_emails"`
	Repos        []string `yaml:"repos"`
	DenylistFile string   `yaml:"denylist_file"`
}

type Store struct {
	Endpoint string `yaml:"endpoint"`
	Bucket   string `yaml:"bucket"`
	Region   string `yaml:"region"`
}

type Ledger struct {
	Path string `yaml:"path"`
}

type Ring0 struct {
	Paths []string `yaml:"paths"`
}

type Harness struct {
	Command []string `yaml:"command"`
}

type Price struct {
	InputPerMTok  float64 `yaml:"input_per_mtok"`
	OutputPerMTok float64 `yaml:"output_per_mtok"`
}

// SecretEnv lists the environment variables Chimera treats as secrets.
var SecretEnv = []string{"CHIMERA_S3_ACCESS_KEY_ID", "CHIMERA_S3_SECRET_ACCESS_KEY", "CHIMERA_S3_SESSION_TOKEN"}

// Env is a read-only view of the process environment.
type Env func(key string) string

// Options are flag-level overrides; they win over env and file.
type Options struct {
	// File is an explicit config path (--config). If set it must exist.
	File string
	Dir  string // directory used to discover ./chimera.yaml; defaults to "."
}

// LoadError is an invalid-config error (exit code 2 at the CLI).
type LoadError struct {
	Path string
	Msg  string
}

func (e *LoadError) Error() string {
	if e.Path == "" {
		return e.Msg
	}
	return e.Path + ": " + e.Msg
}

// Load resolves and parses configuration.
func Load(opts Options, env Env) (*Config, error) {
	path, err := resolvePath(opts, env)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, &LoadError{Path: path, Msg: "cannot read config: " + errText(err)}
		}
		if fs := secretscan.New(nil).Scan(path, data); len(fs) > 0 {
			locs := make([]string, len(fs))
			for i, f := range fs {
				locs[i] = fmt.Sprintf("%d:%d %s", f.Line, f.Col, f.Rule)
			}
			return nil, &LoadError{Path: path, Msg: "secret-shaped value in config (" + strings.Join(locs, ", ") + "); move secrets to CHIMERA_* env"}
		}
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return nil, &LoadError{Path: path, Msg: "invalid config: " + yamlErr(err)}
		}
		cfg.Path = path
	}
	applyEnv(cfg, env)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func yamlErr(err error) string { return strings.TrimPrefix(err.Error(), "yaml: ") }

func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func resolvePath(opts Options, env Env) (string, error) {
	if opts.File != "" {
		return opts.File, nil
	}
	if p := env("CHIMERA_CONFIG"); p != "" {
		return p, nil
	}
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	candidates := []string{filepath.Join(dir, FileName)}
	xdg := env("XDG_CONFIG_HOME")
	if xdg == "" {
		if home := env("HOME"); home != "" {
			xdg = filepath.Join(home, ".config")
		}
	}
	if xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "chimera", FileName))
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", nil
}

func applyEnv(cfg *Config, env Env) {
	list := func(key string, dst *[]string) {
		if v := env(key); v != "" {
			*dst = splitList(v)
		}
	}
	str := func(key string, dst *string) {
		if v := env(key); v != "" {
			*dst = v
		}
	}
	list("CHIMERA_TENANT_OWNER_EMAILS", &cfg.Tenant.OwnerEmails)
	list("CHIMERA_TENANT_REPOS", &cfg.Tenant.Repos)
	str("CHIMERA_TENANT_DENYLIST_FILE", &cfg.Tenant.DenylistFile)
	str("CHIMERA_STORE_ENDPOINT", &cfg.Store.Endpoint)
	str("CHIMERA_STORE_BUCKET", &cfg.Store.Bucket)
	str("CHIMERA_STORE_REGION", &cfg.Store.Region)
	str("CHIMERA_LEDGER_PATH", &cfg.Ledger.Path)
	list("CHIMERA_RING0_PATHS", &cfg.Ring0.Paths)
	cfg.Secrets = map[string]string{}
	for _, k := range SecretEnv {
		if v := env(k); v != "" {
			cfg.Secrets[k] = v
		}
	}
	home := env("HOME")
	cfg.Tenant.DenylistFile = expandHome(cfg.Tenant.DenylistFile, home)
	cfg.Ledger.Path = expandHome(cfg.Ledger.Path, home)
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func expandHome(p, home string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

func (c *Config) validate() error {
	for _, g := range c.Ring0.Paths {
		if strings.HasPrefix(g, "/") || strings.Contains(g, "..") {
			return &LoadError{Path: c.Path, Msg: fmt.Sprintf("ring0.paths: %q must be relative to the repository root", g)}
		}
	}
	if c.Store.Endpoint != "" {
		u, err := url.Parse(c.Store.Endpoint)
		if err != nil || u.Host == "" {
			return &LoadError{Path: c.Path, Msg: "store.endpoint: not an absolute URL"}
		}
	}
	return nil
}

// TenantTerms returns every tenant-identifying value in the loaded config plus
// configured secret values. These join the tenant-leak denylist automatically.
func (c *Config) TenantTerms() []secretscan.Term {
	var out []secretscan.Term
	add := func(rule string, vs ...string) {
		for _, v := range vs {
			out = append(out, secretscan.Term{Value: v, Rule: rule})
		}
	}
	add(secretscan.RuleTenantTerm, c.Tenant.OwnerEmails...)
	add(secretscan.RuleTenantTerm, c.Tenant.Repos...)
	add(secretscan.RuleTenantTerm, c.Store.Bucket)
	if c.Store.Endpoint != "" {
		if u, err := url.Parse(c.Store.Endpoint); err == nil && u.Hostname() != "" {
			add(secretscan.RuleTenantTerm, u.Hostname())
		}
	}
	for _, k := range SecretEnv {
		add(secretscan.RuleConfiguredSecret, c.Secrets[k])
	}
	return out
}

// DenylistTerms reads the configured denylist file: one term per line, blank
// lines and lines starting with '#' ignored. A configured but unreadable file
// is an error (fail closed). No file configured returns nil, nil.
func (c *Config) DenylistTerms() ([]secretscan.Term, error) {
	if c.Tenant.DenylistFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(c.Tenant.DenylistFile)
	if err != nil {
		return nil, fmt.Errorf("denylist file unreadable (%s)", errText(err))
	}
	var out []secretscan.Term
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, secretscan.Term{Value: line, Rule: secretscan.RuleDenylistTerm})
	}
	return out, nil
}

// Redacted reports whether a secret is configured without revealing it.
func (c *Config) Redacted(key string) string {
	if c.Secrets[key] != "" {
		return "<set>"
	}
	return "<unset>"
}
