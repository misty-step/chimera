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
	"time"

	"gopkg.in/yaml.v3"

	"chimera/pkg/secretscan"
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
	Verifiers map[string]Verifier       `yaml:"verifiers"`
	Lanes     map[string]Lane           `yaml:"lanes"`
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

// Harness is an external agent command template. Chimera embeds no agent.
type Harness struct {
	Command []string `yaml:"command"`
	Timeout string   `yaml:"timeout"` // Go duration; empty means the lane default
}

// Verifier is a command template run in the sandbox after the harness.
type Verifier struct {
	Command []string `yaml:"command"`
	Timeout string   `yaml:"timeout"`
}

// Lane is a named LaneConfig (PRODUCT.md §2.2).
type Lane struct {
	Model         string `yaml:"model"`
	Harness       string `yaml:"harness"`
	Skill         string `yaml:"skill"`
	Prompt        string `yaml:"prompt"`
	Effort        string `yaml:"effort"`
	ContextPolicy string `yaml:"context_policy"`
	Runner        string `yaml:"runner"`
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
		switch {
		case err != nil:
			return &LoadError{Path: c.Path, Msg: "store.endpoint: not an absolute URL"}
		case u.Scheme == "file":
			if u.Host != "" || !filepath.IsAbs(u.Path) {
				return &LoadError{Path: c.Path, Msg: "store.endpoint: file endpoint must be file:///absolute/path"}
			}
		case (u.Scheme != "http" && u.Scheme != "https") || u.Host == "":
			return &LoadError{Path: c.Path, Msg: "store.endpoint: not an absolute URL"}
		}
	}
	for name, h := range c.Harnesses {
		if err := checkDuration(h.Timeout); err != nil {
			return &LoadError{Path: c.Path, Msg: fmt.Sprintf("harnesses.%s.timeout: %v", name, err)}
		}
	}
	for name, v := range c.Verifiers {
		if err := checkDuration(v.Timeout); err != nil {
			return &LoadError{Path: c.Path, Msg: fmt.Sprintf("verifiers.%s.timeout: %v", name, err)}
		}
	}
	for name, l := range c.Lanes {
		switch l.ContextPolicy {
		case "", "none", "push", "push+pull":
		default:
			return &LoadError{Path: c.Path, Msg: fmt.Sprintf("lanes.%s.context_policy: must be none, push, or push+pull", name)}
		}
	}
	return nil
}

func checkDuration(s string) error {
	if s == "" {
		return nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fmt.Errorf("not a positive duration")
	}
	return nil
}

// placeholderDomain reports whether an email domain is reserved for
// documentation (RFC 2606/6761) and so identifies no operator.
func placeholderDomain(d string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	for _, base := range []string{"example.com", "example.org", "example.net"} {
		if d == base || strings.HasSuffix(d, "."+base) {
			return true
		}
	}
	for _, tld := range []string{"example", "test", "invalid", "localhost"} {
		if d == tld || strings.HasSuffix(d, "."+tld) {
			return true
		}
	}
	return false
}

// placeholderOwner reports whether a repository owner segment is one of the
// placeholder names the Folio reserves for tests and docs.
func placeholderOwner(o string) bool {
	switch strings.ToLower(o) {
	case "acme", "example":
		return true
	}
	return false
}

// minDerivedTerm is the shortest standalone term derived from a longer tenant
// value. Shorter fragments ("a", "go") would match ordinary words everywhere;
// the full value they came from is still matched.
const minDerivedTerm = 3

// derivedTerms returns the standalone identifiers hidden inside tenant
// values: the domain of each owner email and the owner segment of each
// repository. Placeholders are skipped.
func (c *Config) derivedTerms() []string {
	var out []string
	for _, e := range c.Tenant.OwnerEmails {
		if i := strings.LastIndexByte(e, '@'); i >= 0 {
			if d := strings.TrimSpace(e[i+1:]); len(d) >= minDerivedTerm && !placeholderDomain(d) {
				out = append(out, d)
			}
		}
	}
	for _, r := range c.Tenant.Repos {
		segs := strings.Split(strings.Trim(strings.TrimSuffix(strings.TrimSpace(r), ".git"), "/"), "/")
		if len(segs) < 2 {
			continue
		}
		if o := segs[len(segs)-2]; len(o) >= minDerivedTerm && !placeholderOwner(o) {
			out = append(out, o)
		}
	}
	return out
}

// TenantTerms returns every tenant-identifying value in the loaded config, the
// standalone identifiers derived from them (email domains, repository owners),
// plus configured secret values. These join the tenant-leak denylist automatically.
func (c *Config) TenantTerms() []secretscan.Term {
	var out []secretscan.Term
	add := func(rule string, vs ...string) {
		for _, v := range vs {
			out = append(out, secretscan.Term{Value: v, Rule: rule})
		}
	}
	add(secretscan.RuleTenantTerm, c.Tenant.OwnerEmails...)
	add(secretscan.RuleTenantTerm, c.Tenant.Repos...)
	add(secretscan.RuleTenantTerm, c.derivedTerms()...)
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
