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
	"regexp"
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
	Risk      Risk                      `yaml:"risk"`
	Forge     Forge                     `yaml:"forge"`
	Land      Land                      `yaml:"land"`
	Inlet     Inlet                     `yaml:"inlet"`

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

// Risk maps path globs to the risk class a change touching them carries
// (PRODUCT.md §2.4). Ring-0 paths are always R3 and need no entry here.
type Risk struct {
	R1 []string `yaml:"r1"`
	R2 []string `yaml:"r2"`
	R3 []string `yaml:"r3"`
}

// Forge selects the forge adapter behind the five-method Forge interface.
type Forge struct {
	Kind string `yaml:"kind"` // github | git
	Repo string `yaml:"repo"` // owner/name on the forge (github)
	API  string `yaml:"api"`  // REST root (github); empty means the public API
	Dir  string `yaml:"dir"`  // repository holding the refs (git); empty means the current one
}

// Land configures the MergeTrain (PRODUCT.md §2.5).
type Land struct {
	Target   string `yaml:"target"`   // ref changes land on
	Verifier string `yaml:"verifier"` // verifier run on every rebased tree (default: default)
	Runner   string `yaml:"runner"`   // runner of the verifying lane (default: local)
	Strategy string `yaml:"strategy"` // rebase | squash
	Remote   string `yaml:"remote"`   // git remote of the forge, for object transport; empty when the forge is this repository
}

// Inlet configures the POST /v1/inlet/nit handler (PRODUCT.md §2.6). The
// handler is an http.Handler in pkg/inlet; whatever hosts it reads this block.
type Inlet struct {
	Repo            string   `yaml:"repo"`
	Issuer          string   `yaml:"issuer"`   // required "iss" of the edge token
	Audience        string   `yaml:"audience"` // required "aud"; empty skips the check
	JWKSURL         string   `yaml:"jwks_url"`
	JWKSFile        string   `yaml:"jwks_file"`
	TokenHeader     string   `yaml:"token_header"` // edge header carrying the token, besides Authorization: Bearer
	TokenCookie     string   `yaml:"token_cookie"` // edge session cookie carrying the token
	Debounce        string   `yaml:"debounce"`     // Go duration; window before the Folio PR is updated
	DailyCap        int      `yaml:"daily_cap"`    // owner nits classified per repo per UTC day
	PreviewOrigins  []string `yaml:"preview_origins"`
	BotActors       []string `yaml:"bot_actors"`
	TriagePerMinute int      `yaml:"triage_per_minute"`
	AllowedOrigins  []string `yaml:"allowed_origins"` // cross-origin pages that may post (CORS)
	FolioBranch     string   `yaml:"folio_branch"`    // head of the one open Folio-only PR
	Target          string   `yaml:"target"`          // branch the Folio PR proposes to change
	Classifier      Harness  `yaml:"classifier"`      // external command: nit JSON on stdin, decision JSON on stdout
}

// SecretEnv lists the environment variables Chimera treats as secrets.
var SecretEnv = []string{"CHIMERA_S3_ACCESS_KEY_ID", "CHIMERA_S3_SECRET_ACCESS_KEY", "CHIMERA_S3_SESSION_TOKEN", "CHIMERA_FORGE_TOKEN"}

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

var yamlValueRE = regexp.MustCompile("`[^`]*`")

// yamlErr renders a decode error without the value excerpts the YAML library
// quotes: a config value may be a tenant term, and errors are printed.
func yamlErr(err error) string {
	return yamlValueRE.ReplaceAllString(strings.TrimPrefix(err.Error(), "yaml: "), "<value>")
}

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
	str("CHIMERA_FORGE_KIND", &cfg.Forge.Kind)
	str("CHIMERA_FORGE_REPO", &cfg.Forge.Repo)
	str("CHIMERA_FORGE_API", &cfg.Forge.API)
	str("CHIMERA_FORGE_DIR", &cfg.Forge.Dir)
	str("CHIMERA_LAND_TARGET", &cfg.Land.Target)
	str("CHIMERA_INLET_REPO", &cfg.Inlet.Repo)
	str("CHIMERA_INLET_ISSUER", &cfg.Inlet.Issuer)
	str("CHIMERA_INLET_AUDIENCE", &cfg.Inlet.Audience)
	str("CHIMERA_INLET_JWKS_URL", &cfg.Inlet.JWKSURL)
	str("CHIMERA_INLET_JWKS_FILE", &cfg.Inlet.JWKSFile)
	cfg.Secrets = map[string]string{}
	for _, k := range SecretEnv {
		if v := env(k); v != "" {
			cfg.Secrets[k] = v
		}
	}
	home := env("HOME")
	cfg.Tenant.DenylistFile = expandHome(cfg.Tenant.DenylistFile, home)
	cfg.Ledger.Path = expandHome(cfg.Ledger.Path, home)
	cfg.Forge.Dir = expandHome(cfg.Forge.Dir, home)
	cfg.Inlet.JWKSFile = expandHome(cfg.Inlet.JWKSFile, home)
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
	for class, globs := range map[string][]string{"r1": c.Risk.R1, "r2": c.Risk.R2, "r3": c.Risk.R3} {
		for _, g := range globs {
			if strings.HasPrefix(g, "/") || strings.Contains(g, "..") {
				return &LoadError{Path: c.Path, Msg: fmt.Sprintf("risk.%s: %q must be relative to the repository root", class, g)}
			}
		}
	}
	switch c.Forge.Kind {
	case "", "github", "git":
	default:
		return &LoadError{Path: c.Path, Msg: "forge.kind: must be github or git"}
	}
	if c.Forge.API != "" {
		if u, err := url.Parse(c.Forge.API); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &LoadError{Path: c.Path, Msg: "forge.api: not an absolute URL"}
		}
	}
	switch c.Land.Strategy {
	case "", "rebase", "squash":
	default:
		return &LoadError{Path: c.Path, Msg: "land.strategy: must be rebase or squash"}
	}
	if err := checkDuration(c.Inlet.Debounce); err != nil {
		return &LoadError{Path: c.Path, Msg: fmt.Sprintf("inlet.debounce: %v", err)}
	}
	if err := checkDuration(c.Inlet.Classifier.Timeout); err != nil {
		return &LoadError{Path: c.Path, Msg: fmt.Sprintf("inlet.classifier.timeout: %v", err)}
	}
	if c.Inlet.DailyCap < 0 || c.Inlet.TriagePerMinute < 0 {
		return &LoadError{Path: c.Path, Msg: "inlet.daily_cap and inlet.triage_per_minute: must not be negative"}
	}
	for _, key := range []struct{ name, value string }{{"inlet.issuer", c.Inlet.Issuer}, {"inlet.jwks_url", c.Inlet.JWKSURL}} {
		if key.value == "" {
			continue
		}
		if u, err := url.Parse(key.value); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return &LoadError{Path: c.Path, Msg: key.name + ": not an absolute URL"}
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
	for _, r := range c.repoValues() {
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

// repoValues lists every repository named anywhere in the config.
func (c *Config) repoValues() []string {
	out := append([]string{}, c.Tenant.Repos...)
	for _, r := range []string{c.Forge.Repo, c.Inlet.Repo} {
		if r != "" {
			out = append(out, r)
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
	add(secretscan.RuleTenantTerm, c.repoValues()...)
	add(secretscan.RuleTenantTerm, c.derivedTerms()...)
	add(secretscan.RuleTenantTerm, c.Store.Bucket)
	// The identity provider's host names the operator as surely as a bucket does.
	if u, err := url.Parse(c.Inlet.Issuer); err == nil && c.Inlet.Issuer != "" && u.Hostname() != "" && !placeholderDomain(u.Hostname()) {
		add(secretscan.RuleTenantTerm, u.Hostname())
	}
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
