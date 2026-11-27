package inlet

import (
	"fmt"
	"strings"
	"time"

	"chimera/pkg/capsule"
	"chimera/pkg/config"
)

// OptionsFromConfig maps the inlet block of chimera.yaml, plus
// tenant.owner_emails, to handler options. An inlet that could not verify
// owners — no issuer, no audience, no JWKS, no owner — is a configuration
// error: it must not start.
func OptionsFromConfig(cfg *config.Config) (Options, error) {
	in := cfg.Inlet
	o := Options{
		Repo: in.Repo, OwnerEmails: cfg.Tenant.OwnerEmails, Issuer: in.Issuer, Audience: in.Audience,
		JWKSFile: in.JWKSFile, JWKSURL: in.JWKSURL, TokenHeader: in.TokenHeader, TokenCookie: in.TokenCookie,
		EmailVerified: in.EmailVerified, ClientIPHeader: in.ClientIPHeader,
		DailyCap: in.DailyCap, TriagePerMinute: in.TriagePerMinute, PreviewOrigins: in.PreviewOrigins, BotActors: in.BotActors,
		AllowedOrigins: in.AllowedOrigins, FolioBranch: in.FolioBranch, Target: in.Target, ClassifierCommand: in.Classifier.Command,
		Debounce: DefaultDebounce, ClassifierTimeout: DefaultClassifierTimeout,
	}
	if o.Repo == "" {
		switch {
		case cfg.Forge.Repo != "":
			o.Repo = cfg.Forge.Repo
		case len(cfg.Tenant.Repos) == 1:
			o.Repo = cfg.Tenant.Repos[0]
		}
	}
	if o.Target == "" {
		o.Target = cfg.Land.Target
	}
	owners := 0
	for _, e := range o.OwnerEmails {
		if strings.TrimSpace(e) != "" {
			owners++
		}
	}
	switch {
	case o.Repo == "":
		return Options{}, fmt.Errorf("inlet.repo: not configured")
	case o.Issuer == "":
		return Options{}, fmt.Errorf("inlet.issuer: not configured; owners cannot be verified")
	case o.Audience == "":
		return Options{}, fmt.Errorf("inlet.audience: not configured; a token minted for another party would be accepted")
	case o.JWKSFile == "" && o.JWKSURL == "":
		return Options{}, fmt.Errorf("inlet.jwks_url or inlet.jwks_file: not configured; owners cannot be verified")
	case owners == 0:
		return Options{}, fmt.Errorf("tenant.owner_emails: empty; no one could be an owner")
	case o.Target == "":
		return Options{}, fmt.Errorf("inlet.target: not configured")
	}
	if in.Debounce != "" {
		d, err := time.ParseDuration(in.Debounce)
		if err != nil || d <= 0 {
			return Options{}, fmt.Errorf("inlet.debounce: not a positive duration")
		}
		o.Debounce = d
	}
	if in.Classifier.Timeout != "" {
		d, err := time.ParseDuration(in.Classifier.Timeout)
		if err != nil || d <= 0 {
			return Options{}, fmt.Errorf("inlet.classifier.timeout: not a positive duration")
		}
		o.ClassifierTimeout = d
	}
	if o.DailyCap == 0 {
		o.DailyCap = DefaultDailyCap
	}
	if o.TriagePerMinute == 0 {
		o.TriagePerMinute = DefaultTriagePerMinute
	}
	if o.FolioBranch == "" {
		o.FolioBranch = DefaultFolioBranch
	}
	if o.FolioBranch == o.Target {
		return Options{}, fmt.Errorf("inlet.folio_branch: must differ from inlet.target")
	}
	switch o.EmailVerified {
	case "", "required", "if-present":
	default:
		return Options{}, fmt.Errorf("inlet.email_verified: must be required or if-present")
	}
	for _, entry := range o.AllowedOrigins {
		if _, err := parseAllowedOrigin(entry); err != nil {
			return Options{}, fmt.Errorf("inlet.allowed_origins: %w", err)
		}
	}
	for _, entry := range o.PreviewOrigins {
		if _, err := parsePreviewPattern(entry); err != nil {
			return Options{}, fmt.Errorf("inlet.preview_origins: %w", err)
		}
	}
	if o.JWKSURL != "" {
		if _, err := jwksURL(o.JWKSURL); err != nil {
			return Options{}, fmt.Errorf("inlet.jwks_url: must be https")
		}
	}
	// A reconcile order names the verifier Land uses, so the order and the
	// landing are judged alike.
	verifierName := cfg.Land.Verifier
	if verifierName == "" {
		verifierName = "default"
	}
	if v, ok := cfg.Verifiers[verifierName]; ok {
		o.Verifier = capsule.TaskVerifier{Command: v.Command, Timeout: v.Timeout}
	}
	return o, nil
}
