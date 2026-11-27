package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/ledger"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// openStore returns the configured evidence store. A missing or invalid
// store configuration is a usage error: nothing was attempted.
func (c *ctx) openStore(cfg *config.Config) (objstore.Store, error) {
	store, err := objstore.Open(cfg.Store.Endpoint, cfg.Store.Bucket, cfg.Store.Region, objstore.Credentials{
		AccessKeyID:     cfg.Secrets["CHIMERA_S3_ACCESS_KEY_ID"],
		SecretAccessKey: cfg.Secrets["CHIMERA_S3_SECRET_ACCESS_KEY"],
		SessionToken:    cfg.Secrets["CHIMERA_S3_SESSION_TOKEN"],
	})
	if err != nil {
		return nil, usageErr("store", err.Error(), "set store.endpoint in chimera.yaml or CHIMERA_STORE_ENDPOINT")
	}
	return store, nil
}

// gate builds the secret gate: built-in rules, every tenant value in the
// loaded config, and the denylist. An unreadable denylist fails closed.
func (c *ctx) gate(cfg *config.Config) (*secretscan.Scanner, error) {
	deny, err := cfg.DenylistTerms()
	if err != nil {
		return nil, &cliError{code: ExitError, object: "denylist file", msg: strings.TrimPrefix(err.Error(), "denylist file "), next: "nothing uploaded"}
	}
	return secretscan.New(append(cfg.TenantTerms(), deny...)), nil
}

// ledgerPath resolves ledger.path, defaulting to the XDG state directory.
func (c *ctx) ledgerPath(cfg *config.Config) (string, error) {
	if cfg.Ledger.Path != "" {
		return c.abs(cfg.Ledger.Path), nil
	}
	if d := c.inv.Env("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "chimera", "ledger.db"), nil
	}
	if home := c.inv.Env("HOME"); home != "" {
		return filepath.Join(home, ".local", "state", "chimera", "ledger.db"), nil
	}
	return "", usageErr("ledger.path", "not configured", "set ledger.path in chimera.yaml or CHIMERA_LEDGER_PATH")
}

// failed wraps an error as an exit-1 failure about object.
func failed(object string, err error, next string) *cliError {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce
	}
	return &cliError{code: ExitError, object: object, msg: lower(err.Error()), next: next}
}

// grid renders rows as aligned plain text with two-space gutters. The last
// column is not padded.
func grid(rows [][]string) string {
	// Cells may hold text from files, harnesses, or verifiers; none of it may
	// put a control or escape byte on the terminal (DESIGN.md §1.4).
	for _, r := range rows {
		for i := range r {
			r[i] = ledger.Printable(r[i])
		}
	}
	var w []int
	for _, r := range rows {
		for i, cell := range r {
			if i >= len(w) {
				w = append(w, 0)
			}
			if n := len([]rune(cell)); n > w[i] {
				w[i] = n
			}
		}
	}
	var b strings.Builder
	for _, r := range rows {
		for i, cell := range r {
			if i == len(r)-1 {
				b.WriteString(cell)
				break
			}
			fmt.Fprintf(&b, "%s%s  ", cell, strings.Repeat(" ", w[i]-len([]rune(cell))))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// short abbreviates "sha256:<hex>" or "folio:<hex>" to 12 hex characters.
func short(id string) string {
	if k, v, ok := strings.Cut(id, ":"); ok {
		return k + ":" + abbrev(v)
	}
	return abbrev(id)
}

func passWord(pass bool) string {
	if pass {
		return "PASS"
	}
	return "FAIL"
}
