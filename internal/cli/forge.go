package cli

import (
	"errors"
	"strings"

	"chimera/pkg/config"
	"chimera/pkg/forge"
	"chimera/pkg/objstore"
)

// openForge returns the configured forge adapter. A missing or invalid forge
// configuration is a usage error: nothing was attempted. root is the current
// work tree, or "" outside one.
func (c *ctx) openForge(cfg *config.Config, root string) (forge.Forge, error) {
	switch cfg.Forge.Kind {
	case "git":
		dir := c.abs(cfg.Forge.Dir)
		if dir == "" {
			dir = root
		}
		if dir == "" {
			return nil, usageErr("forge.dir", "not configured and not inside a git work tree", "set forge.dir in chimera.yaml or CHIMERA_FORGE_DIR")
		}
		return &forge.Git{Dir: dir}, nil
	case "github":
		if !strings.Contains(strings.Trim(cfg.Forge.Repo, "/"), "/") {
			return nil, usageErr("forge.repo", "must be owner/name", "set forge.repo in chimera.yaml or CHIMERA_FORGE_REPO")
		}
		token := cfg.Secrets["CHIMERA_FORGE_TOKEN"]
		if token == "" {
			// Credentials print as <set> or <unset>, never as a value (DESIGN.md §1.5).
			return nil, usageErr("forge", "CHIMERA_FORGE_TOKEN is "+cfg.Redacted("CHIMERA_FORGE_TOKEN"), "export the forge token; it is never read from chimera.yaml")
		}
		return &forge.GitHub{API: cfg.Forge.API, Repo: strings.Trim(cfg.Forge.Repo, "/"), Token: token}, nil
	}
	return nil, usageErr("forge.kind", "not configured", "set forge.kind to github or git in chimera.yaml or CHIMERA_FORGE_KIND")
}

// remoteErr renders a forge or store failure: an unanswered call is pending
// (exit 3, retry later), anything else an error.
func remoteErr(object string, err error, next string) *cliError {
	if errors.Is(err, forge.ErrUnavailable) || errors.Is(err, objstore.ErrUnavailable) {
		return &cliError{code: ExitPending, object: object, msg: lower(err.Error()), next: "outcome unknown; run the command again"}
	}
	return failed(object, err, next)
}
