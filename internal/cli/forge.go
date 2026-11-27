package cli

import (
	"fmt"

	"chimera/pkg/config"
	"chimera/pkg/forge"
)

// openForge returns the configured forge adapter. A missing or invalid forge
// configuration is a usage error: nothing was attempted.
func (c *ctx) openForge(cfg *config.Config, root string) (forge.Forge, error) {
	return nil, fmt.Errorf("not implemented")
}
