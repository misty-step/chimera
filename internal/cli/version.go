package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

const modulePath = "github.com/misty-step/chimera"

type versionInfo struct {
	Schema       string `json:"schema"`
	Module       string `json:"module"`
	Version      string `json:"version"`
	Revision     string `json:"revision"`
	RevisionTime string `json:"revision_time"`
	Modified     bool   `json:"modified"`
	Go           string `json:"go"`
}

func readVersion() versionInfo {
	v := versionInfo{Schema: "chimera.version/v1", Module: modulePath, Version: "(devel)", Go: runtime.Version()}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	if bi.Main.Path != "" {
		v.Module = bi.Main.Path
	}
	if bi.Main.Version != "" {
		v.Version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.time":
			v.RevisionTime = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v
}

func runVersion(c *ctx) error {
	v := readVersion()
	if c.json {
		return c.emitJSON(v)
	}
	rev := "unknown"
	if v.Revision != "" {
		rev = abbrev(v.Revision)
		if v.Modified {
			rev += "-modified"
		}
	}
	_, err := fmt.Fprintf(c.inv.Stdout, "chimera %s %s %s\n", v.Version, rev, v.Go)
	return err
}

// abbrev shortens a hash to 12 hex characters for humans.
func abbrev(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
