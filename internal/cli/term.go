package cli

import (
	"io"
	"os"
	"path/filepath"

	"chimera/pkg/config"
)

// colorAllowed reports whether ANSI escapes may be written to w: w is a TTY,
// NO_COLOR is unset, and TERM is not "dumb". Off a TTY output has zero escapes.
func colorAllowed(w io.Writer, env config.Env) bool {
	if env("NO_COLOR") != "" || env("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func isAbs(p string) bool { return filepath.IsAbs(p) }

func join(dir, p string) string { return filepath.Join(dir, p) }
