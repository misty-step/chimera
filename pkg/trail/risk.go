package trail

import (
	"path"

	"chimera/pkg/gitx"
)

// A change is wide — R2 on blast radius alone — when it exceeds any of
// these: files touched, packages (distinct directories) touched, lines
// added plus deleted.
const (
	WideFiles    = 5
	WidePackages = 3
	WideLines    = 200
)

func isWide(s Stats) bool {
	return s.Files > WideFiles || s.Packages > WidePackages || s.Lines > WideLines
}

func maxClass(a, b string) string {
	if b > a {
		return b
	}
	return a
}

// pathClass grades one touched path: R3 for a Ring-0 path (always) or an r3
// risk glob, otherwise the class of the config risk glob it matches, R1 for
// any other file.
func pathClass(p string, o Options) (class, reason string) {
	if o.Ring0 != nil && o.Ring0(p) {
		return "R3", "Ring-0 path changed"
	}
	if o.RiskGlob != nil {
		if cls, glob := o.RiskGlob(p); cls != "" {
			return maxClass("R1", cls), "matches risk glob " + glob
		}
	}
	return "R1", ""
}

// classify computes the deterministic risk class of a diff from its blast
// radius (PRODUCT.md §2.4): R0 for no change; R1 for any change; R2 for a
// wide change or a path under an r2 risk glob; R3 for a Ring-0 path or an r3
// risk glob.
func classify(stats []gitx.FileStat, o Options) (string, Stats) {
	var st Stats
	dirs := map[string]bool{}
	class := "R0"
	for _, f := range stats {
		st.Files++
		st.Lines += f.Added + f.Deleted
		dirs[path.Dir(f.Path)] = true
		cls, _ := pathClass(f.Path, o)
		class = maxClass(class, cls)
	}
	st.Packages = len(dirs)
	if isWide(st) {
		class = maxClass(class, "R2")
	}
	return class, st
}
