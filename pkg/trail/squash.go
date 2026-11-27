package trail

import (
	"context"
	"strings"

	"chimera/pkg/gitx"
)

// SquashMessage returns the commit message of a squash of sources (oldest
// first): the given subject and body, then the union of every source
// commit's trailers, de-duplicated and in original order (PRODUCT.md §2.4).
// No source commit's binding to its Intent and Capsule is lost.
func SquashMessage(ctx context.Context, repoDir, subject, body string, sources []gitx.Commit) (string, error) {
	sets := make([][]gitx.Trailer, len(sources))
	for i, c := range sources {
		sets[i] = c.Trailers
	}
	msg := strings.TrimSpace(subject) + "\n"
	if b := strings.TrimSpace(body); b != "" {
		msg += "\n" + b + "\n"
	}
	return gitx.MessageWithTrailers(ctx, repoDir, msg, gitx.UnionTrailers(sets...))
}
