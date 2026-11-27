package land

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
)

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:299]) + "…"
	}
	return s
}

// LaneVerifier verifies a rebased tree in a Lane: an ephemeral sandbox
// provisioned at the rebased commit, the verifier run alone (no harness),
// and the verdict sealed and pushed as a Capsule through the same engine as
// `chimera run` (a Bench of K=1). It verifies the tree that will land, not
// the tree that was authored.
type LaneVerifier struct {
	RepoDir  string       // the lander's clone, where the rebased commit lives
	Repo     string       // name recorded in the Capsule
	Target   string       // for the land:<target> tag
	Verifier lane.Command // run on every rebased tree
	Runner   string       // "" means local
	Deps     lane.Deps    // runner lookup, capsule push, indexing
	Epoch    func() int   // for the epoch:<n> tag; nil omits it
}

// Verify has the signature Train.Verify wants.
func (v LaneVerifier) Verify(ctx context.Context, c forge.Change, rb Rebased) (Verification, error) {
	runner := v.Runner
	if runner == "" {
		runner = "local"
	}
	f := lane.Fixture{Name: "land", Repo: v.Repo, RepoDir: v.RepoDir, BaseSHA: string(rb.SHA),
		Brief: fmt.Sprintf("land %s on %s", c.Branch, forge.Branch(v.Target)), Verifier: v.Verifier}
	f.Intent = v.intent(ctx, rb, f)
	tags := []string{"land:" + forge.Branch(v.Target), "change:" + c.ID}
	if v.Epoch != nil {
		tags = append(tags, "epoch:"+strconv.Itoa(v.Epoch()))
	}
	// A runner that cannot be had is the lander's configuration, not the
	// change: stop before anything is judged.
	if _, err := v.Deps.Runner(runner); err != nil {
		return Verification{}, err
	}
	// Keep the typed error of the Capsule push: the lane reports only text.
	deps := v.Deps
	var pushErr error
	if push := v.Deps.Push; push != nil {
		deps.Push = func(ctx context.Context, dir string) error {
			pushErr = push(ctx, dir)
			return pushErr
		}
	}
	plan := lane.Plan{K: 1, Tags: tags, Cells: []lane.Cell{{
		Fixture: f, VerifyOnly: true, Lane: capsule.LaneConfig{ContextPolicy: "none", Runner: runner},
	}}}
	rep, err := lane.Run(ctx, plan, deps)
	if ctx.Err() != nil {
		return Verification{}, ctx.Err()
	}
	if rep == nil || len(rep.Cells) == 0 || len(rep.Cells[0].Lanes) == 0 {
		if err == nil {
			err = fmt.Errorf("lane produced no report")
		}
		return Verification{}, err
	}
	lr := rep.Cells[0].Lanes[0]
	if lr.Capsule == "" {
		reason := lr.Error
		if reason == "" {
			reason = "lane recorded no capsule"
		}
		// A store that did not answer is nobody's fault: no verdict, the change
		// stays queued. Anything else — the secret gate refusing what the
		// verifier printed, a tree the sandbox cannot hold — is this change
		// failing to be verified, and a verifier that cannot decide is a
		// failed verifier (PRODUCT.md §0.3).
		if errors.Is(pushErr, objstore.ErrUnavailable) {
			return Verification{}, fmt.Errorf("%s: %w", reason, objstore.ErrUnavailable)
		}
		return Verification{Pass: false, Reason: "verification recorded no capsule (" + oneLine(reason) + ")"}, nil
	}
	// A Ledger that could not index is derived state; the Capsule stands.
	out := Verification{Pass: lr.Pass, Capsule: lr.Capsule}
	if !lr.Pass {
		var failing []string
		for _, vd := range lr.Verdicts {
			if !vd.Pass {
				name := vd.Criterion
				if !strings.HasPrefix(name, vd.ID+" ") { // "verifier exits 0" already names its ID
					name = strings.TrimSpace(vd.ID + " " + name)
				}
				failing = append(failing, name)
			}
		}
		out.Reason = "verifier failed (" + strings.Join(failing, "; ") + "), capsule " + lr.Capsule
	}
	return out, nil
}

// intent resolves the Intent the landing verdict is recorded against: the
// first Chimera-Intent trailer of the change's commits, else the Folio at
// the rebased commit, else the task Intent of the landing fixture itself.
func (v LaneVerifier) intent(ctx context.Context, rb Rebased, f lane.Fixture) string {
	for _, c := range rb.Sources {
		for _, id := range c.Chimera().Intents {
			if capsule.ValidIntent(id) {
				return id
			}
		}
	}
	if id, err := gitx.FolioIntent(ctx, v.RepoDir, string(rb.SHA)); err == nil {
		return id
	}
	return lane.TaskIntent(f)
}
