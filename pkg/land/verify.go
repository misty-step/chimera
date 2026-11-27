package land

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"chimera/pkg/capsule"
	"chimera/pkg/forge"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
)

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
	plan := lane.Plan{K: 1, Tags: tags, Cells: []lane.Cell{{
		Fixture: f, VerifyOnly: true, Lane: capsule.LaneConfig{ContextPolicy: "none", Runner: runner},
	}}}
	rep, err := lane.Run(ctx, plan, v.Deps)
	if rep == nil || len(rep.Cells) == 0 || len(rep.Cells[0].Lanes) == 0 {
		if err == nil {
			err = fmt.Errorf("lane produced no report")
		}
		return Verification{}, err
	}
	lr := rep.Cells[0].Lanes[0]
	if lr.Capsule == "" {
		// No Capsule, no verdict: the change neither lands nor is blamed.
		reason := lr.Error
		if reason == "" {
			reason = "lane recorded no capsule"
		}
		return Verification{}, fmt.Errorf("%s", reason)
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
