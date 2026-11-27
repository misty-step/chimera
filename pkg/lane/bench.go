package lane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"chimera/pkg/capsule"
)

// Fixture is one frozen starting point: (repo, base_sha, task_brief, verifier).
type Fixture struct {
	Name     string
	Repo     string // name recorded in Capsules
	RepoDir  string
	BaseSHA  string // full commit SHA
	Brief    string
	Verifier Command
	Intent   string // task:<sha256> of the canonical task manifest, unless given
}

// TaskIntent hashes the canonical task manifest of a fixture: brief, target
// repo, base SHA, and verifier, as YAML with a fixed key order.
func TaskIntent(f Fixture) string {
	manifest := struct {
		Brief    string `yaml:"brief"`
		Repo     string `yaml:"repo"`
		BaseSHA  string `yaml:"base_sha"`
		Verifier struct {
			Command []string `yaml:"command"`
			Timeout string   `yaml:"timeout"`
		} `yaml:"verifier"`
	}{Brief: f.Brief, Repo: f.Repo, BaseSHA: f.BaseSHA}
	manifest.Verifier.Command = f.Verifier.Argv
	manifest.Verifier.Timeout = f.Verifier.Timeout.String()
	raw, _ := yaml.Marshal(manifest)
	sum := sha256.Sum256(raw)
	return "task:" + hex.EncodeToString(sum[:])
}

// Cell is one point of the matrix: a fixture and a LaneConfig.
type Cell struct {
	Fixture Fixture
	Lane    capsule.LaneConfig
	Harness Command
	Price   *Price
	// VerifyOnly runs the verifier alone on the fixture's tree (no harness).
	VerifyOnly bool
}

// Hash identifies the cell: 12 hex characters over its Intent and LaneConfig.
func (c Cell) Hash() string {
	raw, _ := capsule.Canonical(map[string]any{"intent": c.Fixture.Intent, "lane": c.Lane})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:6])
}

// Plan is a fully resolved Bench: every cell runs K lanes.
type Plan struct {
	ID    string // "" for a production run (no bench tag)
	K     int
	Cells []Cell
	Tags  []string // extra tags on every Capsule
}

// Matrix is the bench file (--matrix).
type Matrix struct {
	ID       string          `yaml:"id"`
	K        int             `yaml:"k"`
	Fixtures []MatrixFixture `yaml:"fixtures"`
	Axes     Axes            `yaml:"axes"`
}

// MatrixFixture is a fixture as written in the bench file.
type MatrixFixture struct {
	Name      string         `yaml:"name"`
	Repo      string         `yaml:"repo"` // path to a Git work tree, relative to the bench file
	BaseSHA   string         `yaml:"base_sha"`
	TaskBrief string         `yaml:"task_brief"`
	Verifier  MatrixVerifier `yaml:"verifier"`
}

// MatrixVerifier is either the name of a configured verifier or an inline
// command.
type MatrixVerifier struct {
	Name    string
	Command []string `yaml:"command"`
	Timeout string   `yaml:"timeout"`
}

// UnmarshalYAML accepts a scalar (a configured verifier's name) or a mapping.
func (v *MatrixVerifier) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		v.Name = n.Value
		return nil
	}
	type plain MatrixVerifier
	return n.Decode((*plain)(v))
}

// Axes are the LaneConfig axes whose cross product forms the cells.
type Axes struct {
	Model         []string `yaml:"model"`
	Harness       []string `yaml:"harness"`
	Skill         []string `yaml:"skill"`
	Prompt        []string `yaml:"prompt"`
	Effort        []string `yaml:"effort"`
	ContextPolicy []string `yaml:"context_policy"`
	Runner        []string `yaml:"runner"`
}

// ParseMatrix decodes a bench file strictly.
func ParseMatrix(data []byte) (*Matrix, error) {
	var m Matrix
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("invalid matrix: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	if len(m.Fixtures) == 0 {
		return nil, fmt.Errorf("invalid matrix: no fixtures")
	}
	if len(m.Axes.Harness) == 0 {
		return nil, fmt.Errorf("invalid matrix: axes.harness is empty")
	}
	if m.ID == "" {
		sum := sha256.Sum256(data)
		m.ID = hex.EncodeToString(sum[:6])
	}
	for _, p := range m.Axes.ContextPolicy {
		if p != "none" && p != "push" && p != "push+pull" {
			return nil, fmt.Errorf("invalid matrix: context_policy %q", p)
		}
	}
	return &m, nil
}

// LaneConfigs returns the cross product of the axes in a fixed order: model,
// harness, skill, prompt, effort, context_policy, runner; values in file order.
func (a Axes) LaneConfigs() []capsule.LaneConfig {
	or := func(vs []string, def string) []string {
		if len(vs) == 0 {
			return []string{def}
		}
		return vs
	}
	var out []capsule.LaneConfig
	for _, model := range or(a.Model, "") {
		for _, harness := range or(a.Harness, "") {
			for _, skill := range or(a.Skill, "") {
				for _, prompt := range or(a.Prompt, "") {
					for _, effort := range or(a.Effort, "") {
						for _, policy := range or(a.ContextPolicy, "none") {
							for _, runner := range or(a.Runner, "local") {
								out = append(out, capsule.LaneConfig{Model: model, Harness: harness, Skill: skill, Prompt: prompt,
									Effort: effort, ContextPolicy: policy, Runner: runner})
							}
						}
					}
				}
			}
		}
	}
	return out
}

// Deps are the services a Bench needs from its caller.
type Deps struct {
	Runner func(name string) (Runner, error)
	// Push uploads a packed Capsule directory through the secret gate.
	Push func(ctx context.Context, dir string) error
	// Index adds new Capsules to the Ledger; nil skips indexing.
	Index func(ctx context.Context) error
	// Scent returns pre-flight text for a cell (context_policy push); nil means none.
	Scent func(ctx context.Context, c Cell) string
	Ring0 func(string) bool
	Env   []string
	Now   func() time.Time
	// Progress is called before each lane; nil means silent.
	Progress func(cell Cell, k, total int)
}

// LaneReport is one lane of a cell.
type LaneReport struct {
	K          int               `json:"k"`
	Capsule    string            `json:"capsule"` // "" when no Capsule was produced
	Checkpoint string            `json:"checkpoint,omitempty"`
	Error      string            `json:"error,omitempty"`
	Warning    string            `json:"warning,omitempty"`
	Pass       bool              `json:"pass"`
	WallMS     int64             `json:"wall_ms"`
	CostUSD    *float64          `json:"cost_usd"`
	BaseSHA    string            `json:"base_sha"`
	Tree       string            `json:"tree"`
	Verdicts   []capsule.Verdict `json:"verdicts"`
	Transcript []Event           `json:"-"`
	Diff       []byte            `json:"-"`
}

// CellReport is one row of the Bench table.
type CellReport struct {
	Fixture   string             `json:"fixture"`
	Cell      string             `json:"cell"`
	Intent    string             `json:"intent"`
	Repo      string             `json:"repo"`
	Lane      capsule.LaneConfig `json:"lane"`
	K         int                `json:"k"`
	PassRate  float64            `json:"pass_rate"` // criteria passed / criteria judged, over all K lanes
	AllPass   int                `json:"all_pass"`  // lanes in which every criterion passed
	WallP50MS int64              `json:"wall_p50_ms"`
	WallP90MS int64              `json:"wall_p90_ms"`
	CostUSD   *float64           `json:"cost_usd"` // mean per lane; null unless every lane reported usage
	Lanes     []LaneReport       `json:"lanes"`
}

// Report is the result of a Bench.
type Report struct {
	Schema string       `json:"schema"`
	Bench  string       `json:"bench"`
	K      int          `json:"k"`
	Cells  []CellReport `json:"cells"`
}

// Failed counts lanes that produced no Capsule.
func (r *Report) Failed() int {
	n := 0
	for _, c := range r.Cells {
		for _, l := range c.Lanes {
			if l.Capsule == "" {
				n++
			}
		}
	}
	return n
}

// Run executes every cell K times, sequentially and in plan order, so the
// same plan always visits lanes in the same order. Each lane's Capsule is
// tagged (bench:<id>, cell:<hash>, k:<n>), pushed, and indexed.
func Run(ctx context.Context, plan Plan, deps Deps) (*Report, error) {
	if plan.K < 1 {
		return nil, fmt.Errorf("K must be at least 1")
	}
	rep := &Report{Schema: "chimera.bench/v1", Bench: plan.ID, K: plan.K}
	for _, cell := range plan.Cells {
		cr := CellReport{Fixture: cell.Fixture.Name, Cell: cell.Hash(), Intent: cell.Fixture.Intent, Repo: cell.Fixture.Repo, Lane: cell.Lane, K: plan.K}
		runner, rerr := deps.Runner(cell.Lane.Runner)
		for k := 1; k <= plan.K; k++ {
			if ctx.Err() != nil {
				return rep, ctx.Err()
			}
			if deps.Progress != nil {
				deps.Progress(cell, k, plan.K)
			}
			lr := LaneReport{K: k, BaseSHA: cell.Fixture.BaseSHA, Verdicts: []capsule.Verdict{}}
			if rerr != nil {
				lr.Error = rerr.Error()
				cr.Lanes = append(cr.Lanes, lr)
				continue
			}
			tags := append([]string{"cell:" + cr.Cell, "k:" + strconv.Itoa(k)}, plan.Tags...)
			if plan.ID != "" {
				tags = append(tags, "bench:"+plan.ID)
			}
			if cell.Fixture.Name != "" {
				tags = append(tags, "fixture:"+cell.Fixture.Name)
			}
			spec := Spec{
				Intent: cell.Fixture.Intent, Repo: cell.Fixture.Repo, RepoDir: cell.Fixture.RepoDir, BaseSHA: cell.Fixture.BaseSHA,
				Lane: cell.Lane, Brief: cell.Fixture.Brief, Harness: cell.Harness, Verifier: cell.Fixture.Verifier,
				Tags: tags, Env: deps.Env, Ring0: deps.Ring0, Price: cell.Price, Now: deps.Now, VerifyOnly: cell.VerifyOnly,
			}
			if deps.Scent != nil && strings.HasPrefix(cell.Lane.ContextPolicy, "push") {
				spec.Scent = deps.Scent(ctx, cell)
			}
			res, err := Execute(ctx, runner, spec)
			if err != nil {
				if ctx.Err() != nil {
					return rep, ctx.Err()
				}
				lr.Error = err.Error()
				cr.Lanes = append(cr.Lanes, lr)
				continue
			}
			lr.Checkpoint, lr.Tree, lr.Verdicts, lr.Pass = res.Checkpoint, res.Tree, res.Verdicts, res.Passed()
			lr.WallMS, lr.CostUSD, lr.Transcript, lr.Diff = res.Metrics.WallMS, res.Metrics.CostUSD, res.Transcript, res.Diff
			lr.Warning = res.Warning
			if err := deps.Push(ctx, res.Dir); err != nil {
				lr.Error = err.Error()
				lr.Pass = false
			} else {
				lr.Capsule = string(res.Address)
			}
			os.RemoveAll(res.Dir)
			cr.Lanes = append(cr.Lanes, lr)
		}
		summarize(&cr)
		rep.Cells = append(rep.Cells, cr)
	}
	if deps.Index != nil {
		if err := deps.Index(ctx); err != nil {
			return rep, fmt.Errorf("ledger: %w", err)
		}
	}
	return rep, nil
}

func summarize(cr *CellReport) {
	var walls []int64
	passed, judged := 0, 0
	var cost float64
	costKnown := len(cr.Lanes) > 0
	for _, l := range cr.Lanes {
		if l.Capsule == "" {
			// A lane with no Capsule proved nothing. It counts as one failed
			// criterion, so a crash can never raise the pass rate.
			judged++
			costKnown = false
			continue
		}
		if l.Pass {
			cr.AllPass++
		}
		for _, v := range l.Verdicts {
			judged++
			if v.Pass {
				passed++
			}
		}
		walls = append(walls, l.WallMS)
		if l.CostUSD == nil {
			costKnown = false
		} else {
			cost += *l.CostUSD
		}
	}
	if judged > 0 {
		cr.PassRate = float64(passed) / float64(judged)
	}
	cr.WallP50MS, cr.WallP90MS = Percentile(walls, 50), Percentile(walls, 90)
	if costKnown {
		mean := cost / float64(len(cr.Lanes))
		cr.CostUSD = &mean
	}
}

// Percentile returns the nearest-rank p-th percentile; 0 for no samples.
func Percentile(samples []int64, p int) int64 {
	if len(samples) == 0 {
		return 0
	}
	s := append([]int64{}, samples...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	rank := int(math.Ceil(float64(p) / 100 * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	return s[rank-1]
}
