package lane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"time"

	"chimera/pkg/capsule"
)

// Command is a command template with a time bound.
type Command struct {
	Argv    []string
	Timeout time.Duration
}

// Default time bounds when config gives none.
const (
	DefaultHarnessTimeout  = 30 * time.Minute
	DefaultVerifierTimeout = 10 * time.Minute
)

// Price is a model's cost per million tokens.
type Price struct {
	InputPerMTok, OutputPerMTok float64
}

// Spec is everything one lane needs.
type Spec struct {
	Intent   string
	Repo     string // name recorded in the Capsule
	RepoDir  string // Git work tree the Runner provisions from
	BaseSHA  string
	Lane     capsule.LaneConfig
	Brief    string // task brief; with Lane.Prompt it forms the prompt file
	Harness  Command
	Verifier Command
	Tags     []string
	Scent    string            // pre-flight text pushed to the harness (context_policy push)
	Env      []string          // extra KEY=VALUE for harness and verifier
	Ring0    func(string) bool // reports Ring-0 paths; nil means none
	Price    *Price            // nil when the model has no configured price
	Now      func() time.Time  // nil means time.Now
}

// Event is one line of transcript.jsonl. Every event names the checkpoint,
// never a commit, so the Capsule can be sealed before any commit exists.
type Event struct {
	Seq        int      `json:"seq"`
	Checkpoint string   `json:"checkpoint"`
	Event      string   `json:"event"` // start | exec | output | verdict | end
	Step       string   `json:"step,omitempty"`
	Argv       []string `json:"argv,omitempty"`
	Line       string   `json:"line,omitempty"`
	Exit       *int     `json:"exit,omitempty"`
	TimedOut   bool     `json:"timed_out,omitempty"`
	WallMS     *int64   `json:"wall_ms,omitempty"`
	BaseSHA    string   `json:"base_sha,omitempty"`
	Tree       string   `json:"tree,omitempty"`
	ID         string   `json:"id,omitempty"`
	Criterion  string   `json:"criterion,omitempty"`
	Pass       *bool    `json:"pass,omitempty"`
}

// Text renders an event as one transcript line for humans.
func (e Event) Text() string {
	switch e.Event {
	case "start":
		return fmt.Sprintf("start %s base %s tree %s", e.Checkpoint, short(e.BaseSHA), short(e.Tree))
	case "exec":
		s := "$ " + strings.Join(e.Argv, " ")
		if e.Exit != nil {
			s = fmt.Sprintf("%s exit %d", e.Step, *e.Exit)
			if e.TimedOut {
				s = e.Step + " timed out"
			}
			if e.WallMS != nil {
				s += fmt.Sprintf(" · %dms", *e.WallMS)
			}
		}
		return s
	case "output":
		return e.Line
	case "verdict":
		state := "FAIL"
		if e.Pass != nil && *e.Pass {
			state = "PASS"
		}
		return fmt.Sprintf("%s %s %s", e.ID, state, e.Criterion)
	case "end":
		return "end " + e.Checkpoint
	}
	return e.Event
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// Result is a finished lane: a packed Capsule directory plus what it holds.
type Result struct {
	Dir        string // packed, ready to push; the caller removes it
	Address    capsule.Address
	Checkpoint string
	BaseSHA    string
	Tree       string
	Verdicts   []capsule.Verdict
	Metrics    capsule.Metrics
	Diff       []byte
	Transcript []Event
	Tags       []string
	// Warning is a problem that did not invalidate the evidence, such as a
	// sandbox that could not be torn down.
	Warning string
}

// Passed reports whether every criterion passed (and there is at least one).
func (r *Result) Passed() bool {
	for _, v := range r.Verdicts {
		if !v.Pass {
			return false
		}
	}
	return len(r.Verdicts) > 0
}

// maxTranscriptLines bounds output lines recorded per step; the full output
// is kept under proof/.
const maxTranscriptLines = 400

type recorder struct {
	checkpoint string
	events     []Event
}

func (r *recorder) add(e Event) int {
	e.Seq = len(r.events) + 1
	e.Checkpoint = r.checkpoint
	r.events = append(r.events, e)
	return e.Seq
}

func (r *recorder) output(step string, out []byte) {
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return
	}
	skipped := 0
	if len(lines) > maxTranscriptLines {
		skipped = len(lines) - maxTranscriptLines
		lines = lines[skipped:]
	}
	if skipped > 0 {
		r.add(Event{Event: "output", Step: step, Line: fmt.Sprintf("[%d earlier lines in proof/%s.log]", skipped, step)})
	}
	for _, l := range lines {
		r.add(Event{Event: "output", Step: step, Line: strings.ToValidUTF8(l, "�")})
	}
}

func (r *recorder) exec(step string, argv []string, res ExecResult) int {
	r.add(Event{Event: "exec", Step: step, Argv: argv})
	r.output(step, res.Output)
	exit, wall := res.ExitCode, res.WallMS
	return r.add(Event{Event: "exec", Step: step, Exit: &exit, TimedOut: res.TimedOut, WallMS: &wall})
}

// vars are the fields a command template may use.
type vars struct {
	PromptFile, ScentFile, OutDir, Workspace       string
	Model, Effort, Skill, Prompt, ContextPolicy    string
	Intent, Checkpoint, Brief, Harness, RunnerName string
}

func render(argv []string, v vars) ([]string, error) {
	out := make([]string, len(argv))
	for i, a := range argv {
		t, err := template.New("arg").Option("missingkey=error").Parse(a)
		if err != nil {
			return nil, fmt.Errorf("command template %q: malformed", a)
		}
		var b bytes.Buffer
		if err := t.Execute(&b, v); err != nil {
			return nil, fmt.Errorf("command template %q: unknown field", a)
		}
		out[i] = b.String()
	}
	return out, nil
}

// Execute runs one lane: provision, harness, verifier, collect, tear down,
// pack. It returns an error only when no Capsule could be produced at all;
// a harness that fails or times out still yields a Capsule, with a failing
// verdict rather than a missing one.
func Execute(ctx context.Context, runner Runner, spec Spec) (res *Result, err error) {
	now := spec.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	checkpoint, err := capsule.NewCheckpoint(started)
	if err != nil {
		return nil, err
	}
	if spec.Harness.Timeout <= 0 {
		spec.Harness.Timeout = DefaultHarnessTimeout
	}
	if spec.Verifier.Timeout <= 0 {
		spec.Verifier.Timeout = DefaultVerifierTimeout
	}
	ws, err := runner.Provision(ctx, spec.RepoDir, spec.BaseSHA)
	if err != nil {
		return nil, fmt.Errorf("runner %s: %w", runner.Name(), err)
	}
	defer func() {
		// Tear down even when interrupted. A sandbox that will not go away does
		// not undo a finished lane: the Capsule stands and the failure is reported.
		if terr := ws.Teardown(context.WithoutCancel(ctx)); terr != nil {
			if res != nil {
				res.Warning = fmt.Sprintf("runner %s: %s", runner.Name(), terr)
			} else if err == nil {
				err = fmt.Errorf("runner %s: %w", runner.Name(), terr)
			}
		}
	}()
	tree, err := ws.Tree(ctx)
	if err != nil {
		return nil, fmt.Errorf("runner %s: %w", runner.Name(), err)
	}
	rec := &recorder{checkpoint: checkpoint}
	rec.add(Event{Event: "start", BaseSHA: spec.BaseSHA, Tree: tree})

	prompt := strings.TrimSpace(spec.Lane.Prompt + "\n\n" + spec.Brief)
	if err := ws.Put(ctx, "prompt.md", []byte(prompt+"\n")); err != nil {
		return nil, err
	}
	v := vars{
		PromptFile: ws.OutDir() + "/prompt.md", OutDir: ws.OutDir(), Workspace: ws.Dir(),
		Model: spec.Lane.Model, Effort: spec.Lane.Effort, Skill: spec.Lane.Skill, Prompt: spec.Lane.Prompt,
		ContextPolicy: spec.Lane.ContextPolicy, Intent: spec.Intent, Checkpoint: checkpoint, Brief: spec.Brief,
		Harness: spec.Lane.Harness, RunnerName: runner.Name(),
	}
	env := append([]string{
		"CHIMERA_OUT=" + ws.OutDir(), "CHIMERA_PROMPT_FILE=" + v.PromptFile, "CHIMERA_INTENT=" + spec.Intent,
		"CHIMERA_CHECKPOINT=" + checkpoint, "CHIMERA_MODEL=" + spec.Lane.Model, "CHIMERA_EFFORT=" + spec.Lane.Effort,
		"CHIMERA_CONTEXT_POLICY=" + spec.Lane.ContextPolicy,
	}, spec.Env...)
	if strings.HasPrefix(spec.Lane.ContextPolicy, "push") {
		if err := ws.Put(ctx, "scent.txt", []byte(spec.Scent)); err != nil {
			return nil, err
		}
		v.ScentFile = ws.OutDir() + "/scent.txt"
		env = append(env, "CHIMERA_SCENT_FILE="+v.ScentFile)
	}

	// Lanes run with Ring-0 paths read-only. Their blob IDs are recorded now
	// and compared after the verifier, independent of the diff.
	ring0 := map[string]string{} // path → blob at base
	var locked []string
	if spec.Ring0 != nil {
		listed := ws.Exec(ctx, []string{"git", "ls-files", "-s", "-z"}, nil, time.Minute)
		for _, rec := range strings.Split(string(listed.Stdout), "\x00") {
			meta, path, ok := strings.Cut(rec, "\t")
			f := strings.Fields(meta)
			if !ok || len(f) != 3 || !spec.Ring0(path) {
				continue
			}
			locked = append(locked, path)
			if f[0] != "120000" { // a symlink's blob is its target text, not file content
				ring0[path] = f[1]
			}
		}
		if len(locked) > 0 {
			ws.Exec(ctx, append([]string{"chmod", "a-w", "--"}, locked...), nil, time.Minute)
		}
	}

	var verdicts []capsule.Verdict
	addVerdict := func(vd capsule.Verdict) {
		pass := vd.Pass
		seq := rec.add(Event{Event: "verdict", ID: vd.ID, Criterion: vd.Criterion, Pass: &pass})
		if vd.Evidence == "" {
			vd.Evidence = fmt.Sprintf("transcript:%d", seq)
		}
		verdicts = append(verdicts, vd)
	}

	// Harness.
	var hres ExecResult
	hargv, herr := render(spec.Harness.Argv, v)
	if herr != nil || len(hargv) == 0 {
		hres = ExecResult{ExitCode: -1, Err: "harness command is not runnable"}
		if herr != nil {
			hres.Err = herr.Error()
		}
		rec.add(Event{Event: "output", Step: "harness", Line: hres.Err})
	} else {
		hres = ws.Exec(ctx, hargv, env, spec.Harness.Timeout)
		rec.exec("harness", spec.Harness.Argv, hres)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch {
	case hres.TimedOut:
		addVerdict(capsule.Verdict{ID: "harness", Criterion: "harness completes within its timeout", Pass: false,
			Evidence: fmt.Sprintf("timed out after %s", spec.Harness.Timeout)})
	case hres.Err != "":
		addVerdict(capsule.Verdict{ID: "harness", Criterion: "harness starts", Pass: false, Evidence: hres.Err})
	}

	// Verifier: run after the harness, whatever the harness did.
	_ = ws.Exec(ctx, []string{"rm", "-f", ws.OutDir() + "/" + capsule.MemberVerdicts}, nil, time.Minute)
	var vres ExecResult
	vargv, verr := render(spec.Verifier.Argv, v)
	if verr != nil || len(vargv) == 0 {
		vres = ExecResult{ExitCode: -1, Err: "verifier command is not runnable"}
		if verr != nil {
			vres.Err = verr.Error()
		}
		rec.add(Event{Event: "output", Step: "verifier", Line: vres.Err})
	} else {
		vres = ws.Exec(ctx, vargv, env, spec.Verifier.Timeout)
		rec.exec("verifier", spec.Verifier.Argv, vres)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	written, rerr := ws.Read(ctx, capsule.MemberVerdicts)
	switch {
	case vres.TimedOut:
		// A verifier that exceeds its timeout fails, whatever it wrote.
		addVerdict(capsule.Verdict{ID: "verifier", Criterion: "verifier completes within its timeout", Pass: false,
			Evidence: fmt.Sprintf("timed out after %s", spec.Verifier.Timeout)})
	case vres.Err != "":
		addVerdict(capsule.Verdict{ID: "verifier", Criterion: "verifier starts", Pass: false, Evidence: vres.Err})
	case rerr == nil:
		var vs []capsule.Verdict
		if json.Unmarshal(written, &vs) != nil || len(vs) == 0 {
			addVerdict(capsule.Verdict{ID: "verifier", Criterion: "verifier writes a valid verdicts.json", Pass: false, Evidence: "verdicts.json is malformed or empty"})
			break
		}
		for _, vd := range vs {
			if strings.TrimSpace(vd.ID) == "" || strings.TrimSpace(vd.Criterion) == "" {
				addVerdict(capsule.Verdict{ID: "verifier", Criterion: "verifier writes a valid verdicts.json", Pass: false, Evidence: "a verdict lacks id or criterion"})
				continue
			}
			addVerdict(vd)
		}
	case errors.Is(rerr, fs.ErrNotExist):
		// No verdicts.json: the exit code becomes a single criterion.
		vd := capsule.Verdict{ID: "verifier", Criterion: "verifier exits 0", Pass: vres.ExitCode == 0}
		if !vd.Pass {
			vd.Evidence = fmt.Sprintf("exit %d: %s", vres.ExitCode, lastLine(vres.Output))
		}
		addVerdict(vd)
	default:
		addVerdict(capsule.Verdict{ID: "verifier", Criterion: "verdicts.json is readable", Pass: false, Evidence: "cannot read verdicts.json"})
	}

	diff, err := ws.Diff(ctx)
	if err != nil {
		return nil, fmt.Errorf("runner %s: %w", runner.Name(), err)
	}
	if spec.Ring0 != nil {
		changed := map[string]bool{}
		for _, t := range capsule.TouchedPaths(diff) {
			if spec.Ring0(t.Path) {
				changed[t.Path] = true
			}
		}
		// Second, independent check: hash the files as they are on disk, with
		// no filters, and compare with the base blobs.
		for _, path := range locked {
			want, ok := ring0[path]
			if !ok {
				continue
			}
			h := ws.Exec(ctx, []string{"git", "hash-object", "--no-filters", "--", path}, nil, time.Minute)
			if h.ExitCode != 0 || strings.TrimSpace(string(h.Stdout)) != want {
				changed[path] = true
			}
		}
		touched := make([]string, 0, len(changed))
		for path := range changed {
			touched = append(touched, path)
		}
		sort.Strings(touched)
		if len(touched) > 0 {
			addVerdict(capsule.Verdict{ID: "ring0", Criterion: "lane leaves Ring-0 paths unchanged", Pass: false, Evidence: "changed: " + strings.Join(touched, ", ")})
		}
	}

	metrics := capsule.Metrics{}
	if raw, err := ws.Read(ctx, "usage.json"); err == nil {
		var u capsule.Usage
		if json.Unmarshal(raw, &u) == nil && (u.InputTokens > 0 || u.OutputTokens > 0) {
			metrics.Usage = &u
			if spec.Price != nil {
				// Cost comes from reported usage and the price table; never estimated.
				cost := float64(u.InputTokens)/1e6*spec.Price.InputPerMTok + float64(u.OutputTokens)/1e6*spec.Price.OutputPerMTok
				metrics.CostUSD = &cost
			}
		}
	}
	rec.add(Event{Event: "end"})
	ended := now()
	metrics.WallMS = ended.Sub(started).Milliseconds()

	dir, err := os.MkdirTemp("", "chimera-capsule-")
	if err != nil {
		return nil, fmt.Errorf("cannot create capsule directory")
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	var transcript bytes.Buffer
	enc := json.NewEncoder(&transcript)
	enc.SetEscapeHTML(false)
	for _, e := range rec.events {
		enc.Encode(e)
	}
	vjson, _ := json.MarshalIndent(verdicts, "", "  ")
	mjson, _ := json.MarshalIndent(metrics, "", "  ")
	members := map[string][]byte{
		capsule.MemberTranscript: capsule.Zstd(transcript.Bytes()),
		capsule.MemberDiff:       diff,
		capsule.MemberVerdicts:   append(vjson, '\n'),
		capsule.MemberMetrics:    append(mjson, '\n'),
		"proof/harness.log":      hres.Output,
		"proof/verifier.log":     vres.Output,
	}
	for name, data := range members {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
			err = os.WriteFile(p, data, 0o644)
		}
		if err != nil {
			return nil, fmt.Errorf("cannot write capsule member %s", name)
		}
	}
	addr, err := capsule.Pack(dir, capsule.Meta{
		Intent: spec.Intent, Checkpoint: checkpoint, Repo: spec.Repo, BaseSHA: spec.BaseSHA, Lane: spec.Lane,
		StartedAt: started, EndedAt: ended, Tags: spec.Tags,
	})
	if err != nil {
		return nil, err
	}
	return &Result{Dir: dir, Address: addr, Checkpoint: checkpoint, BaseSHA: spec.BaseSHA, Tree: tree, Verdicts: verdicts,
		Metrics: metrics, Diff: diff, Transcript: rec.events, Tags: spec.Tags}, nil
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	l := strings.Join(strings.Fields(lines[len(lines)-1]), " ")
	if r := []rune(l); len(r) > 160 {
		l = string(r[:159]) + "…"
	}
	return l
}
