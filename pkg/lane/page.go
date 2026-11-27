package lane

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"chimera/folio"
	"chimera/pkg/capsule"
)

// benchCSS is appended to the reference stylesheet for the components the
// Bench page adds (DESIGN.md §2.5). Tokens and every other rule come from
// the Folio's trail.css unchanged.
const benchCSS = `
/* chimera / bench — Bench table and empty-section rows (DESIGN.md §2.1, §2.5). */
.best { font-weight: 600; }
caption { text-align: left; font-size: 0.875rem; color: var(--muted); padding: 0 0 8px; }
.scroll + .scroll { margin-top: 32px; }
p.none { margin: 0; padding: 8px 0; border-bottom: 1px solid var(--rule); font-size: 0.875rem; color: var(--muted); }
`

// lockedAssets are copied into every report byte-for-byte.
var lockedAssets = []string{
	"favicon.svg",
	"media/capsule-write.svg",
	"fonts/OFL.txt",
	"fonts/ibm-plex-mono-latin-400-normal.woff2",
	"fonts/ibm-plex-mono-latin-600-normal.woff2",
	"fonts/ibm-plex-sans-latin-400-normal.woff2",
	"fonts/ibm-plex-sans-latin-600-normal.woff2",
}

// LockedAssets returns the names of the Folio assets every report bundle
// ships byte-for-byte, relative to the bundle root.
func LockedAssets() []string { return append([]string{}, lockedAssets...) }

// FormatDuration renders milliseconds for humans: 1.42s, 3m07s.
func FormatDuration(ms int64) string {
	if ms < 60_000 {
		return fmt.Sprintf("%.2fs", float64(ms)/1000)
	}
	s := ms / 1000
	return fmt.Sprintf("%dm%02ds", s/60, s%60)
}

// FormatCost renders a cost, or an em dash when it is unknown.
func FormatCost(c *float64) string {
	if c == nil {
		return "—"
	}
	return fmt.Sprintf("$%.4f", *c)
}

// RiskClass grades one lane's blast radius: R3 if it changed a Ring-0 path,
// R2 for a wide change, R1 for any change, R0 for none.
func RiskClass(l LaneReport) string {
	for _, v := range l.Verdicts {
		if v.ID == "ring0" && !v.Pass {
			return "R3"
		}
	}
	files := len(capsule.TouchedPaths(l.Diff))
	lines := 0
	for _, line := range strings.Split(string(l.Diff), "\n") {
		if (strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++")) || (strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---")) {
			lines++
		}
	}
	switch {
	case files > 5 || lines > 200:
		return "R2"
	case files > 0:
		return "R1"
	}
	return "R0"
}

type pageRisk struct {
	Class, Lane, Reason, Href, LinkText string
	High                                bool
}

type pageUnmet struct{ ID, Criterion, Cell string }

type pageMissing struct{ Cell, K, Reason string }

type pageBenchRow struct {
	Model, Harness, Effort, Context, PassRate, XofK, P50, P90, Cost string
	BestRate, BestX, BestP50, BestP90, BestCost                     bool
}

type pageBench struct {
	Fixture, Intent string
	Rows            []pageBenchRow
}

type pageVerdict struct {
	ID, Criterion, State, Href, LinkText string
	Fail                                 bool
}

type pageLine struct {
	Anchor, Text string
	N            int
}

type pageLane struct {
	Anchor, Capsule, Fixture, Cell, K, Wall, State, Summary string
	Fail, HasCapsule                                        bool
	Lines                                                   []pageLine
	Skipped                                                 int
}

type pageData struct {
	Title, Repo, Bench, Intent, Risk, Footer string
	RiskHigh                                 bool
	Pass, FailCount                          int
	Risks                                    []pageRisk
	Unmet                                    []pageUnmet
	Missing                                  []pageMissing
	Benches                                  []pageBench
	Verdicts                                 []pageVerdict
	Lanes                                    []pageLane
	Cells                                    int
}

// maxPageLines bounds transcript lines rendered per lane; the Capsule holds
// the full transcript.
const maxPageLines = 200

var pageTmpl = template.Must(template.New("bench").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<title>{{.Title}}</title>
<link rel="stylesheet" href="trail.css">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
</head>
<body>
<header class="masthead">
  <p class="wordmark">chimera / bench</p>
  <h1>{{.Repo}} <span class="mono">bench:{{.Bench}}</span></h1>
  <dl class="facts">
    <div><dt>Intent</dt><dd class="mono">{{.Intent}}</dd></div>
    <div><dt>Risk class</dt><dd><span class="risk{{if .RiskHigh}} risk-high{{end}}">{{.Risk}}</span></dd></div>
    <div><dt>Open risk</dt><dd class="num">{{len .Risks}}</dd></div>
    <div><dt>Unmet intent</dt><dd class="num">{{len .Unmet}}</dd></div>
    <div><dt>Missing proof</dt><dd class="num">{{len .Missing}}</dd></div>
    <div><dt>Verdicts</dt><dd class="num">{{len .Verdicts}} <span class="muted">({{.Pass}} pass, {{.FailCount}} fail)</span></dd></div>
  </dl>
</header>

<div class="layout">
<nav class="index" aria-label="Sections">
  <ol>
    <li><a href="#risk">Open risk <span class="num">{{len .Risks}}</span></a></li>
    <li><a href="#unmet">Unmet intent <span class="num">{{len .Unmet}}</span></a></li>
    <li><a href="#missing">Missing proof <span class="num">{{len .Missing}}</span></a></li>
    <li><a href="#bench">Bench <span class="num">{{.Cells}}</span></a></li>
    <li><a href="#verdicts">Verdicts <span class="num">{{len .Verdicts}}</span></a></li>
    <li><a href="#media">Media <span class="num">1</span></a></li>
    <li><a href="#lanes">Lanes <span class="num">{{len .Lanes}}</span></a></li>
  </ol>
</nav>

<main>
<section id="risk" aria-labelledby="risk-h">
  <h2 id="risk-h">Open risk</h2>
{{- if .Risks}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">Class</th><th scope="col">Lane</th><th scope="col">Reason</th><th scope="col">Source</th></tr></thead>
    <tbody>
{{- range .Risks}}
      <tr class="fail"><td><span class="risk{{if .High}} risk-high{{end}}">{{.Class}}</span></td><td class="mono">{{.Lane}}</td><td>{{.Reason}}</td><td>{{if .Href}}<a href="{{.Href}}">{{.LinkText}}</a>{{else}}—{{end}}</td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
{{- end}}
</section>

<section id="unmet" aria-labelledby="unmet-h">
  <h2 id="unmet-h">Unmet intent</h2>
{{- if .Unmet}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">ID</th><th scope="col">Criterion</th><th scope="col">Cell</th><th scope="col">State</th></tr></thead>
    <tbody>
{{- range .Unmet}}
      <tr class="fail"><td class="mono">{{.ID}}</td><td>{{.Criterion}}</td><td class="mono">{{.Cell}}</td><td><span class="state">FAIL</span></td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
{{- end}}
</section>

<section id="missing" aria-labelledby="missing-h">
  <h2 id="missing-h">Missing proof</h2>
{{- if .Missing}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">Cell</th><th scope="col">Lane</th><th scope="col">Missing</th></tr></thead>
    <tbody>
{{- range .Missing}}
      <tr class="fail"><td class="mono">{{.Cell}}</td><td class="mono">{{.K}}</td><td>{{.Reason}}</td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
{{- end}}
</section>

<section id="bench" aria-labelledby="bench-h">
  <h2 id="bench-h">Bench</h2>
{{- range .Benches}}
  <div class="scroll">
  <table>
    <caption>{{.Fixture}} · <span class="mono">{{.Intent}}</span></caption>
    <thead><tr><th scope="col">Model</th><th scope="col">Harness</th><th scope="col">Effort</th><th scope="col">Context</th><th scope="col">Pass rate</th><th scope="col">x/K</th><th scope="col">Wall p50</th><th scope="col">Wall p90</th><th scope="col">Cost</th></tr></thead>
    <tbody>
{{- range .Rows}}
      <tr><td class="mono">{{.Model}}</td><td class="mono">{{.Harness}}</td><td>{{.Effort}}</td><td>{{.Context}}</td><td class="num{{if .BestRate}} best{{end}}">{{.PassRate}}</td><td class="num{{if .BestX}} best{{end}}">{{.XofK}}</td><td class="num{{if .BestP50}} best{{end}}">{{.P50}}</td><td class="num{{if .BestP90}} best{{end}}">{{.P90}}</td><td class="num{{if .BestCost}} best{{end}}">{{.Cost}}</td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- end}}
</section>

<section id="verdicts" aria-labelledby="verdicts-h">
  <h2 id="verdicts-h">Verdicts</h2>
{{- if .Verdicts}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">ID</th><th scope="col">Criterion</th><th scope="col">State</th><th scope="col">Evidence</th></tr></thead>
    <tbody>
{{- range .Verdicts}}
      <tr{{if .Fail}} class="fail"{{end}}><td class="mono">{{.ID}}</td><td>{{.Criterion}}</td><td><span class="state">{{.State}}</span></td><td><a href="{{.Href}}">{{.LinkText}}</a></td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
{{- end}}
</section>

<section id="media" aria-labelledby="media-h">
  <h2 id="media-h">Media</h2>
  <figure>
    <img src="media/capsule-write.svg" width="720" height="200" alt="Capsule write protocol: secret gate, members, capsule.json last, readback">
    <figcaption><span class="mono">capsule-write.svg</span> · <span class="mono">[M1-2]</span></figcaption>
  </figure>
</section>

<section id="lanes" aria-labelledby="lanes-h">
  <h2 id="lanes-h">Lanes</h2>
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">Capsule</th><th scope="col">Fixture</th><th scope="col">Cell</th><th scope="col">Lane</th><th scope="col">Wall</th><th scope="col">State</th></tr></thead>
    <tbody>
{{- range .Lanes}}
      <tr{{if .Fail}} class="fail"{{end}}><td class="mono">{{if .HasCapsule}}<a href="#{{.Anchor}}">{{.Capsule}}</a>{{else}}—{{end}}</td><td>{{.Fixture}}</td><td class="mono">{{.Cell}}</td><td class="mono">{{.K}}</td><td class="num">{{.Wall}}</td><td><span class="state">{{.State}}</span></td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{range .Lanes}}
  <details id="{{.Anchor}}">
    <summary>{{.Summary}}</summary>
    <ol class="transcript">
{{- $lane := .}}
{{- if .Skipped}}
      <li><span class="ln">…</span><code>{{.Skipped}} earlier lines are in the capsule transcript</code></li>
{{- end}}
{{- range .Lines}}
      <li id="{{.Anchor}}"><a href="#{{.Anchor}}" class="ln">{{.N}}</a><code>{{.Text}}</code></li>
{{- end}}
    </ol>
  </details>
{{- end}}
</section>
</main>
</div>

<footer class="colophon">
  <p class="mono">{{.Footer}}</p>
</footer>
</body>
</html>
`))

// RenderPage builds index.html for a Bench report.
func RenderPage(rep *Report) ([]byte, error) {
	d := pageData{Bench: rep.Bench, Risk: "R0", Cells: len(rep.Cells)}
	if d.Bench == "" {
		d.Bench = "run"
	}
	intents := map[string]bool{}
	repos := map[string]bool{}
	byFixture := map[string]*pageBench{}
	var fixtureOrder []string
	lanes := 0
	for _, c := range rep.Cells {
		intents[c.Intent] = true
		repos[c.Repo] = true
		pb, ok := byFixture[c.Fixture]
		if !ok {
			pb = &pageBench{Fixture: c.Fixture, Intent: abbrevID(c.Intent)}
			byFixture[c.Fixture] = pb
			fixtureOrder = append(fixtureOrder, c.Fixture)
		}
		pb.Rows = append(pb.Rows, pageBenchRow{
			Model: dash(c.Lane.Model), Harness: dash(c.Lane.Harness), Effort: dash(c.Lane.Effort), Context: dash(c.Lane.ContextPolicy),
			PassRate: fmt.Sprintf("%.2f", c.PassRate), XofK: fmt.Sprintf("%d/%d", c.AllPass, c.K),
			P50: FormatDuration(c.WallP50MS), P90: FormatDuration(c.WallP90MS), Cost: FormatCost(c.CostUSD),
		})
		// A criterion no lane of the cell passed is unmet intent.
		type crit struct{ id, criterion string }
		met := map[crit]bool{}
		var order []crit
		for li, l := range c.Lanes {
			lanes++
			laneKey := fmt.Sprintf("%s-k%d", c.Cell, l.K)
			laneLabel := fmt.Sprintf("%s/k%d", c.Cell, l.K)
			pl := pageLane{Anchor: "cap-" + laneKey, Fixture: c.Fixture, Cell: c.Cell, K: fmt.Sprintf("k%d", l.K), Wall: FormatDuration(l.WallMS),
				State: "PASS", HasCapsule: l.Capsule != ""}
			if !l.Pass {
				pl.State, pl.Fail = "FAIL", true
			}
			if l.Capsule == "" {
				reason := l.Error
				if reason == "" {
					reason = "no capsule"
				}
				d.Missing = append(d.Missing, pageMissing{Cell: c.Cell, K: pl.K, Reason: reason})
				pl.Wall = "—"
			} else {
				pl.Capsule = abbrevID(l.Capsule)[len("sha256:"):]
			}
			pl.Summary = strings.Join(nonEmptyStrings(orStr(abbrevID(l.Capsule), "no capsule"), "lane "+dash(c.Lane.Runner), c.Lane.Model, c.Lane.Harness,
				prefixed("effort ", c.Lane.Effort), prefixed("context ", c.Lane.ContextPolicy)), " · ")
			events := l.Transcript
			if len(events) > maxPageLines {
				pl.Skipped = len(events) - maxPageLines
				events = events[pl.Skipped:]
			}
			seqAnchor := map[int]string{}
			for _, e := range events {
				a := fmt.Sprintf("t-%s-%d", laneKey, e.Seq)
				seqAnchor[e.Seq] = a
				pl.Lines = append(pl.Lines, pageLine{Anchor: a, N: e.Seq, Text: e.Text()})
			}
			// Each verdict links to the transcript line that recorded it.
			verdictSeq := map[int]int{}
			n := 0
			for _, e := range l.Transcript {
				if e.Event == "verdict" {
					verdictSeq[n] = e.Seq
					n++
				}
			}
			class := RiskClass(l)
			if class > d.Risk {
				d.Risk = class
			}
			for vi, v := range l.Verdicts {
				k := crit{v.ID, v.Criterion}
				if _, seen := met[k]; !seen {
					order = append(order, k)
					met[k] = false
				}
				met[k] = met[k] || v.Pass
				seq := verdictSeq[vi]
				href := "#" + pl.Anchor
				if a, ok := seqAnchor[seq]; ok {
					href = "#" + a
				}
				pv := pageVerdict{ID: v.ID, Criterion: v.Criterion, State: "PASS", Href: href, LinkText: fmt.Sprintf("Transcript %s line %d", laneLabel, seq)}
				if v.Pass {
					d.Pass++
				} else {
					pv.State, pv.Fail = "FAIL", true
					d.FailCount++
					if v.ID == "harness" || v.ID == "ring0" {
						d.Risks = append(d.Risks, pageRisk{Class: class, High: class >= "R2", Lane: laneLabel, Reason: v.Criterion + ": " + v.Evidence, Href: href, LinkText: pv.LinkText})
					}
				}
				d.Verdicts = append(d.Verdicts, pv)
			}
			if class == "R2" {
				d.Risks = append(d.Risks, pageRisk{Class: class, High: true, Lane: laneLabel, Reason: "wide change: " + fmt.Sprintf("%d files", len(capsule.TouchedPaths(l.Diff))), Href: "#" + pl.Anchor, LinkText: "Lane " + laneLabel})
			}
			d.Lanes = append(d.Lanes, pl)
			_ = li
		}
		for _, k := range order {
			if !met[k] {
				d.Unmet = append(d.Unmet, pageUnmet{ID: k.id, Criterion: k.criterion, Cell: c.Cell})
			}
		}
	}
	d.RiskHigh = d.Risk >= "R2"
	// Failures first within the verdict table; order is otherwise plan order.
	sort.SliceStable(d.Verdicts, func(i, j int) bool { return d.Verdicts[i].Fail && !d.Verdicts[j].Fail })
	for _, name := range fixtureOrder {
		pb := byFixture[name]
		markBest(pb.Rows, rep, name)
		d.Benches = append(d.Benches, *pb)
	}
	d.Repo = joinKeys(repos)
	switch len(intents) {
	case 1:
		d.Intent = abbrevID(joinKeys(intents))
	default:
		d.Intent = fmt.Sprintf("%d intents", len(intents))
	}
	d.Title = fmt.Sprintf("chimera / bench — %s bench:%s", d.Repo, d.Bench)
	d.Footer = fmt.Sprintf("chimera bench · bench:%s · K=%d · %d cells · %d lanes · every row resolves to a capsule", d.Bench, rep.K, len(rep.Cells), lanes)
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("cannot render page")
	}
	return buf.Bytes(), nil
}

// markBest sets weight 600 on the best value of each column within a fixture.
func markBest(rows []pageBenchRow, rep *Report, fixture string) {
	var cells []CellReport
	for _, c := range rep.Cells {
		if c.Fixture == fixture {
			cells = append(cells, c)
		}
	}
	if len(cells) == 0 {
		return
	}
	// A wall time or a cost is only "best" for a cell that passed at least
	// once: the fastest or cheapest way to fail everything is not an
	// achievement to set in weight 600. A column whose best is zero has none.
	bestRate, bestX := cells[0].PassRate, cells[0].AllPass
	bestP50, bestP90 := int64(-1), int64(-1)
	var bestCost *float64
	for _, c := range cells {
		if c.PassRate > bestRate {
			bestRate = c.PassRate
		}
		if c.AllPass > bestX {
			bestX = c.AllPass
		}
		if c.AllPass > 0 {
			if bestP50 < 0 || c.WallP50MS < bestP50 {
				bestP50 = c.WallP50MS
			}
			if bestP90 < 0 || c.WallP90MS < bestP90 {
				bestP90 = c.WallP90MS
			}
		}
		if c.AllPass > 0 && c.CostUSD != nil && (bestCost == nil || *c.CostUSD < *bestCost) {
			bestCost = c.CostUSD
		}
	}
	for i, c := range cells {
		rows[i].BestRate = bestRate > 0 && c.PassRate == bestRate
		rows[i].BestX = bestX > 0 && c.AllPass == bestX
		rows[i].BestP50 = c.AllPass > 0 && c.WallP50MS == bestP50
		rows[i].BestP90 = c.AllPass > 0 && c.WallP90MS == bestP90
		rows[i].BestCost = c.AllPass > 0 && c.CostUSD != nil && bestCost != nil && *c.CostUSD == *bestCost
	}
}

func joinKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return dash(strings.Join(keys, ", "))
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func prefixed(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

func nonEmptyStrings(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// abbrevID shortens "kind:<hex>" to 12 hex characters.
func abbrevID(id string) string {
	if k, v, ok := strings.Cut(id, ":"); ok && len(v) > 12 {
		return k + ":" + v[:12]
	}
	return id
}

// WritePage writes the static report bundle to dir: index.html, trail.css,
// favicon.svg, fonts/, and media/. The favicon, fonts, and media are the
// Folio's files byte-for-byte; trail.css is the Folio's stylesheet with the
// Bench rules appended. The bundle opens from disk under a strict CSP.
func WritePage(dir string, rep *Report) error {
	html, err := RenderPage(rep)
	if err != nil {
		return err
	}
	css, err := fs.ReadFile(folio.Assets, folio.TrailReference+"/trail.css")
	if err != nil {
		return fmt.Errorf("reference stylesheet missing from the binary")
	}
	files := map[string][]byte{"index.html": html, "trail.css": append(css, []byte(benchCSS)...)}
	for _, name := range lockedAssets {
		data, err := fs.ReadFile(folio.Assets, folio.TrailReference+"/"+name)
		if err != nil {
			return fmt.Errorf("reference asset %s missing from the binary", name)
		}
		files[name] = data
	}
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("cannot create %s", filepath.Dir(name))
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return fmt.Errorf("cannot write %s", name)
		}
	}
	return nil
}
