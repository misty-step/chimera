package trail

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
	"chimera/pkg/lane"
)

// trailCSS is appended to the reference stylesheet for what a generated
// Trail adds to the reference rendering (DESIGN.md §2.1, §2.5): the empty
// section row, video, more than one figure, elided transcript runs, and
// transcript lines that wrap inside themselves however long their tokens.
// Tokens and every other rule come from the Folio's trail.css unchanged.
const trailCSS = `
/* chimera / trail — generated pages: empty rows, video, elided transcript (DESIGN.md §2.1, §2.5). */
p.none { margin: 0; padding: 8px 0; border-bottom: 1px solid var(--rule); font-size: 0.875rem; color: var(--muted); }
figure + figure { margin-top: 32px; }
figure video { max-width: 100%; height: auto; border: 1px solid var(--rule); display: block; }
.transcript li.gap { color: var(--muted); }
td .muted { font-size: 0.75rem; }
/* A long unbroken token (a URL, a JSON blob) wraps inside its line instead of widening the page (DESIGN.md §2.4). */
.transcript code { min-width: 0; overflow-wrap: anywhere; }
/* A wide table's scroll container is a keyboard stop: it takes the accent focus ring too (DESIGN.md §2.6). */
.scroll:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
`

type pageLink struct{ Href, Text string }

type pageRisk struct {
	Class  string
	High   bool
	Path   template.HTML
	Reason string
	Source pageLink
}

type pageUnmet struct{ ID, Criterion, State string }

type pageMissing struct{ SHA, Subject, Missing string }

type pageVerdict struct {
	ID, Criterion, State, Superseded string
	Accent                           bool
	Source                           pageLink
}

type pageMedia struct {
	Video              bool
	Src, Name, ID, Alt string
	Width, Height      int
}

type pageCap struct{ Hex, Anchor string }

type pageCommit struct {
	SHA      string
	Subject  string
	Fail     bool
	Capsules []pageCap
	Intents  string
}

type pageLine struct {
	Anchor, Text string
	N            int
	Gap          int
}

type pageCapsule struct {
	Anchor, Address, Summary string
	Lines                    []pageLine
}

type pageData struct {
	Repo, Range, Intent, Risk, Footer string
	RiskHigh                          bool
	Counts                            string
	Risks                             []pageRisk
	Unmet                             []pageUnmet
	Missing                           []pageMissing
	Verdicts                          []pageVerdict
	Media                             []pageMedia
	Commits                           []pageCommit
	Capsules                          []pageCapsule
}

var pageTmpl = template.Must(template.New("trail").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
<title>chimera / trail — {{.Repo}} {{.Range}}</title>
<link rel="stylesheet" href="trail.css">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
</head>
<body>
<header class="masthead">
  <p class="wordmark">chimera / trail</p>
  <h1>{{.Repo}} <span class="mono">{{.Range}}</span></h1>
  <dl class="facts">
    <div><dt>Intent</dt><dd class="mono">{{.Intent}}</dd></div>
    <div><dt>Risk class</dt><dd><span class="risk{{if .RiskHigh}} risk-high{{end}}">{{.Risk}}</span></dd></div>
    <div><dt>Open risk</dt><dd class="num">{{len .Risks}}</dd></div>
    <div><dt>Unmet intent</dt><dd class="num">{{len .Unmet}}</dd></div>
    <div><dt>Missing proof</dt><dd class="num">{{len .Missing}}</dd></div>
    <div><dt>Verdicts</dt><dd class="num">{{len .Verdicts}} <span class="muted">({{.Counts}})</span></dd></div>
  </dl>
</header>

<div class="layout">
<nav class="index" aria-label="Sections">
  <ol>
    <li><a href="#risk">Open risk <span class="num">{{len .Risks}}</span></a></li>
    <li><a href="#unmet">Unmet intent <span class="num">{{len .Unmet}}</span></a></li>
    <li><a href="#missing">Missing proof <span class="num">{{len .Missing}}</span></a></li>
    <li><a href="#verdicts">Verdicts <span class="num">{{len .Verdicts}}</span></a></li>
    <li><a href="#media">Media <span class="num">{{len .Media}}</span></a></li>
    <li><a href="#commits">Commits <span class="num">{{len .Commits}}</span></a></li>
  </ol>
</nav>

<main>
<section id="risk" aria-labelledby="risk-h">
  <h2 id="risk-h">Open risk</h2>
{{- if .Risks}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">Class</th><th scope="col">Path</th><th scope="col">Reason</th><th scope="col">Source</th></tr></thead>
    <tbody>
{{- range .Risks}}
      <tr class="fail"><td>{{if .Class}}<span class="risk{{if .High}} risk-high{{end}}">{{.Class}}</span>{{else}}—{{end}}</td><td class="mono">{{.Path}}</td><td>{{.Reason}}</td><td><a href="{{.Source.Href}}">{{.Source.Text}}</a></td></tr>
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
    <thead><tr><th scope="col">ID</th><th scope="col">Criterion</th><th scope="col">State</th></tr></thead>
    <tbody>
{{- range .Unmet}}
      <tr class="fail"><td class="mono">{{.ID}}</td><td>{{.Criterion}}</td><td><span class="state">{{.State}}</span></td></tr>
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
    <thead><tr><th scope="col">Commit</th><th scope="col">Subject</th><th scope="col">Missing</th></tr></thead>
    <tbody>
{{- range .Missing}}
      <tr class="fail"><td class="mono"><a href="#c-{{.SHA}}">{{.SHA}}</a></td><td>{{.Subject}}</td><td>{{.Missing}}</td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
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
      <tr{{if .Accent}} class="fail"{{end}}><td class="mono">{{.ID}}</td><td>{{.Criterion}}{{if .Superseded}} <span class="muted">superseded by {{.Superseded}}</span>{{end}}</td><td><span class="state">{{.State}}</span></td><td><a href="{{.Source.Href}}">{{.Source.Text}}</a></td></tr>
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
{{- range .Media}}
  <figure>
{{- if .Video}}
    <video controls preload="metadata" width="{{.Width}}" height="{{.Height}}" src="{{.Src}}" aria-label="{{.Alt}}"></video>
{{- else}}
    <img src="{{.Src}}" width="{{.Width}}" height="{{.Height}}" alt="{{.Alt}}">
{{- end}}
    <figcaption><span class="mono">{{.Name}}</span> · <span class="mono">{{.ID}}</span></figcaption>
  </figure>
{{- else}}
  <p class="none">None.</p>
{{- end}}
</section>

<section id="commits" aria-labelledby="commits-h">
  <h2 id="commits-h">Commits</h2>
{{- if .Commits}}
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">Commit</th><th scope="col">Subject</th><th scope="col">Capsule</th><th scope="col">Intent</th></tr></thead>
    <tbody>
{{- range .Commits}}
      <tr id="c-{{.SHA}}"{{if .Fail}} class="fail"{{end}}><td class="mono">{{.SHA}}</td><td>{{.Subject}}</td><td class="mono">{{range $i, $c := .Capsules}}{{if $i}} {{end}}{{if $c.Anchor}}<a href="#{{$c.Anchor}}">{{$c.Hex}}</a>{{else}}{{$c.Hex}}{{end}}{{else}}—{{end}}</td><td class="mono">{{.Intents}}</td></tr>
{{- end}}
    </tbody>
  </table>
  </div>
{{- else}}
  <p class="none">None.</p>
{{- end}}
{{range .Capsules}}
  <details id="{{.Anchor}}">
    <summary><span class="mono">{{.Address}}</span>{{.Summary}}</summary>
    <ol class="transcript">
{{- range .Lines}}
{{- if .Gap}}
      <li class="gap"><span class="ln">…</span><code>{{.Gap}} lines in the capsule transcript</code></li>
{{- else}}
      <li id="{{.Anchor}}"><a href="#{{.Anchor}}" class="ln">{{.N}}</a><code>{{.Text}}</code></li>
{{- end}}
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

// wbrPath escapes a path and lets it break after every slash, as the
// reference rendering does, so a long path never widens the page.
func wbrPath(p string) template.HTML {
	if p == "" {
		return "—"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = template.HTMLEscapeString(s)
	}
	return template.HTML(strings.Join(segs, "/<wbr>"))
}

func capAnchor(addr string) string { return "cap-" + hex12(addr) }

func lineAnchor(addr string, n int) string { return fmt.Sprintf("t-%s-%d", hex12(addr), n) }

// link turns a Source into the one click that reaches it (DESIGN.md §2.1).
// A Capsule or line that is not on the page falls back to the commit row.
func (r *Report) link(s Source, onPage map[string]bool) pageLink {
	if s.Capsule != "" && s.Line > 0 && onPage[lineAnchor(s.Capsule, s.Line)] {
		return pageLink{Href: "#" + lineAnchor(s.Capsule, s.Line), Text: fmt.Sprintf("Transcript %s line %d", hex12(s.Capsule), s.Line)}
	}
	if s.Capsule != "" && onPage[capAnchor(s.Capsule)] {
		return pageLink{Href: "#" + capAnchor(s.Capsule), Text: "Capsule " + hex12(s.Capsule)}
	}
	sha := s.Commit
	if sha == "" {
		for _, c := range r.Capsules {
			if c.Address == s.Capsule && len(c.Commits) > 0 {
				sha = c.Commits[0]
			}
		}
	}
	if sha == "" {
		return pageLink{Href: "#commits", Text: "Commits"}
	}
	return pageLink{Href: "#c-" + abbrevID(sha), Text: "Commit " + abbrevID(sha)}
}

// RenderHTML builds index.html for a Trail (DESIGN.md §2): failures first,
// no score, no script, nothing inline, every row one click from its
// transcript line. The same Report always renders the same bytes.
func RenderHTML(r *Report) ([]byte, error) {
	d := pageData{Repo: r.Repo, Range: abbrevID(r.Base) + ".." + abbrevID(r.Head), Risk: r.Risk, RiskHigh: r.Risk >= "R2"}
	if d.Repo == "" {
		d.Repo = "—"
	}
	switch len(r.Intents) {
	case 0:
		d.Intent = "—"
	case 1:
		d.Intent = abbrevID(r.Intents[0])
	default:
		d.Intent = fmt.Sprintf("%d intents", len(r.Intents))
	}
	pass, fail, stale, superseded := r.Counts()
	d.Counts = fmt.Sprintf("%d pass, %d fail", pass, fail)
	if stale > 0 {
		d.Counts += fmt.Sprintf(", %d stale", stale)
	}
	if superseded > 0 {
		d.Counts += fmt.Sprintf(", %d superseded", superseded)
	}

	onPage := map[string]bool{}
	for _, c := range r.Capsules {
		pc := pageCapsule{Anchor: capAnchor(c.Address), Address: abbrevID(c.Address)}
		onPage[pc.Anchor] = true
		for _, part := range []string{prefixed("lane ", c.Lane.Runner), c.Lane.Model, c.Lane.Harness, prefixed("effort ", c.Lane.Effort), prefixed("context ", c.Lane.ContextPolicy)} {
			if part != "" {
				pc.Summary += " · " + part
			}
		}
		for _, l := range c.Transcript {
			if l.Gap > 0 {
				pc.Lines = append(pc.Lines, pageLine{Gap: l.Gap})
				continue
			}
			a := lineAnchor(c.Address, l.N)
			onPage[a] = true
			pc.Lines = append(pc.Lines, pageLine{Anchor: a, N: l.N, Text: l.Text})
		}
		d.Capsules = append(d.Capsules, pc)
	}
	for _, it := range r.OpenRisk {
		d.Risks = append(d.Risks, pageRisk{Class: it.Class, High: it.Class >= "R2", Path: wbrPath(it.Path), Reason: it.Reason, Source: r.link(it.Source, onPage)})
	}
	for _, u := range r.Unmet {
		d.Unmet = append(d.Unmet, pageUnmet{ID: u.ID, Criterion: u.Criterion, State: u.State})
	}
	for _, m := range r.Missing {
		d.Missing = append(d.Missing, pageMissing{SHA: abbrevID(m.Commit), Subject: m.Subject, Missing: strings.Join(m.Reasons, "; ")})
	}
	for _, v := range r.Verdicts {
		// Every row that is not PASS carries the accent rule, superseded or not.
		pv := pageVerdict{ID: v.ID, Criterion: v.Criterion, State: v.State, Accent: v.State != StatePass, Source: r.link(v.Source, onPage)}
		if v.SupersededBy != "" {
			pv.Superseded = hex12(v.SupersededBy)
		}
		d.Verdicts = append(d.Verdicts, pv)
	}
	for _, m := range r.Media {
		pm := pageMedia{Video: m.Kind == "video", Src: m.File, Name: m.Name, ID: m.ID, Width: m.Width, Height: m.Height}
		if pm.ID == "" {
			pm.ID = "—"
		}
		pm.Alt = fmt.Sprintf("Proof %s from capsule %s", m.Name, hex12(m.Capsule))
		d.Media = append(d.Media, pm)
	}
	for _, c := range r.Commits {
		pc := pageCommit{SHA: abbrevID(c.SHA), Subject: c.Subject, Fail: c.Missing, Intents: "—"}
		for _, a := range c.Capsules {
			cap := pageCap{Hex: hex12(a)}
			if onPage[capAnchor(a)] {
				cap.Anchor = capAnchor(a)
			}
			pc.Capsules = append(pc.Capsules, cap)
		}
		if len(c.Intents) > 0 {
			short := make([]string, len(c.Intents))
			for i, id := range c.Intents {
				short[i] = abbrevID(id)
			}
			pc.Intents = strings.Join(short, " ")
		}
		d.Commits = append(d.Commits, pc)
	}
	d.Footer = fmt.Sprintf("chimera trail · %s · %d commits · %d capsules · %d files, %d packages, %d lines",
		d.Range, len(r.Commits), len(r.Capsules), r.Stats.Files, r.Stats.Packages, r.Stats.Lines)
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("cannot render page")
	}
	return buf.Bytes(), nil
}

func prefixed(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// BundleFiles returns every file of the static Trail bundle, keyed by its
// path inside the bundle: index.html, trail.css (the Folio's stylesheet with
// the Trail rules appended), the Folio's favicon, fonts, and reference media
// byte for byte, and the Capsule media byte for byte.
func BundleFiles(r *Report) (map[string][]byte, error) {
	html, err := RenderHTML(r)
	if err != nil {
		return nil, err
	}
	css, err := fs.ReadFile(folio.Assets, folio.TrailReference+"/trail.css")
	if err != nil {
		return nil, fmt.Errorf("reference stylesheet missing from the binary")
	}
	files := map[string][]byte{"index.html": html, "trail.css": append(append([]byte{}, css...), []byte(trailCSS)...)}
	for _, name := range lane.LockedAssets() {
		data, err := fs.ReadFile(folio.Assets, folio.TrailReference+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("reference asset %s missing from the binary", name)
		}
		files[name] = data
	}
	for _, m := range r.Media {
		data, ok := r.media[m.File]
		if !ok {
			return nil, fmt.Errorf("media %s: bytes not loaded; build the report from the store", m.Name)
		}
		if _, clash := files[m.File]; clash {
			return nil, fmt.Errorf("media %s: name collides with a bundle asset", m.Name)
		}
		files[m.File] = data
	}
	return files, nil
}

// WriteBundle writes the static Trail bundle to dir. It opens from disk or
// any static host under the strict CSP of DESIGN.md §2.6.
func WriteBundle(dir string, r *Report) error {
	files, err := BundleFiles(r)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	// A page written over an older one must not keep the older one's proof:
	// regular files in media/ that this bundle does not hold are removed.
	if entries, err := os.ReadDir(filepath.Join(dir, "media")); err == nil {
		for _, e := range entries {
			if _, keep := files["media/"+e.Name()]; !keep && e.Type().IsRegular() {
				if err := os.Remove(filepath.Join(dir, "media", e.Name())); err != nil {
					return fmt.Errorf("cannot remove stale media/%s", e.Name())
				}
			}
		}
	}
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return fmt.Errorf("cannot create %s", filepath.Dir(name))
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			return fmt.Errorf("cannot write %s", name)
		}
	}
	return nil
}
