// Package trail is the review view that replaces passive diffs (PRODUCT.md
// §2.4). It walks the Chimera-Intent and Chimera-Capsule trailers of a commit
// range, fetches and verifies every Capsule, and reports the evidence rather
// than the diff: a risk class from blast radius, spec drift (unmet intent and
// orphan proof), commits with missing proof, every verdict, and watchable
// media. Failures are listed, never folded into a score.
//
// Everything here is derived: the same range and the same store give the
// same Report, byte for byte.
package trail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
)

// Schema identifies the JSON form of a Report.
const Schema = "chimera.trail/v1"

// Status words (DESIGN.md §1.4). A verdict that passes but cites an
// acceptance ID its Intent does not contain is STALE: proof of nothing.
const (
	StatePass    = "PASS"
	StateFail    = "FAIL"
	StatePending = "PENDING"
	StateStale   = "STALE"
)

// Options select the range and the services a Trail is built from.
type Options struct {
	RepoDir string // Git work tree holding the range
	Repo    string // name shown on the report
	Base    string // revision the range starts after
	Head    string // revision the range ends at
	Store   objstore.Store
	// Ring0 reports Ring-0 paths; a range touching one is always R3. nil: none.
	Ring0 func(path string) bool
	// RiskGlob returns the class ("R1".."R3") and the glob of the config risk
	// glob a path matches, or "" when it matches none. nil: none.
	RiskGlob func(path string) (class, glob string)
}

// Stats is the blast radius of the whole range, base..head.
type Stats struct {
	Files    int `json:"files"`
	Packages int `json:"packages"` // distinct directories
	Lines    int `json:"lines"`    // added plus deleted
}

// Check is the forge check summary: a state word, one line of counts, and a
// few plain lines. It is what Land reports on a commit.
type Check struct {
	State   string `json:"state"` // PASS, FAIL, or PENDING
	Title   string `json:"title"`
	Summary string `json:"summary"`
}

// Source says where a row's evidence is: a transcript line of a Capsule, the
// Capsule itself, or — when there is no Capsule — the commit.
type Source struct {
	Capsule string `json:"capsule,omitempty"`
	Line    int    `json:"line,omitempty"`
	Commit  string `json:"commit,omitempty"`
}

// RiskItem is one row of Open risk.
type RiskItem struct {
	Kind   string `json:"kind"`  // path | wide | uncovered | verdict | orphan | intent
	Class  string `json:"class"` // R2 or R3 for blast-radius rows; "" otherwise
	Path   string `json:"path"`  // "" when the row is not about one file
	Reason string `json:"reason"`
	Source Source `json:"source"`
}

// Unmet is one row of Unmet intent: an acceptance ID of the Intent without a
// passing verdict in the range.
type Unmet struct {
	ID        string `json:"id"`
	Criterion string `json:"criterion"`
	State     string `json:"state"` // FAIL (a criterion fails) or PENDING (never judged)
	Intent    string `json:"intent"`
	Source    Source `json:"source"`
}

// Missing is one row of Missing proof: a commit whose binding to evidence is
// absent or does not hold.
type Missing struct {
	Commit  string   `json:"commit"`
	Subject string   `json:"subject"`
	Reasons []string `json:"reasons"`
}

// Orphan is a verdict citing an acceptance ID its Intent does not contain.
type Orphan struct {
	ID        string `json:"id"`
	Criterion string `json:"criterion"`
	Pass      bool   `json:"pass"`
	Intent    string `json:"intent"`
	Capsule   string `json:"capsule"`
	Source    Source `json:"source"`
}

// Verdict is one verdict of one verified Capsule.
type Verdict struct {
	ID        string `json:"id"`
	Criterion string `json:"criterion"`
	Pass      bool   `json:"pass"`
	State     string `json:"state"` // PASS, FAIL, or STALE
	Evidence  string `json:"evidence"`
	Capsule   string `json:"capsule"`
	Commit    string `json:"commit"`
	// SupersededBy names the newer Capsule in the range that judged the same
	// acceptance ID and criterion again; such a verdict no longer decides.
	SupersededBy string `json:"superseded_by,omitempty"`
	Source       Source `json:"source"`
}

// Media is one watchable proof file copied out of a Capsule.
type Media struct {
	File    string `json:"file"`   // path inside the bundle, media/<capsule12>-<name>
	Name    string `json:"name"`   // file name inside the Capsule's proof/
	Member  string `json:"member"` // Capsule member path
	Kind    string `json:"kind"`   // image | video
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	ID      string `json:"id"` // acceptance ID the file proves; "" when unknown
	Capsule string `json:"capsule"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

// Commit is one commit of the range.
type Commit struct {
	SHA      string   `json:"sha"`
	Subject  string   `json:"subject"`
	Intents  []string `json:"intents"`
	Capsules []string `json:"capsules"`
	Risk     string   `json:"risk"`
	Files    int      `json:"files"`
	Lines    int      `json:"lines"`
	Missing  bool     `json:"missing_proof"`
}

// Line is one transcript line kept for the page, or — when Gap is set — a
// run of lines left in the Capsule.
type Line struct {
	N    int    `json:"n,omitempty"`
	Text string `json:"text,omitempty"`
	Gap  int    `json:"gap,omitempty"`
}

// Capsule is one verified Capsule the range points at.
type Capsule struct {
	Address         string             `json:"address"`
	Intent          string             `json:"intent"`
	Checkpoint      string             `json:"checkpoint"`
	Lane            capsule.LaneConfig `json:"lane"`
	Commits         []string           `json:"commits"`
	TranscriptLines int                `json:"transcript_lines"`
	Transcript      []Line             `json:"transcript"`
}

// Report is a Trail: the review view of base..head.
type Report struct {
	Schema   string     `json:"schema"`
	Repo     string     `json:"repo"`
	Base     string     `json:"base"`
	Head     string     `json:"head"`
	Intents  []string   `json:"intents"`
	Risk     string     `json:"risk"`
	Stats    Stats      `json:"stats"`
	Check    Check      `json:"check"`
	OpenRisk []RiskItem `json:"open_risk"`
	Unmet    []Unmet    `json:"unmet_intent"`
	Missing  []Missing  `json:"missing_proof"`
	Orphans  []Orphan   `json:"orphan_proof"`
	Verdicts []Verdict  `json:"verdicts"`
	Media    []Media    `json:"media"`
	Commits  []Commit   `json:"commits"`
	Capsules []Capsule  `json:"capsules"`

	// media holds the bytes of every Media file, keyed by its bundle path.
	// They come from verified Capsules and from nowhere else.
	media map[string][]byte
}

// Counts returns how many verdicts currently pass, fail, and are stale, and
// how many were superseded by a newer Capsule in the range.
func (r *Report) Counts() (pass, fail, stale, superseded int) {
	for _, v := range r.Verdicts {
		switch {
		case v.SupersededBy != "":
			superseded++
		case v.State == StateFail:
			fail++
		case v.State == StateStale:
			stale++
		default:
			pass++
		}
	}
	return
}

// tline is one transcript line with the event it was decoded from.
type tline struct {
	n    int
	text string
	ev   lane.Event
}

// loaded is a verified Capsule during a build.
type loaded struct {
	idx      int // index in Report.Capsules
	addr     string
	local    *capsule.Local
	verdicts []capsule.Verdict
	lines    []tline
	keep     map[int]bool // lines that are link targets
}

func (l *loaded) hasLine(n int) bool {
	i := sort.Search(len(l.lines), func(i int) bool { return l.lines[i].n >= n })
	return i < len(l.lines) && l.lines[i].n == n
}

// intentInfo is what an Intent ID resolved to.
type intentInfo struct {
	resolved bool
	ids      []string
	declared map[string]bool
	problem  string // "" when the Intent is the current one and readable
}

// transcriptRefRE is evidence that is exactly a transcript line;
// transcriptMentionRE finds the first such reference inside longer evidence
// ("transcript:4 and proof/shot.png").
var (
	transcriptRefRE     = regexp.MustCompile(`^transcript:([0-9]+)$`)
	transcriptMentionRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])transcript:([0-9]+)(?:[^0-9]|$)`)
)

// maxPageLines bounds a drill-down: a longer transcript keeps its last
// tailLines lines plus every line a row links to.
const (
	maxPageLines = 400
	tailLines    = 200
)

// Build walks base..head and assembles the Trail. It returns an error only
// when the range cannot be read in full (unknown revisions, no shared
// history, a shallow clone that cuts the range) or the store gave no answer
// (the error then wraps objstore.ErrUnavailable); everything wrong with the
// evidence itself is a row of the Report.
func Build(ctx context.Context, o Options) (*Report, error) {
	if o.Store == nil {
		return nil, fmt.Errorf("store not configured")
	}
	base, err := gitx.RevParse(ctx, o.RepoDir, o.Base+"^{commit}")
	if err != nil {
		return nil, err
	}
	head, err := gitx.RevParse(ctx, o.RepoDir, o.Head+"^{commit}")
	if err != nil {
		return nil, err
	}
	commits, err := gitx.RangeCommits(ctx, o.RepoDir, base, head)
	if err != nil {
		return nil, err
	}
	r := &Report{Schema: Schema, Repo: o.Repo, Base: base, Head: head, Intents: []string{}, OpenRisk: []RiskItem{}, Unmet: []Unmet{},
		Missing: []Missing{}, Orphans: []Orphan{}, Verdicts: []Verdict{}, Media: []Media{}, Commits: []Commit{}, Capsules: []Capsule{},
		media: map[string][]byte{}}

	// A walk that a shallow clone cut short would report less than happened.
	// Refuse it: nothing is proven about history that is not there.
	shallow, err := shallowBoundaries(ctx, o.RepoDir)
	if err != nil {
		return nil, err
	}
	for _, gc := range commits {
		if shallow[gc.SHA] {
			return nil, fmt.Errorf("history is shallow at %s; fetch the full range", abbrevID(gc.SHA))
		}
	}
	// The blast radius of the range is what head adds to the history it
	// shares with base — not whatever base gained on its own since.
	mergeBase := base
	if len(commits) > 0 {
		out, err := gitx.Run(ctx, o.RepoDir, "merge-base", base, head)
		if err != nil || strings.TrimSpace(string(out)) == "" {
			return nil, fmt.Errorf("%s and %s share no history", o.Base, o.Head)
		}
		mergeBase = strings.TrimSpace(string(out))
		if shallow[mergeBase] {
			return nil, fmt.Errorf("history is shallow at %s; fetch the full range", abbrevID(mergeBase))
		}
	}

	// The current Folio: its acceptance IDs are what "the Intent" contains.
	headFolio, folioErr := gitx.FolioIntent(ctx, o.RepoDir, head)
	var folioIDs []string
	if folioErr == nil {
		folioIDs, _ = folioDeclared(ctx, o.RepoDir, head)
	}

	caps := map[string]*loaded{}        // address → verified Capsule
	capErr := map[string]string{}       // address → why it is not proof
	intents := map[string]*intentInfo{} // Intent ID → resolution
	var intentOrder []string            // every Intent seen, first appearance
	intentCommit := map[string]int{}    // Intent ID → first commit citing it
	resolve := func(id string, ci int) (*intentInfo, error) {
		if info, ok := intents[id]; ok {
			return info, nil
		}
		info := &intentInfo{declared: map[string]bool{}}
		switch {
		case !capsule.ValidIntent(id):
			// Not an Intent at all; the commit is listed under missing proof.
		case strings.HasPrefix(id, "folio:"):
			if folioErr != nil {
				info.problem = fmt.Sprintf("intent %s cannot be resolved: no Folio at head; spec drift cannot be decided", abbrevID(id))
				break
			}
			info.resolved, info.ids = true, folioIDs
			if id != headFolio {
				info.problem = fmt.Sprintf("intent %s is not the Folio at head (%s)", abbrevID(id), abbrevID(headFolio))
			}
		default:
			m, err := capsule.GetTask(ctx, o.Store, id)
			var ie *capsule.IntegrityError
			switch {
			case err == nil:
				info.resolved, info.ids = true, m.AcceptanceIDs()
			case errors.Is(err, objstore.ErrUnavailable):
				return nil, fmt.Errorf("intent %s: %w", abbrevID(id), err)
			case errors.Is(err, capsule.ErrNotInStore):
				info.problem = fmt.Sprintf("intent %s has no manifest in the store; spec drift cannot be decided", abbrevID(id))
			case errors.As(err, &ie):
				info.problem = fmt.Sprintf("intent %s: manifest failed verification; spec drift cannot be decided", abbrevID(id))
			default:
				info.problem = fmt.Sprintf("intent %s: manifest unreadable; spec drift cannot be decided", abbrevID(id))
			}
		}
		for _, a := range info.ids {
			info.declared[a] = true
		}
		intents[id] = info
		intentOrder = append(intentOrder, id)
		intentCommit[id] = ci
		return info, nil
	}

	// Pass 1: commits, trailers, Capsules, per-commit blast radius.
	commitCaps := make([][]*loaded, len(commits)) // verified Capsules per commit
	commitStats := make([]Stats, len(commits))    // each commit's own blast radius
	commitPaths := make([][]string, len(commits)) // files each commit changes itself
	index := map[string]int{}                     // commit SHA → position in the range
	pathLast := map[string]int{}                  // path → last commit touching it
	touched := map[string]bool{}
	capFirst := map[string]int{} // address → first commit citing it
	var capOrder []*loaded
	for ci, gc := range commits {
		index[gc.SHA] = ci
		tr := gc.Chimera()
		c := Commit{SHA: gc.SHA, Subject: gc.Subject, Intents: uniqStrings(tr.Intents), Capsules: uniqStrings(tr.Capsules)}
		var reasons []string
		var lacking []string
		if len(c.Intents) == 0 {
			lacking = append(lacking, gitx.TrailerIntent)
		}
		if len(c.Capsules) == 0 {
			lacking = append(lacking, gitx.TrailerCapsule)
		}
		if len(lacking) > 0 {
			reasons = append(reasons, strings.Join(lacking, ", "))
		}
		for _, id := range c.Intents {
			if !capsule.ValidIntent(id) {
				reasons = append(reasons, gitx.TrailerIntent+" is not an Intent ID")
				continue
			}
			if !containsString(r.Intents, id) {
				r.Intents = append(r.Intents, id)
			}
			if _, err := resolve(id, ci); err != nil {
				return nil, err
			}
		}
		for _, raw := range c.Capsules {
			addr, err := capsule.ParseAddress(raw)
			if err != nil {
				reasons = append(reasons, gitx.TrailerCapsule+" is not a capsule address")
				continue
			}
			l, ok := caps[raw]
			if _, bad := capErr[raw]; !ok && !bad {
				local, err := capsule.Get(ctx, o.Store, addr)
				var ie *capsule.IntegrityError
				switch {
				case err == nil:
					l = newLoaded(raw, local)
					caps[raw] = l
					capFirst[raw] = ci
					capOrder = append(capOrder, l)
				case errors.Is(err, objstore.ErrUnavailable):
					return nil, fmt.Errorf("capsule %s: %w", abbrevID(raw), err)
				case errors.Is(err, capsule.ErrNotInStore):
					capErr[raw] = fmt.Sprintf("capsule %s not in store", abbrevID(raw))
				case errors.As(err, &ie):
					capErr[raw] = fmt.Sprintf("capsule %s failed verification (member %s)", abbrevID(raw), ie.Member)
				default:
					capErr[raw] = fmt.Sprintf("capsule %s unreadable", abbrevID(raw))
				}
			}
			if why, bad := capErr[raw]; bad {
				reasons = append(reasons, why)
				continue
			}
			if !containsString(c.Intents, l.local.Manifest.Intent) {
				reasons = append(reasons, fmt.Sprintf("capsule %s is bound to intent %s, not to this commit's", abbrevID(raw), abbrevID(l.local.Manifest.Intent)))
			}
			// A Capsule that judged nothing proves nothing (fail closed): one
			// with no verdicts.json, an unreadable one, or an empty list.
			if len(l.verdicts) == 0 {
				reasons = append(reasons, fmt.Sprintf("capsule %s carries no verdicts", abbrevID(raw)))
			}
			if _, err := resolve(l.local.Manifest.Intent, ci); err != nil {
				return nil, err
			}
			commitCaps[ci] = append(commitCaps[ci], l)
		}
		// Blast radius of what this commit itself changes: against its parent,
		// or — for a merge — the files that differ from every parent (what the
		// merge wrote by hand; what it merely brings is judged commit by commit
		// and through the range diff).
		stats, err := ownChanges(ctx, o.RepoDir, gc)
		if err != nil {
			return nil, err
		}
		cls, st := classify(stats, o)
		c.Risk, c.Files, c.Lines = cls, st.Files, st.Lines
		commitStats[ci] = st
		for _, f := range stats {
			commitPaths[ci] = append(commitPaths[ci], f.Path)
			pathLast[f.Path] = ci
			touched[f.Path] = true
		}
		if len(reasons) > 0 {
			c.Missing = true
			r.Missing = append(r.Missing, Missing{Commit: gc.SHA, Subject: gc.Subject, Reasons: reasons})
		}
		r.Commits = append(r.Commits, c)
	}

	// Blast radius of the whole range.
	// An empty range reviews nothing, whatever the two trees differ by.
	var rangeStats []gitx.FileStat
	if len(commits) > 0 {
		if rangeStats, err = gitx.DiffStat(ctx, o.RepoDir, mergeBase, head); err != nil {
			return nil, err
		}
	}
	var wide bool
	r.Risk, r.Stats = classify(rangeStats, o)
	wide = isWide(r.Stats)
	for _, f := range rangeStats {
		touched[f.Path] = true
		if _, ok := pathLast[f.Path]; !ok {
			pathLast[f.Path] = len(commits) - 1
		}
	}
	for _, c := range r.Commits {
		r.Risk = maxClass(r.Risk, c.Risk)
	}

	// sourceFor finds the evidence behind a path: a transcript line of the
	// last commit that touched it, else that commit's Capsule, else the commit.
	sourceFor := func(ci int, needle string) Source {
		if ci < 0 || ci >= len(commits) {
			return Source{}
		}
		for _, l := range commitCaps[ci] {
			if needle == "" {
				break
			}
			for _, tl := range l.lines {
				if strings.Contains(tl.text, needle) {
					l.keep[tl.n] = true
					return Source{Capsule: l.addr, Line: tl.n}
				}
			}
		}
		if len(commitCaps[ci]) > 0 {
			return Source{Capsule: commitCaps[ci][0].addr}
		}
		return Source{Commit: commits[ci].SHA}
	}

	// Open risk, part 1: paths and width.
	var paths []string
	for p := range touched {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var pathRows []RiskItem
	for _, p := range paths {
		cls, reason := pathClass(p, o)
		if cls < "R2" {
			continue
		}
		pathRows = append(pathRows, RiskItem{Kind: "path", Class: cls, Path: p, Reason: reason, Source: sourceFor(pathLast[p], p)})
		r.Risk = maxClass(r.Risk, cls)
	}
	sort.SliceStable(pathRows, func(i, j int) bool { return pathRows[i].Class > pathRows[j].Class })
	r.OpenRisk = append(r.OpenRisk, pathRows...)
	if wide {
		r.OpenRisk = append(r.OpenRisk, RiskItem{Kind: "wide", Class: "R2",
			Reason: fmt.Sprintf("wide change: %d files, %d packages, %d lines", r.Stats.Files, r.Stats.Packages, r.Stats.Lines),
			Source: sourceFor(len(commits)-1, "")})
	} else {
		// A commit can be wide where the range is not (it adds what a later
		// commit removes). The class says R2; the row says why.
		for ci, st := range commitStats {
			if isWide(st) {
				r.OpenRisk = append(r.OpenRisk, RiskItem{Kind: "wide", Class: "R2",
					Reason: fmt.Sprintf("wide commit %s: %d files, %d packages, %d lines", abbrevID(commits[ci].SHA), st.Files, st.Packages, st.Lines),
					Source: sourceFor(ci, "")})
			}
		}
	}

	// Open risk, part 2: a Capsule is proof of the change its diff records.
	// Files a commit changes that no Capsule it cites has in its diff were
	// changed without evidence — by hand, or by a squash that swallowed an
	// unproven commit. (A commit citing no verified Capsule is missing proof
	// already; a merge is judged through the commits it brings.)
	for ci, gc := range commits {
		if len(commitCaps[ci]) == 0 || len(gc.Parents) > 1 {
			continue
		}
		covered := map[string]bool{}
		for _, l := range commitCaps[ci] {
			for _, t := range capsule.TouchedPaths(l.local.Members[capsule.MemberDiff]) {
				covered[t.Path] = true
			}
		}
		var uncovered []string
		for _, p := range commitPaths[ci] {
			if !covered[p] {
				uncovered = append(uncovered, p)
			}
		}
		if len(uncovered) == 0 {
			continue
		}
		names := uncovered
		more := ""
		if len(names) > maxUncoveredNames {
			names, more = names[:maxUncoveredNames], ", …"
		}
		noun := "paths"
		if len(uncovered) == 1 {
			noun = "path"
		}
		r.OpenRisk = append(r.OpenRisk, RiskItem{Kind: "uncovered",
			Reason: fmt.Sprintf("%d %s not in any cited capsule's diff: %s%s", len(uncovered), noun, strings.Join(names, ", "), more),
			Source: Source{Capsule: commitCaps[ci][0].addr, Commit: gc.SHA}})
	}

	// Pass 2: verdicts, oldest Capsule first. A verdict is superseded only by
	// a newer verdict of the same Intent, acceptance ID, and criterion whose
	// commit descends from its own: on parallel branches both stand, and
	// another Intent's Capsule decides nothing here.
	descends := descent(commits, index)
	type vkey struct{ intent, id, criterion string }
	current := map[vkey][]int{} // verdicts that still decide, by key
	var meta []vmeta            // parallel to r.Verdicts until they are sorted
	var engineRows, orphanRows []RiskItem
	for _, l := range capOrder {
		ci := capFirst[l.addr]
		info := intents[l.local.Manifest.Intent]
		fam := family(l.local.Manifest.Intent)
		for _, cv := range l.verdicts {
			v := Verdict{ID: cv.ID, Criterion: cv.Criterion, Pass: cv.Pass, State: StatePass, Evidence: cv.Evidence,
				Capsule: l.addr, Commit: commits[ci].SHA, Source: verdictSource(l, cv)}
			orphan := capsule.IsAcceptanceID(cv.ID) && info != nil && info.resolved && !info.declared[cv.ID]
			switch {
			case !cv.Pass:
				v.State = StateFail
			case orphan:
				v.State = StateStale
			}
			// Orphan proof is proof of nothing: it neither supersedes nor is counted.
			if capsule.IsAcceptanceID(cv.ID) && !orphan {
				k := vkey{fam, cv.ID, cv.Criterion}
				var still []int
				for _, prev := range current[k] {
					if r.Verdicts[prev].Capsule != l.addr && descends(ci, meta[prev].commit) {
						r.Verdicts[prev].SupersededBy = l.addr
						continue
					}
					still = append(still, prev)
				}
				current[k] = append(still, len(r.Verdicts))
			}
			if orphan {
				r.Orphans = append(r.Orphans, Orphan{ID: cv.ID, Criterion: cv.Criterion, Pass: cv.Pass, Intent: l.local.Manifest.Intent, Capsule: l.addr, Source: v.Source})
				orphanRows = append(orphanRows, RiskItem{Kind: "orphan",
					Reason: fmt.Sprintf("orphan proof: %s is not in intent %s", cv.ID, abbrevID(l.local.Manifest.Intent)), Source: v.Source})
			}
			if !cv.Pass && (cv.ID == "ring0" || cv.ID == "harness") {
				item := RiskItem{Kind: "verdict", Class: r.Commits[ci].Risk, Reason: joinReason(cv.Criterion, cv.Evidence), Source: v.Source}
				if cv.ID == "ring0" {
					// A lane that changed a Ring-0 path is R3 whatever the diff says.
					item.Class = "R3"
					r.Risk = "R3"
				}
				if item.Class < "R2" {
					item.Class = ""
				}
				engineRows = append(engineRows, item)
			}
			r.Verdicts = append(r.Verdicts, v)
			meta = append(meta, vmeta{family: fam, commit: ci, orphan: orphan})
		}
	}
	r.OpenRisk = append(append(r.OpenRisk, engineRows...), orphanRows...)

	// Open risk, part 3: Intents that cannot anchor spec drift, and
	// acceptance IDs the range itself deleted from the Folio — an ID that is
	// gone can no longer be unmet, so its removal must be seen.
	for _, id := range intentOrder {
		if info := intents[id]; info.problem != "" {
			r.OpenRisk = append(r.OpenRisk, RiskItem{Kind: "intent", Reason: info.problem, Source: sourceFor(intentCommit[id], "")})
		}
	}
	if len(commits) > 0 {
		was, byFile := folioDeclared(ctx, o.RepoDir, mergeBase)
		now, _ := folioDeclared(ctx, o.RepoDir, head)
		for _, id := range was {
			if containsString(now, id) {
				continue
			}
			ci, ok := pathLast[byFile[id]]
			if !ok {
				ci = len(commits) - 1
			}
			r.OpenRisk = append(r.OpenRisk, RiskItem{Kind: "intent", Path: byFile[id],
				Reason: fmt.Sprintf("acceptance ID %s was removed from the Folio in this range", id), Source: sourceFor(ci, "")})
		}
	}

	// Unmet intent: every acceptance ID of every resolved Intent, in Intent
	// order, without a full set of passing current verdicts from Capsules
	// bound to that Intent.
	seenID := map[[2]string]bool{}
	for _, id := range intentOrder {
		info := intents[id]
		if !info.resolved {
			continue
		}
		fam := family(id)
		for _, a := range info.ids {
			if seenID[[2]string{fam, a}] {
				continue
			}
			seenID[[2]string{fam, a}] = true
			judged := false
			for i, v := range r.Verdicts {
				if v.ID != a || v.SupersededBy != "" || meta[i].family != fam || meta[i].orphan {
					continue
				}
				judged = true
				if !v.Pass {
					r.Unmet = append(r.Unmet, Unmet{ID: a, Criterion: v.Criterion, State: StateFail, Intent: id, Source: v.Source})
				}
			}
			if !judged {
				r.Unmet = append(r.Unmet, Unmet{ID: a, Criterion: "no verdict in this range", State: StatePending, Intent: id})
			}
		}
	}

	// Failures first in the verdict table: FAIL, then STALE, then the rest;
	// superseded verdicts last. Order is otherwise commit order.
	rank := func(v Verdict) int {
		switch {
		case v.SupersededBy != "":
			return 3
		case v.State == StateFail:
			return 0
		case v.State == StateStale:
			return 1
		}
		return 2
	}
	sort.SliceStable(r.Verdicts, func(i, j int) bool { return rank(r.Verdicts[i]) < rank(r.Verdicts[j]) })

	// Media and the drill-downs.
	for _, l := range capOrder {
		r.addMedia(l, intents[l.local.Manifest.Intent])
	}
	for _, l := range capOrder {
		m := l.local.Manifest
		c := Capsule{Address: l.addr, Intent: m.Intent, Checkpoint: m.Checkpoint, Lane: m.Lane, Commits: []string{}, TranscriptLines: len(l.lines), Transcript: keptLines(l)}
		for ci := range commits {
			for _, cl := range commitCaps[ci] {
				if cl == l {
					c.Commits = append(c.Commits, commits[ci].SHA)
				}
			}
		}
		r.Capsules = append(r.Capsules, c)
	}
	r.sanitize()
	r.Check = r.check()
	return r, nil
}

// maxUncoveredNames caps the paths one uncovered row spells out.
const maxUncoveredNames = 5

// vmeta is what the build remembers about a verdict besides the row itself.
type vmeta struct {
	family string // Intent family of the verdict's Capsule
	commit int    // first commit citing that Capsule
	orphan bool
}

// family groups Intent IDs that are one Intent for spec drift: every folio
// Intent is "the Folio" (whose acceptance IDs are those at head; a commit
// made against an older Folio is flagged separately), and each task Intent
// is its own. A verdict only ever answers for its own family.
func family(intent string) string {
	if strings.HasPrefix(intent, "folio:") {
		return "folio"
	}
	return intent
}

// folioDeclared returns the acceptance IDs the Folio declares at rev, in
// order, and the Folio file that declares each.
func folioDeclared(ctx context.Context, dir, rev string) (ids []string, byFile map[string]string) {
	byFile = map[string]string{}
	for _, name := range []string{"PRODUCT.md", "DESIGN.md"} {
		out, err := gitx.Run(ctx, dir, "show", rev+":"+name)
		if err != nil {
			continue
		}
		for _, id := range capsule.AcceptanceIDs(string(out)) {
			if _, ok := byFile[id]; !ok {
				byFile[id] = name
				ids = append(ids, id)
			}
		}
	}
	return ids, byFile
}

// shallowBoundaries returns the commits at which a shallow clone's history
// is cut: their parents exist but are not here. It is empty for a full clone.
func shallowBoundaries(ctx context.Context, dir string) (map[string]bool, error) {
	out, err := gitx.Run(ctx, dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(out)) != "true" {
		return nil, nil
	}
	out, err = gitx.Run(ctx, dir, "rev-parse", "--git-path", "shallow")
	if err != nil {
		return nil, err
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("history is shallow and its boundary cannot be read; fetch the full range")
	}
	set := map[string]bool{}
	for _, line := range strings.Fields(string(data)) {
		set[line] = true
	}
	return set, nil
}

// ownChanges lists the files a commit changes itself: against its parent
// (the empty tree for a root), or, for a merge, the files that differ from
// every parent.
func ownChanges(ctx context.Context, dir string, gc gitx.Commit) ([]gitx.FileStat, error) {
	parent := ""
	if len(gc.Parents) > 0 {
		parent = gc.Parents[0]
	}
	stats, err := gitx.DiffStat(ctx, dir, parent, gc.SHA)
	if err != nil || len(gc.Parents) < 2 {
		return stats, err
	}
	for _, other := range gc.Parents[1:] {
		theirs, err := gitx.DiffStat(ctx, dir, other, gc.SHA)
		if err != nil {
			return nil, err
		}
		differs := map[string]bool{}
		for _, f := range theirs {
			differs[f.Path] = true
		}
		var both []gitx.FileStat
		for _, f := range stats {
			if differs[f.Path] {
				both = append(both, f)
			}
		}
		stats = both
	}
	return stats, nil
}

// descent returns a predicate: does commit a (by position in the range)
// strictly descend from commit b? Ancestry is computed inside the range, from
// the commits' own parents, and memoized per descendant.
func descent(commits []gitx.Commit, index map[string]int) func(a, b int) bool {
	reach := map[int]map[int]bool{}
	return func(a, b int) bool {
		if a == b {
			return false
		}
		seen, ok := reach[a]
		if !ok {
			seen = map[int]bool{}
			stack := []int{a}
			for len(stack) > 0 {
				n := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				for _, p := range commits[n].Parents {
					if pi, in := index[p]; in && !seen[pi] {
						seen[pi] = true
						stack = append(stack, pi)
					}
				}
			}
			reach[a] = seen
		}
		return seen[b]
	}
}

// sanitize strips control and escape bytes from every string of the Report
// that came from Git or a Capsule: nothing a commit, a harness, or a
// verifier wrote may steer a terminal or hide inside a page (DESIGN.md §1.4).
// Hashes and addresses that passed validation are unchanged by it.
func (r *Report) sanitize() {
	p := printable
	all := func(vs []string) {
		for i := range vs {
			vs[i] = p(vs[i])
		}
	}
	src := func(s *Source) { s.Capsule, s.Commit = p(s.Capsule), p(s.Commit) }
	r.Repo = p(r.Repo)
	all(r.Intents)
	for i := range r.OpenRisk {
		it := &r.OpenRisk[i]
		it.Path, it.Reason = p(it.Path), p(it.Reason)
		src(&it.Source)
	}
	for i := range r.Unmet {
		u := &r.Unmet[i]
		u.ID, u.Criterion, u.Intent = p(u.ID), p(u.Criterion), p(u.Intent)
		src(&u.Source)
	}
	for i := range r.Missing {
		m := &r.Missing[i]
		m.Subject = p(m.Subject)
		all(m.Reasons)
	}
	for i := range r.Orphans {
		o := &r.Orphans[i]
		o.ID, o.Criterion, o.Intent = p(o.ID), p(o.Criterion), p(o.Intent)
		src(&o.Source)
	}
	for i := range r.Verdicts {
		v := &r.Verdicts[i]
		v.ID, v.Criterion, v.Evidence = p(v.ID), p(v.Criterion), p(v.Evidence)
		src(&v.Source)
	}
	for i := range r.Media {
		m := &r.Media[i]
		m.Name, m.Member, m.ID = p(m.Name), p(m.Member), p(m.ID)
	}
	for i := range r.Commits {
		c := &r.Commits[i]
		c.Subject = p(c.Subject)
		all(c.Intents)
		all(c.Capsules)
	}
	for i := range r.Capsules {
		c := &r.Capsules[i]
		c.Intent, c.Checkpoint = p(c.Intent), p(c.Checkpoint)
		l := &c.Lane
		l.Model, l.Harness, l.Skill, l.Prompt, l.Effort, l.ContextPolicy, l.Runner =
			p(l.Model), p(l.Harness), p(l.Skill), p(l.Prompt), p(l.Effort), p(l.ContextPolicy), p(l.Runner)
		for j := range c.Transcript {
			c.Transcript[j].Text = p(c.Transcript[j].Text)
		}
	}
}

func newLoaded(addr string, local *capsule.Local) *loaded {
	l := &loaded{addr: addr, local: local, keep: map[int]bool{}}
	// Capsule.Get verified the bytes; a verdicts.json that does not parse is
	// a Capsule without verdicts, which Build lists as missing proof.
	l.verdicts, _ = local.Verdicts()
	raw, ok := local.Members[capsule.MemberTranscript]
	if !ok {
		return l
	}
	text, err := capsule.Unzstd(raw)
	if err != nil {
		return l
	}
	prev := 0
	for _, line := range strings.Split(strings.TrimRight(string(text), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		tl := tline{text: line}
		if err := json.Unmarshal([]byte(line), &tl.ev); err == nil && tl.ev.Event != "" {
			tl.text = tl.ev.Text()
		}
		// Line numbers are the transcript's own sequence numbers when it has
		// them and they ascend; otherwise the position in the file.
		tl.n = tl.ev.Seq
		if tl.n <= prev {
			tl.n = prev + 1
		}
		prev = tl.n
		tl.text = printable(tl.text)
		l.lines = append(l.lines, tl)
	}
	return l
}

// verdictSource links a verdict to the transcript line that produced it:
// the line its evidence names, else the verdict event recorded for it, else
// the Capsule.
func verdictSource(l *loaded, v capsule.Verdict) Source {
	if m := transcriptMentionRE.FindStringSubmatch(v.Evidence); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil && l.hasLine(n) {
			l.keep[n] = true
			return Source{Capsule: l.addr, Line: n}
		}
	}
	for _, tl := range l.lines {
		if tl.ev.Event == "verdict" && tl.ev.ID == v.ID && tl.ev.Criterion == v.Criterion {
			l.keep[tl.n] = true
			return Source{Capsule: l.addr, Line: tl.n}
		}
	}
	return Source{Capsule: l.addr}
}

// keptLines returns the transcript lines the page shows: all of a short
// transcript; of a long one, the tail plus every link target, with a gap
// row wherever lines were left in the Capsule.
func keptLines(l *loaded) []Line {
	out := []Line{}
	gap := 0
	for i, tl := range l.lines {
		if len(l.lines) > maxPageLines && i < len(l.lines)-tailLines && !l.keep[tl.n] {
			gap++
			continue
		}
		if gap > 0 {
			out = append(out, Line{Gap: gap})
			gap = 0
		}
		out = append(out, Line{N: tl.n, Text: tl.text})
	}
	return out
}

func (r *Report) check() Check {
	pass, fail, stale, superseded := r.Counts()
	state := StatePass
	switch {
	case len(r.Missing) > 0 || fail > 0:
		state = StateFail
	case len(r.OpenRisk) > 0 || len(r.Unmet) > 0:
		state = StatePending
	}
	counts := fmt.Sprintf("%d pass, %d fail", pass, fail)
	if stale > 0 {
		counts += fmt.Sprintf(", %d stale", stale)
	}
	if superseded > 0 {
		counts += fmt.Sprintf(", %d superseded", superseded)
	}
	title := fmt.Sprintf("%s · risk %s · %d open risk · %d unmet · %d missing · %d verdicts (%s)",
		state, r.Risk, len(r.OpenRisk), len(r.Unmet), len(r.Missing), len(r.Verdicts), counts)
	summary := fmt.Sprintf("Risk class %s\nOpen risk %d\nUnmet intent %d\nMissing proof %d\nVerdicts %d: %s",
		r.Risk, len(r.OpenRisk), len(r.Unmet), len(r.Missing), len(r.Verdicts), counts)
	return Check{State: state, Title: title, Summary: summary}
}

func joinReason(criterion, evidence string) string {
	if evidence == "" || transcriptRefRE.MatchString(evidence) {
		return criterion
	}
	return criterion + ": " + evidence
}

// abbrevID shortens "kind:<hex>" (or a bare hash) to 12 hex characters.
func abbrevID(id string) string {
	if k, v, ok := strings.Cut(id, ":"); ok {
		if len(v) > 12 {
			v = v[:12]
		}
		return k + ":" + v
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func hex12(addr string) string {
	h := strings.TrimPrefix(addr, "sha256:")
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func uniqStrings(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s != "" && !containsString(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func containsString(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}

// printable drops control and escape bytes: nothing a harness or verifier
// wrote may steer a terminal or hide inside a page (DESIGN.md §1.4).
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}
