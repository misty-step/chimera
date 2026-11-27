// Package trailtest builds deterministic Trail fixtures for tests: a real
// Git history with pinned identity and dates (so commit SHAs never change)
// and a directory object store holding real, pushed Capsules with pinned
// checkpoints and times (so Capsule addresses never change). All data is
// fictional: acme, example.com.
package trailtest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"chimera/folio"
	"chimera/pkg/capsule"
	"chimera/pkg/gitx"
	"chimera/pkg/lane"
	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// Repo is the name the fixtures record in Capsules.
const Repo = "acme/widget"

// epoch is the first pinned commit time; each commit is one minute later.
var epoch = time.Date(2026, 11, 26, 19, 4, 0, 0, time.UTC)

// Fixture is a Git repository plus the store its Capsules live in.
type Fixture struct {
	t        testing.TB
	Dir      string // Git work tree
	StoreDir string
	Store    *objstore.Dir
	Base     string // the commit every range in the fixture starts after
	n        int    // commits made so far
	caps     int    // capsules packed so far
}

// New creates a repository with one base commit holding files.
func New(t testing.TB, files map[string]string) *Fixture {
	t.Helper()
	root := t.TempDir()
	f := &Fixture{t: t, Dir: filepath.Join(root, "repo"), StoreDir: filepath.Join(root, "store")}
	f.Store = objstore.NewDir(f.StoreDir)
	if err := os.MkdirAll(f.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f.Git("init", "-q", "-b", "main")
	f.Base = f.Commit("fixture: base", files)
	return f
}

// Git runs git in the fixture with pinned identity, dates, and config.
func (f *Fixture) Git(args ...string) string {
	f.t.Helper()
	return f.gitInput(nil, args...)
}

func (f *Fixture) gitInput(stdin []byte, args ...string) string {
	f.t.Helper()
	when := fmt.Sprintf("@%d +0000", epoch.Add(time.Duration(f.n)*time.Minute).Unix())
	cmd := exec.Command("git", args...)
	cmd.Dir = f.Dir
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Example", "GIT_AUTHOR_EMAIL=dev@example.com", "GIT_COMMITTER_NAME=Example", "GIT_COMMITTER_EMAIL=dev@example.com",
		"GIT_AUTHOR_DATE="+when, "GIT_COMMITTER_DATE="+when)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Write writes files into the work tree without committing.
func (f *Fixture) Write(files map[string]string) {
	f.t.Helper()
	for name, body := range files {
		p := filepath.Join(f.Dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

// Commit writes files and commits them with the given trailers, returning
// the commit SHA.
func (f *Fixture) Commit(subject string, files map[string]string, trailers ...gitx.Trailer) string {
	f.t.Helper()
	f.Write(files)
	f.Git("add", "-A")
	msg, err := gitx.MessageWithTrailers(context.Background(), f.Dir, subject+"\n", trailers)
	if err != nil {
		f.t.Fatal(err)
	}
	f.gitInput([]byte(msg), "commit", "-q", "--allow-empty", "-F", "-")
	f.n++
	return f.Git("rev-parse", "HEAD")
}

// Head returns the current commit.
func (f *Fixture) Head() string { return f.Git("rev-parse", "HEAD") }

// Trailers returns the Intent and Capsule trailers binding a commit.
func Trailers(intent, addr string) []gitx.Trailer {
	return []gitx.Trailer{{Key: gitx.TrailerIntent, Value: intent}, {Key: gitx.TrailerCapsule, Value: addr}}
}

// CapsuleSpec describes one Capsule to pack and push.
type CapsuleSpec struct {
	Intent     string
	BaseSHA    string
	Lane       capsule.LaneConfig // zero: a local example lane
	Verdicts   []capsule.Verdict
	Transcript []lane.Event      // Seq and Checkpoint are filled in
	Proof      map[string][]byte // name under proof/ → bytes
	// Paths are the files the Capsule's diff.patch changes; a commit citing
	// the Capsule is covered for exactly these.
	Paths  []string
	NoPush bool // pack only: the Capsule never reaches the store
	// NoVerdicts leaves verdicts.json out of the Capsule altogether.
	NoVerdicts bool
	// RawVerdicts, when set, is written as verdicts.json verbatim.
	RawVerdicts []byte
}

// Diff renders a git-format diff that touches paths, one line each.
func Diff(paths ...string) []byte {
	var b bytes.Buffer
	for _, p := range paths {
		fmt.Fprintf(&b, "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1 +1 @@\n-before\n+after\n", p, p, p, p)
	}
	return b.Bytes()
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Capsule packs and pushes a Capsule with a pinned checkpoint and pinned
// times, returning its address.
func (f *Fixture) Capsule(spec CapsuleSpec) string {
	f.t.Helper()
	f.caps++
	checkpoint := "ckpt_01ARZ3NDEKTSV4RRFFQ69G5F" + string(crockford[(f.caps/32)%32]) + string(crockford[f.caps%32])
	dir := f.t.TempDir()
	var transcript bytes.Buffer
	enc := json.NewEncoder(&transcript)
	enc.SetEscapeHTML(false)
	events := spec.Transcript
	if len(events) == 0 {
		events = []lane.Event{{Event: "end"}} // a transcript is never empty
	}
	for i, e := range events {
		e.Seq, e.Checkpoint = i+1, checkpoint
		enc.Encode(e)
	}
	verdicts := spec.Verdicts
	if verdicts == nil {
		verdicts = []capsule.Verdict{}
	}
	vjson, _ := json.MarshalIndent(verdicts, "", "  ")
	members := map[string][]byte{
		capsule.MemberTranscript: capsule.Zstd(transcript.Bytes()),
		capsule.MemberVerdicts:   append(vjson, '\n'),
		capsule.MemberDiff:       Diff(spec.Paths...),
	}
	if spec.RawVerdicts != nil {
		members[capsule.MemberVerdicts] = spec.RawVerdicts
	}
	if spec.NoVerdicts {
		delete(members, capsule.MemberVerdicts)
	}
	for name, data := range spec.Proof {
		members["proof/"+name] = data
	}
	for name, data := range members {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	lc := spec.Lane
	if lc == (capsule.LaneConfig{}) {
		lc = capsule.LaneConfig{Model: "example-model", Harness: "example-agent", Effort: "high", ContextPolicy: "push", Runner: "local"}
	}
	started := epoch.Add(time.Duration(f.caps) * time.Hour)
	addr, err := capsule.Pack(dir, capsule.Meta{Intent: spec.Intent, Checkpoint: checkpoint, Repo: Repo, BaseSHA: spec.BaseSHA, Lane: lc,
		StartedAt: started, EndedAt: started.Add(90 * time.Second), Tags: []string{"fixture:trail"}})
	if err != nil {
		f.t.Fatal(err)
	}
	if !spec.NoPush {
		if _, err := capsule.Push(context.Background(), f.Store, dir, secretscan.New(nil)); err != nil {
			f.t.Fatal(err)
		}
	}
	return string(addr)
}

// FolioIntent returns the folio Intent of the fixture at rev.
func (f *Fixture) FolioIntent(rev string) string {
	f.t.Helper()
	id, err := gitx.FolioIntent(context.Background(), f.Dir, rev)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// Corrupt flips the first byte of every stored object whose key ends in
// suffix and reports how many it changed.
func (f *Fixture) Corrupt(suffix string) int {
	f.t.Helper()
	n := 0
	filepath.WalkDir(f.StoreDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(filepath.ToSlash(p), suffix) {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil || len(data) == 0 {
			return nil
		}
		data[0] ^= 0xff
		os.Chmod(p, 0o644)
		if werr := os.WriteFile(p, data, 0o644); werr != nil {
			f.t.Fatal(werr)
		}
		n++
		return nil
	})
	return n
}

// Event builders for transcripts.

// Output is one line a command printed.
func Output(line string) lane.Event { return lane.Event{Event: "output", Step: "verifier", Line: line} }

// Exec is a command the lane ran.
func Exec(argv ...string) lane.Event { return lane.Event{Event: "exec", Step: "verifier", Argv: argv} }

// VerdictEvent is the transcript record of a verdict.
func VerdictEvent(id, criterion string, pass bool) lane.Event {
	return lane.Event{Event: "verdict", ID: id, Criterion: criterion, Pass: &pass}
}

// PNG is a 320×180 PNG of the paper token colour.
func PNG() []byte {
	data, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAUAAAAC0CAIAAABqhmJGAAABkklEQVR42u3TwQkAAAgDse4/rqBv5ygEMsHB5XaAUpEADAwYGDAwGBgwMGBgwMBgYMDAgIHBwICBAQMDBgYDAwYGDAwYGAwMGBgwMBgYMDBgYMDAYGDAwICBAQODgQEDAwYGAwMGBgwMGBgMDBgYMDAYWAUwMGBgwMBgYMDAgIEBA4OBAQMDBgYDAwYGDAwYGAwMGBgwMGBgMDBgYMDAYGDAwICBAQODgQEDAwYGDAwGBgwMGBgMDBgYMDBgYDAwYGDAwGBgwMCAgQEDg4EBAwMGBgwMBgYMDBgYDAwYGDAwYGAwMGBgwMCAgcHAgIEBA4OBAQMDBgYMDAYGDAwYGDAwGBgwMGBgMDBgYMDAgIHBwICBAQODgQEDAwYGDAwGBgwMGBgwMBgYMDBgYDAwYGDAwICBwcCAgQEDAwYGAwMGBgwMBgYMDBgYMDAYGDAwYGAwsApgYMDAgIHBwICBAQMDBgYDAwYGDAwGBgwMGBgwMBgYMDBgYMDAYGDAwICBwcCAgQEDAwYGAwMGBgwMGBi6PVshYr303mk6AAAAAElFTkSuQmCC")
	return data
}

// MP4 is the smallest ISO BMFF file that declares a w×h video track. It
// carries no samples; it exists so the page's <video> markup and the size
// parser have something real to read.
func MP4(w, h int) []byte {
	box := func(kind string, body []byte) []byte {
		out := make([]byte, 8, 8+len(body))
		binary.BigEndian.PutUint32(out, uint32(8+len(body)))
		copy(out[4:], kind)
		return append(out, body...)
	}
	tkhd := make([]byte, 84)
	binary.BigEndian.PutUint32(tkhd[76:], uint32(w)<<16)
	binary.BigEndian.PutUint32(tkhd[80:], uint32(h)<<16)
	return append(box("ftyp", []byte("isom\x00\x00\x02\x00isomiso2mp41")), box("moov", box("trak", box("tkhd", tkhd)))...)
}

// ReferenceSVG is the Folio's reference diagram, byte for byte.
func ReferenceSVG(t testing.TB) []byte {
	t.Helper()
	data, err := fs.ReadFile(folio.Assets, folio.TrailReference+"/media/capsule-write.svg")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Reference is the history the golden page is rendered from: a commit with
// passing proof and media, a commit with a failing verdict and an orphan
// verdict that touches a risk-glob path, a commit without trailers, and a
// commit that touches a Ring-0 path.
type Reference struct {
	*Fixture
	Intent                                  string
	Lint, Push, Docs, Verify                string // commits, oldest first
	LintCapsule, PushCapsule, VerifyCapsule string
}

// Ring0 is the reference history's Ring-0 policy: verify/**.
func Ring0(p string) bool { return strings.HasPrefix(p, "verify/") }

// RiskGlob is the reference history's risk globs: pkg/objstore/** is R2.
func RiskGlob(p string) (class, glob string) {
	if strings.HasPrefix(p, "pkg/objstore/") {
		return "R2", "pkg/objstore/**"
	}
	return "", ""
}

// BaseFiles is the tree of the reference history's base commit. Its Folio
// declares three acceptance IDs: [W-1], [W-2], [W-3].
func BaseFiles() map[string]string {
	return map[string]string{
		"PRODUCT.md": "# Widget — PRODUCT\n\nVerdicts cite IDs such as `[W-1]`.\n\n**[W-1] Lint.** Lint output never contains the matched term.\n\n" +
			"**[W-2] Push.** Push is write-once and reads back what it wrote.\n\n**[W-3] Query.** Query ranks by tier.\n",
		"DESIGN.md":             "# Widget — DESIGN\n\nOutput is plain text.\n",
		"README.md":             "# widget\n\nPush uplods a capsule.\n",
		"pkg/objstore/sigv4.go": "package objstore\n\nfunc sign() string { return \"v4\" }\n",
		"verify/check.sh":       "#!/bin/sh\ngo test ./...\n",
		"folio/assets/.gitkeep": "",
		"cmd/widget/main.go":    "package main\n\nfunc main() {}\n",
	}
}

// NewReference builds the reference history.
func NewReference(t testing.TB) *Reference {
	t.Helper()
	f := New(t, BaseFiles())
	r := &Reference{Fixture: f, Intent: f.FolioIntent("HEAD")}

	r.LintCapsule = f.Capsule(CapsuleSpec{Intent: r.Intent, BaseSHA: f.Base,
		Transcript: []lane.Event{
			{Event: "start", BaseSHA: f.Base, Tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			Exec("go", "test", "./pkg/lint"),
			Output("ok   pkg/lint  0.41s"),
			VerdictEvent("[W-1]", "Lint output never contains the matched term", true),
			VerdictEvent("[W-1]", "Unreadable denylist fails closed", true),
			{Event: "end"},
		},
		Verdicts: []capsule.Verdict{
			{ID: "[W-1]", Criterion: "Lint output never contains the matched term", Pass: true, Evidence: "transcript:3"},
			{ID: "[W-1]", Criterion: "Unreadable denylist fails closed", Pass: true, Evidence: "see proof/w-1-lint.png"},
		},
		Proof: map[string][]byte{"w-1-lint.png": PNG(), "capsule-write.svg": ReferenceSVG(t)},
		Paths: []string{"pkg/lint/lint.go"},
	})
	r.Lint = f.Commit("lint: add tenant-leak scanner", map[string]string{"pkg/lint/lint.go": "package lint\n\nfunc Scan() int { return 0 }\n"},
		Trailers(r.Intent, r.LintCapsule)...)

	r.PushCapsule = f.Capsule(CapsuleSpec{Intent: r.Intent, BaseSHA: r.Lint,
		Transcript: []lane.Event{
			{Event: "start", BaseSHA: r.Lint, Tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			Output("edit pkg/objstore/sigv4.go (+2 −1)"),
			Exec("go", "test", "./pkg/objstore"),
			Output("--- PASS: TestPutIsWriteOnce (0.12s)"),
			Output("--- FAIL: TestCorruptMemberFailsGet (0.03s): get returned nil error"),
			VerdictEvent("[X-9]", "Legacy export still works", true),
			{Event: "end"},
		},
		Verdicts: []capsule.Verdict{
			{ID: "[W-2]", Criterion: "Two concurrent pushes write once", Pass: true, Evidence: "transcript:4"},
			{ID: "[W-2]", Criterion: "Corrupted member makes get fail", Pass: false, Evidence: "transcript:5"},
			{ID: "[X-9]", Criterion: "Legacy export still works", Pass: true},
		},
		Proof: map[string][]byte{"w-2-push.mp4": MP4(640, 360)},
		Paths: []string{"pkg/objstore/sigv4.go"},
	})
	r.Push = f.Commit("capsule: write-once push with readback", map[string]string{
		"pkg/objstore/sigv4.go": "package objstore\n\n// sign returns the signature version.\nfunc sign() string { return \"v4a\" }\n"},
		Trailers(r.Intent, r.PushCapsule)...)

	r.Docs = f.Commit("docs: fix typo in push help", map[string]string{"README.md": "# widget\n\nPush uploads a capsule.\n"})

	r.VerifyCapsule = f.Capsule(CapsuleSpec{Intent: r.Intent, BaseSHA: r.Docs,
		Transcript: []lane.Event{
			{Event: "start", BaseSHA: r.Docs, Tree: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
			Exec("sh", "check.sh"),
			Output("ok   all packages"),
			VerdictEvent("verifier", "verifier exits 0", true),
			{Event: "end"},
		},
		Verdicts: []capsule.Verdict{{ID: "verifier", Criterion: "verifier exits 0", Pass: true, Evidence: "transcript:4"}},
		Paths:    []string{"verify/check.sh"},
	})
	r.Verify = f.Commit("verify: run vet before the tests", map[string]string{"verify/check.sh": "#!/bin/sh\ngo vet ./... && go test ./...\n"},
		Trailers(r.Intent, r.VerifyCapsule)...)
	return r
}

// Config is a chimera.yaml for the reference history: the fixture's store,
// its Ring-0 paths, and its risk globs.
func (r *Reference) Config() string {
	return "store:\n  endpoint: file://" + r.StoreDir + "\nring0:\n  paths: [\"verify/**\"]\nrisk:\n  r2: [\"pkg/objstore/**\"]\n"
}

// SortedKeys returns a map's keys in order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
