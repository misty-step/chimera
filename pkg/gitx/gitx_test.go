package gitx

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=Example", "-c", "user.email=dev@example.com"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestM1_2_TrailersRoundTripInOrder(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "a.txt", "one\ntwo\n")
	git(t, dir, "add", "-A")
	intent := "folio:" + strings.Repeat("9c", 32)
	capsule := "sha256:" + strings.Repeat("4b", 32)
	msg, err := WithTrailers(ctx, dir, "capsule: verify readback hash\n\nBody text.\n", intent, capsule)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(msg, "\n\nChimera-Intent: "+intent+"\nChimera-Capsule: "+capsule+"\n") {
		t.Fatalf("trailers not appended in order:\n%s", msg)
	}
	again, _ := WithTrailers(ctx, dir, msg, intent, capsule)
	if again != msg {
		t.Fatalf("same pair repeated:\n%s", again)
	}
	git(t, dir, "commit", "-q", "-m", msg)
	tr, err := ReadTrailers(ctx, dir, "HEAD")
	if err != nil || len(tr.Intents) != 1 || tr.Intents[0] != intent || len(tr.Capsules) != 1 || tr.Capsules[0] != capsule {
		t.Fatalf("%+v %v", tr, err)
	}
	write(t, dir, "a.txt", "one\nTWO\n")
	git(t, dir, "commit", "-q", "-am", "edit without trailers")
	plain, _ := ReadTrailers(ctx, dir, "HEAD")
	if !plain.Empty() {
		t.Fatalf("%+v", plain)
	}
	first, err := BlameLine(ctx, dir, "a.txt", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := BlameLine(ctx, dir, "a.txt", 2)
	head := git(t, dir, "rev-parse", "HEAD")
	if second != head || first == head {
		t.Fatalf("blame first=%s second=%s head=%s", first, second, head)
	}
	if n, _ := CountSince(ctx, dir, first, "a.txt"); n != 1 {
		t.Fatalf("drift=%d", n)
	}
	if _, err := BlameLine(ctx, dir, "a.txt", 99); err == nil {
		t.Fatal("line past EOF accepted")
	}
}

func TestM1_3_FolioIntentHashesSortedPathAndBlob(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "PRODUCT.md", "# product\n")
	write(t, dir, "DESIGN.md", "# design\n")
	write(t, dir, "folio/assets/a.svg", "<svg/>\n")
	write(t, dir, "README.md", "not folio\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "folio")
	id, err := FolioIntent(ctx, dir, "HEAD")
	if err != nil || len(id) != len("folio:")+64 {
		t.Fatalf("%q %v", id, err)
	}
	write(t, dir, "README.md", "still not folio\n")
	git(t, dir, "commit", "-q", "-am", "readme")
	if same, _ := FolioIntent(ctx, dir, "HEAD"); same != id {
		t.Fatal("non-folio change moved the intent")
	}
	write(t, dir, "DESIGN.md", "# design v2\n")
	git(t, dir, "commit", "-q", "-am", "design")
	if moved, _ := FolioIntent(ctx, dir, "HEAD"); moved == id {
		t.Fatal("folio change did not move the intent")
	}
	entries, _ := LsTree(ctx, dir, "HEAD")
	var shas []string
	for _, e := range entries {
		shas = append(shas, e.SHA)
	}
	blobs, err := CatBlobs(ctx, dir, shas)
	if err != nil || len(blobs) != 4 || string(blobs[entries[0].SHA]) != "# design v2\n" {
		t.Fatalf("%d blobs err=%v", len(blobs), err)
	}
}

func TestM2_1_UnionTrailersKeepsEveryDistinctTrailerInOriginalOrder(t *testing.T) {
	a := []Trailer{{"Chimera-Intent", "folio:aa"}, {"Chimera-Capsule", "sha256:01"}, {"Signed-off-by", "Dev <dev@example.com>"}}
	b := []Trailer{{"chimera-intent", "folio:aa"}, {"Chimera-Capsule", "sha256:02"}, {"Signed-off-by", "Dev <dev@example.com>"}}
	c := []Trailer{{"Chimera-Intent", "task:bb"}, {"Chimera-Capsule", "sha256:01"}, {"", "ignored"}}
	got := UnionTrailers(a, b, c)
	want := []Trailer{{"Chimera-Intent", "folio:aa"}, {"Chimera-Capsule", "sha256:01"}, {"Signed-off-by", "Dev <dev@example.com>"},
		{"Chimera-Capsule", "sha256:02"}, {"Chimera-Intent", "task:bb"}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trailer %d: got %v want %v", i, got[i], want[i])
		}
	}
	if ct := ChimeraTrailers(got); strings.Join(ct.Intents, ",") != "folio:aa,task:bb" || strings.Join(ct.Capsules, ",") != "sha256:01,sha256:02" {
		t.Fatalf("%+v", ct)
	}
	if UnionTrailers() != nil {
		t.Fatal("empty union is not nil")
	}
}

func TestM2_1_RangeCommitsCarryTrailersAndDiffStatCountsLines(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "a.txt", "one\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "base")
	base := git(t, dir, "rev-parse", "HEAD")
	intent := "folio:" + strings.Repeat("9c", 32)
	capsule := "sha256:" + strings.Repeat("4b", 32)
	write(t, dir, "a.txt", "one\ntwo\nthree\n")
	write(t, dir, "pkg/b.bin", "\x00\x01\x02")
	git(t, dir, "add", "-A")
	msg, err := MessageWithTrailers(ctx, dir, "a: add lines\n\nBody with a --- divider\n---\nstill body", []Trailer{{TrailerIntent, intent}, {TrailerCapsule, capsule}, {TrailerIntent, intent}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(msg, "still body\n\nChimera-Intent: "+intent+"\nChimera-Capsule: "+capsule+"\n") {
		t.Fatalf("message:\n%s", msg)
	}
	git(t, dir, "commit", "-q", "-m", msg)
	write(t, dir, "c.txt", "no trailers\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "docs: untrailered")
	commits, err := RangeCommits(ctx, dir, base, "HEAD")
	if err != nil || len(commits) != 2 {
		t.Fatalf("%v %+v", err, commits)
	}
	first, second := commits[0], commits[1]
	if first.Subject != "a: add lines" || len(first.Parents) != 1 || first.Parents[0] != base || len(first.Trailers) != 2 ||
		first.Chimera().Intents[0] != intent || first.Chimera().Capsules[0] != capsule {
		t.Fatalf("first: %+v", first)
	}
	if second.Subject != "docs: untrailered" || len(second.Trailers) != 0 || !second.Chimera().Empty() {
		t.Fatalf("second: %+v", second)
	}
	all, err := CommitTrailers(ctx, dir, first.SHA)
	if err != nil || len(all) != 2 || all[0] != (Trailer{TrailerIntent, intent}) {
		t.Fatalf("%v %+v", err, all)
	}
	stats, err := DiffStat(ctx, dir, base, first.SHA)
	if err != nil || len(stats) != 2 || stats[0] != (FileStat{Path: "a.txt", Added: 2}) || stats[1] != (FileStat{Path: "pkg/b.bin", Binary: true}) {
		t.Fatalf("%v %+v", err, stats)
	}
	root, err := DiffStat(ctx, dir, "", base)
	if err != nil || len(root) != 1 || root[0] != (FileStat{Path: "a.txt", Added: 1}) {
		t.Fatalf("%v %+v", err, root)
	}
}
