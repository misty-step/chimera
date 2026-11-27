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
