package capsule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/objstore"
)

func TestM2_1_AcceptanceIDsAreDeclaredNotMerelyMentioned(t *testing.T) {
	text := "# Product\n\nVerifiers report against IDs (`[M1-2]`, `[AUTH-3]`, …).\n\n**[M1-1] Module.** Refers to [M9-9] in passing.\n- [AUTH-3] login\n" +
		"  2. __[UI-12]__ dark mode\n> ## [M2-1] Trail\n**[M1-1] again**\n[lowercase-1] no\n[M1-] no\n"
	got := strings.Join(AcceptanceIDs(text), " ")
	if got != "[M1-1] [AUTH-3] [UI-12] [M2-1]" {
		t.Fatalf("got %q", got)
	}
	if !IsAcceptanceID("[M2-3]") || IsAcceptanceID("verifier") || IsAcceptanceID("[m2-3]") || IsAcceptanceID("M2-3") {
		t.Fatal("IsAcceptanceID")
	}
	// The repository's own Folio declares exactly its seven milestone items.
	folio, err := os.ReadFile(filepath.Join("..", "..", "PRODUCT.md"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(AcceptanceIDs(string(folio)), " "); got != "[M1-1] [M1-2] [M1-3] [M1-4] [M2-1] [M2-2] [M2-3]" {
		t.Fatalf("PRODUCT.md declares %q", got)
	}
}

func TestM2_3_TaskManifestIsContentAddressedAndWriteOnce(t *testing.T) {
	ctx := context.Background()
	store := objstore.NewDir(filepath.Join(t.TempDir(), "store"))
	m := TaskManifest{Brief: "Restore the focus ring.\n- [NIT-1] focus ring is 2px accent", Repo: "acme/widget", BaseSHA: strings.Repeat("a", 40),
		Verifier: TaskVerifier{Command: []string{"go", "test", "./..."}, Timeout: "10m0s"}, Clause: "DESIGN.md §2.6"}
	intent, err := PutTask(ctx, store, m)
	if err != nil || !ValidIntent(intent) || intent != m.Intent() {
		t.Fatalf("%q %v", intent, err)
	}
	if again, err := PutTask(ctx, store, m); err != nil || again != intent {
		t.Fatalf("second put: %q %v", again, err)
	}
	got, err := GetTask(ctx, store, intent)
	if err != nil || got.Clause != "DESIGN.md §2.6" || got.Brief != m.Brief || strings.Join(got.AcceptanceIDs(), ",") != "[NIT-1]" {
		t.Fatalf("%+v %v", got, err)
	}
	other := m
	other.Clause = "DESIGN.md §2.2"
	if other.Intent() == intent {
		t.Fatal("a different clause hashed to the same intent")
	}
	if _, err := GetTask(ctx, store, other.Intent()); !errors.Is(err, ErrNotInStore) {
		t.Fatalf("missing manifest: %v", err)
	}
	// A manifest that no longer hashes to its ID is refused.
	p := filepath.Join(t.TempDir(), "s2")
	bad := objstore.NewDir(p)
	if _, err := bad.Put(ctx, TaskKey(intent), []byte("brief: tampered\n")); err != nil {
		t.Fatal(err)
	}
	var ie *IntegrityError
	if _, err := GetTask(ctx, bad, intent); !errors.As(err, &ie) {
		t.Fatalf("tampered manifest: %v", err)
	}
	// Without the optional fields the bytes are the four-field manifest M1 hashed.
	plain := TaskManifest{Brief: "b", Repo: "acme/widget", BaseSHA: "c", Verifier: TaskVerifier{Command: []string{"true"}, Timeout: "1s"}}
	if string(plain.Bytes()) != "brief: b\nrepo: acme/widget\nbase_sha: c\nverifier:\n    command:\n        - \"true\"\n    timeout: 1s\n" {
		t.Fatalf("canonical bytes:\n%s", plain.Bytes())
	}
}
