package capsule

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

const (
	testIntent     = "folio:9c1e000000000000000000000000000000000000000000000000000000000000"
	testCheckpoint = "ckpt_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func writeDir(t *testing.T, files map[string][]byte, order []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range order {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func sampleFiles() map[string][]byte {
	return map[string][]byte{
		MemberTranscript:     Zstd([]byte(`{"checkpoint":"` + testCheckpoint + `","event":"harness","line":"ok"}` + "\n")),
		MemberDiff:           []byte("diff --git a/pkg/a.go b/pkg/a.go\nindex 1111111111111111111111111111111111111111..2222222222222222222222222222222222222222 100644\n--- a/pkg/a.go\n+++ b/pkg/a.go\n@@ -1 +1 @@\n-old\n+new\n"),
		MemberVerdicts:       []byte(`[{"id":"[M1-2]","criterion":"put is write-once","pass":true,"evidence":"transcript:1"}]`),
		"proof/verifier.log": []byte("ok   pkg/a  0.01s\n"),
	}
}

func sampleMeta() Meta {
	return Meta{
		Intent: testIntent, Checkpoint: testCheckpoint, Repo: "acme/widget", BaseSHA: strings.Repeat("a", 40),
		Lane:      LaneConfig{Model: "example-model", Harness: "example-agent", Effort: "high", ContextPolicy: "push", Runner: "local"},
		StartedAt: time.Date(2026, 11, 26, 19, 4, 11, 0, time.UTC), EndedAt: time.Date(2026, 11, 26, 19, 5, 0, 0, time.UTC),
		Tags: []string{"k:1", "bench:demo", "k:1"},
	}
}

func packed(t *testing.T) (string, Address) {
	t.Helper()
	files := sampleFiles()
	dir := writeDir(t, files, []string{MemberTranscript, MemberDiff, MemberVerdicts, "proof/verifier.log"})
	addr, err := Pack(dir, sampleMeta())
	if err != nil {
		t.Fatal(err)
	}
	return dir, addr
}

func fakeStore(t *testing.T) (*objstore.Fake, objstore.Store) {
	t.Helper()
	cr := objstore.Credentials{AccessKeyID: "test-access", SecretAccessKey: "test-" + randHex(t, 8)}
	fake := objstore.NewFake(cr.AccessKeyID, cr.SecretAccessKey)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	store, err := objstore.Open(srv.URL, "acme-capsules", "auto", cr)
	if err != nil {
		t.Fatal(err)
	}
	return fake, store
}

func TestM1_2_PackIsDeterministic(t *testing.T) {
	files := sampleFiles()
	a := writeDir(t, files, []string{MemberTranscript, MemberDiff, MemberVerdicts, "proof/verifier.log"})
	b := writeDir(t, files, []string{"proof/verifier.log", MemberVerdicts, MemberDiff, MemberTranscript})
	old := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(filepath.Join(b, MemberDiff), old, old)
	os.Chmod(filepath.Join(b, MemberDiff), 0o600)
	addrA, err := Pack(a, sampleMeta())
	if err != nil {
		t.Fatal(err)
	}
	meta := sampleMeta()
	meta.Tags = []string{"bench:demo", "k:1"} // order and duplicates do not matter
	addrB, err := Pack(b, meta)
	if err != nil {
		t.Fatal(err)
	}
	rawA, _ := os.ReadFile(filepath.Join(a, ManifestName))
	rawB, _ := os.ReadFile(filepath.Join(b, ManifestName))
	if addrA != addrB || !bytes.Equal(rawA, rawB) {
		t.Fatalf("pack differs:\n%s\n%s", rawA, rawB)
	}
	if again, _ := Pack(a, sampleMeta()); again != addrA {
		t.Fatal("re-pack moved the address")
	}
	// Canonical form: keys sorted, no insignificant whitespace, no trailing newline.
	if bytes.ContainsAny(rawA, "\n\t") || bytes.Contains(rawA, []byte(": ")) || bytes.Contains(rawA, []byte(", ")) {
		t.Fatalf("not compact: %s", rawA)
	}
	if !bytes.HasPrefix(rawA, []byte(`{"base_sha":"`)) || !bytes.HasSuffix(rawA, []byte(`"tags":["bench:demo","k:1"]}`)) {
		t.Fatalf("keys not sorted: %s", rawA)
	}
	if AddressOf(rawA) != addrA {
		t.Fatal("address is not the sha256 of capsule.json")
	}
	m, err := ParseManifest(rawA)
	if err != nil || len(m.Members) != 4 || m.Members[0].Path != MemberDiff || m.Lane.ContextPolicy != "push" || m.StartedAt != "2026-11-26T19:04:11Z" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := ParseManifest(append(rawA, '\n')); err == nil {
		t.Fatal("non-canonical manifest accepted")
	}
}

func TestM1_2_PackRejectsBadIdentifiersAndSymlinks(t *testing.T) {
	dir := writeDir(t, map[string][]byte{"a.txt": []byte("x")}, []string{"a.txt"})
	for _, m := range []Meta{
		{Intent: "folio:abc", Checkpoint: testCheckpoint},
		{Intent: testIntent, Checkpoint: "ckpt_lowercase"},
		{Intent: "", Checkpoint: testCheckpoint},
	} {
		if _, err := Pack(dir, m); err == nil {
			t.Errorf("accepted %+v", m)
		}
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, "link")); err == nil {
		if _, err := Pack(dir, Meta{Intent: testIntent, Checkpoint: testCheckpoint}); err == nil {
			t.Error("symlink member accepted")
		}
	}
}

func TestM1_2_PushThenGetRoundTrips(t *testing.T) {
	ctx := context.Background()
	dir, addr := packed(t)
	fake, store := fakeStore(t)
	res, err := Push(ctx, store, dir, secretscan.New(nil))
	if err != nil || res.Address != addr || res.Uploaded != 5 || res.Existing != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	keys := fake.Keys()
	if len(keys) != 5 || keys[0] != "acme-capsules/"+addr.Key(ManifestName) {
		t.Fatalf("keys=%v", keys)
	}
	if fake.Rejected() != 0 {
		t.Fatalf("%d requests failed SigV4 verification", fake.Rejected())
	}
	got, err := Get(ctx, store, addr)
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := got.WriteDir(out); err != nil {
		t.Fatal(err)
	}
	back, err := Load(out)
	if err != nil || back.Address != addr {
		t.Fatalf("%v %v", back, err)
	}
	vs, err := got.Verdicts()
	if err != nil || len(vs) != 1 || !vs[0].Pass || vs[0].ID != "[M1-2]" {
		t.Fatalf("%+v %v", vs, err)
	}
	if ok, err := Exists(ctx, store, addr); !ok || err != nil {
		t.Fatalf("exists=%v err=%v", ok, err)
	}
	missing := Address("sha256:" + strings.Repeat("0", 64))
	if ok, _ := Exists(ctx, store, missing); ok {
		t.Fatal("missing capsule exists")
	}
	if _, err := Get(ctx, store, missing); !errors.Is(err, ErrNotInStore) {
		t.Fatalf("err=%v", err)
	}
	list, err := List(ctx, store)
	if err != nil || len(list) != 1 || list[0] != addr {
		t.Fatalf("list=%v err=%v", list, err)
	}
	// A second push is all readback-verified 412s: success, zero new writes.
	res, err = Push(ctx, store, dir, secretscan.New(nil))
	if err != nil || res.Uploaded != 0 || res.Existing != 5 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestM1_2_ConcurrentPushesWriteOnceAndBothSucceed(t *testing.T) {
	ctx := context.Background()
	dir, addr := packed(t)
	fake, store := fakeStore(t)
	var wg sync.WaitGroup
	results := make([]PushResult, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = Push(ctx, store, dir, secretscan.New(nil))
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil || results[i].Address != addr {
			t.Fatalf("push %d: %+v %v", i, results[i], errs[i])
		}
	}
	writes := fake.Writes()
	if len(writes) != 5 {
		t.Fatalf("writes=%v", writes)
	}
	for k, n := range writes {
		if n != 1 {
			t.Errorf("%s written %d times", k, n)
		}
	}
	if results[0].Uploaded+results[1].Uploaded != 5 || results[0].Existing+results[1].Existing != 5 {
		t.Fatalf("%+v", results)
	}
}

func TestM1_2_CorruptedMemberFailsPushAndGet(t *testing.T) {
	ctx := context.Background()
	dir, addr := packed(t)

	// A store that corrupts a member on write: push must fail at readback.
	fake, store := fakeStore(t)
	fake.CorruptOnPut(func(key string, body []byte) []byte {
		if strings.HasSuffix(key, MemberDiff) {
			return append([]byte("X"), body...)
		}
		return body
	})
	_, err := Push(ctx, store, dir, secretscan.New(nil))
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Member != MemberDiff {
		t.Fatalf("push err=%v", err)
	}
	// capsule.json is the commit point: a failed push leaves no Capsule.
	if ok, _ := Exists(ctx, store, addr); ok {
		t.Fatal("capsule.json was committed after a failed member")
	}
	// The corrupt object stays (write-once), so a retry fails too: a 412 is
	// success only when the readback hash matches.
	fake.CorruptOnPut(nil)
	if _, err := Push(ctx, store, dir, secretscan.New(nil)); !errors.As(err, &ie) {
		t.Fatalf("retry over a corrupt object err=%v", err)
	}

	// A member corrupted at rest: get must fail.
	fake2, store2 := fakeStore(t)
	if _, err := Push(ctx, store2, dir, secretscan.New(nil)); err != nil {
		t.Fatal(err)
	}
	if n := fake2.Corrupt(MemberVerdicts); n != 1 {
		t.Fatalf("corrupted %d objects", n)
	}
	if _, err := Get(ctx, store2, addr); !errors.As(err, &ie) || ie.Member != MemberVerdicts {
		t.Fatalf("get err=%v", err)
	}
	fake3, store3 := fakeStore(t)
	Push(ctx, store3, dir, secretscan.New(nil))
	fake3.Corrupt(ManifestName)
	if _, err := Get(ctx, store3, addr); !errors.As(err, &ie) || ie.Member != ManifestName {
		t.Fatalf("get with corrupt capsule.json err=%v", err)
	}
}

func TestM1_2_SecretInTranscriptAbortsBeforeAnyRequest(t *testing.T) {
	ctx := context.Background()
	token := "ghp_" + randHex(t, 18) // forge-token shape, generated per run
	files := sampleFiles()
	files[MemberTranscript] = Zstd([]byte(`{"event":"harness","line":"export GH=` + token + `"}` + "\n"))
	if bytes.Contains(files[MemberTranscript], []byte(token)) {
		t.Skip("token survived compression verbatim; the test would not prove decoding")
	}
	dir := writeDir(t, files, []string{MemberTranscript, MemberDiff, MemberVerdicts, "proof/verifier.log"})
	if _, err := Pack(dir, sampleMeta()); err != nil {
		t.Fatal(err)
	}
	fake, store := fakeStore(t)
	_, err := Push(ctx, store, dir, secretscan.New(nil))
	var ge *GateError
	if !errors.As(err, &ge) || len(ge.Findings) != 1 {
		t.Fatalf("err=%v", err)
	}
	f := ge.Findings[0]
	if f.Path != MemberTranscript || f.Rule != secretscan.RuleForgeToken || f.Line != 1 || f.Col == 0 {
		t.Fatalf("%+v", f)
	}
	if fake.Requests() != 0 {
		t.Fatalf("%d requests reached the store", fake.Requests())
	}
	if strings.Contains(err.Error(), token) || strings.Contains(f.String(), token) {
		t.Fatal("finding echoes the secret")
	}
}

func TestM1_2_GateFailsClosedOnUndecodableMemberAndTenantTerms(t *testing.T) {
	ctx := context.Background()
	term := "acme" + randHex(t, 5)
	files := sampleFiles()
	files[MemberTranscript] = []byte("not zstd at all")
	files["proof/notes.txt"] = []byte("deployed for " + strings.ToUpper(term) + "\n")
	dir := writeDir(t, files, []string{MemberTranscript, MemberDiff, MemberVerdicts, "proof/verifier.log", "proof/notes.txt"})
	meta := sampleMeta()
	meta.Repo = term + "/widget" // the repo field itself is exempt
	if _, err := Pack(dir, meta); err != nil {
		t.Fatal(err)
	}
	fake, store := fakeStore(t)
	scanner := secretscan.New([]secretscan.Term{{Value: term, Rule: secretscan.RuleTenantTerm}, {Value: term + "/widget", Rule: secretscan.RuleTenantTerm}})
	_, err := Push(ctx, store, dir, scanner)
	var ge *GateError
	if !errors.As(err, &ge) {
		t.Fatalf("err=%v", err)
	}
	got := []string{}
	for _, f := range ge.Findings {
		got = append(got, f.String())
	}
	want := "proof/notes.txt:1:14 tenant-term|transcript.jsonl.zst:0:0 unreadable"
	if strings.Join(got, "|") != want {
		t.Fatalf("findings=%v", got)
	}
	if fake.Requests() != 0 {
		t.Fatal("gate refused but requests were sent")
	}
	if _, err := Push(ctx, store, dir, nil); err == nil {
		t.Fatal("push without a gate succeeded")
	}
	// A tenant term in a tag (not the repo field) is still a finding.
	clean := sampleFiles()
	dir2 := writeDir(t, clean, []string{MemberTranscript, MemberDiff, MemberVerdicts, "proof/verifier.log"})
	meta.Tags = []string{"owner:" + term}
	Pack(dir2, meta)
	if _, err := Push(ctx, store, dir2, scanner); !errors.As(err, &ge) || ge.Findings[0].Path != ManifestName {
		t.Fatalf("err=%v", err)
	}
}

func TestM1_2_PushRefusesStalePack(t *testing.T) {
	dir, _ := packed(t)
	os.WriteFile(filepath.Join(dir, MemberDiff), []byte("edited after pack"), 0o644)
	fake, store := fakeStore(t)
	if _, err := Push(context.Background(), store, dir, secretscan.New(nil)); err == nil || fake.Requests() != 0 {
		t.Fatalf("err=%v requests=%d", err, fake.Requests())
	}
	if _, err := Push(context.Background(), store, t.TempDir(), secretscan.New(nil)); !errors.Is(err, ErrNotPacked) {
		t.Fatalf("err=%v", err)
	}
}

func TestM1_2_CheckpointIsULID(t *testing.T) {
	a, err := NewCheckpoint(time.UnixMilli(1700000000000))
	if err != nil || !ValidCheckpoint(a) {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := NewCheckpoint(time.UnixMilli(1700000000000))
	later, _ := NewCheckpoint(time.UnixMilli(1700000001000))
	if a == b {
		t.Fatal("checkpoints collide")
	}
	if a[:15] != b[:15] || !(later[:15] > a[:15]) {
		t.Fatalf("time prefix not sortable: %s %s %s", a, b, later)
	}
}

func TestM1_2_TouchedPathsReadsPostImageBlobs(t *testing.T) {
	diff := "diff --git a/pkg/a.go b/pkg/a.go\nindex " + strings.Repeat("1", 40) + ".." + strings.Repeat("2", 40) + " 100644\n--- a/pkg/a.go\n+++ b/pkg/a.go\n" +
		"diff --git a/gone.txt b/gone.txt\ndeleted file mode 100644\nindex " + strings.Repeat("3", 40) + ".." + strings.Repeat("0", 40) + "\n"
	got := TouchedPaths([]byte(diff))
	if len(got) != 2 || got[0] != (Touched{Path: "gone.txt"}) || got[1] != (Touched{Path: "pkg/a.go", Blob: strings.Repeat("2", 40)}) {
		t.Fatalf("%+v", got)
	}
}
