package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"chimera/pkg/capsule"
	"chimera/pkg/objstore"
)

const (
	fxIntent     = "folio:9c1e000000000000000000000000000000000000000000000000000000000000"
	fxCheckpoint = "ckpt_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

// loopback starts the S3 fake on a loopback listener and returns the
// environment that points the CLI at it.
func loopback(t *testing.T) (*objstore.Fake, map[string]string) {
	t.Helper()
	id, secret := "test-access", "test-"+genTerm(t)
	fake := objstore.NewFake(id, secret)
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return fake, map[string]string{
		"CHIMERA_STORE_ENDPOINT": srv.URL, "CHIMERA_STORE_BUCKET": "capsules", "CHIMERA_STORE_REGION": "auto",
		"CHIMERA_S3_ACCESS_KEY_ID": id, "CHIMERA_S3_SECRET_ACCESS_KEY": secret,
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func commitAll(t *testing.T, dir, msg string) string {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "-c", "user.name=Example", "-c", "user.email=dev@example.com", "commit", "-q", "-m", msg)
	return gitOut(t, dir, "rev-parse", "HEAD")
}

// capsuleDir writes the members of a small Capsule about pkg/a.go.
func capsuleDir(t *testing.T, repo string, transcript string) string {
	t.Helper()
	dir := t.TempDir()
	blob := gitOut(t, repo, "rev-parse", "HEAD:pkg/a.go")
	writeFiles(t, dir, map[string]string{
		"diff.patch":         "diff --git a/pkg/a.go b/pkg/a.go\nindex " + strings.Repeat("1", 40) + ".." + blob + " 100644\n--- a/pkg/a.go\n+++ b/pkg/a.go\n@@ -1 +1,3 @@\n package a\n+\n+func A() int { return 1 }\n",
		"verdicts.json":      `[{"id":"[M1-2]","criterion":"A returns one","pass":true,"evidence":"transcript:3"},{"id":"[M1-2]","criterion":"vet is clean","pass":false,"evidence":"vet: unused variable at a.go:9"}]`,
		"proof/verifier.log": "ok   pkg/a  0.01s\n",
	})
	if err := os.WriteFile(filepath.Join(dir, "transcript.jsonl.zst"), capsule.Zstd([]byte(transcript)), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func widgetRepo(t *testing.T) string {
	t.Helper()
	repo := fixtureRepo(t, map[string]string{"pkg/a.go": "package a\n", "README.md": "# widget\n"})
	writeFiles(t, repo, map[string]string{"pkg/a.go": "package a\n\nfunc A() int { return 1 }\n"})
	commitAll(t, repo, "a: add A")
	return repo
}

func TestM1_2_PackPushGetAttachWhyAgainstLoopbackFake(t *testing.T) {
	repo := widgetRepo(t)
	fake, env := loopback(t)
	dir := capsuleDir(t, repo, `{"checkpoint":"`+fxCheckpoint+`","event":"output","line":"ok"}`+"\n")
	head := gitOut(t, repo, "rev-parse", "HEAD")

	// pack: prints the address; deterministic.
	p := run(t, repo, env, "capsule", "pack", dir, "--intent", fxIntent, "--checkpoint", fxCheckpoint, "--repo", "acme/widget", "--base-sha", head, "--tag", "k:1", "--tag", "lane:demo")
	if p.code != ExitOK || !strings.HasPrefix(p.stdout, "sha256:") || len(strings.TrimSpace(p.stdout)) != 71 {
		t.Fatalf("pack: %+v", p)
	}
	addr := strings.TrimSpace(p.stdout)
	if again := run(t, repo, env, "capsule", "pack", dir, "--intent", fxIntent, "--checkpoint", fxCheckpoint, "--repo", "acme/widget", "--base-sha", head, "--tag", "lane:demo,k:1"); again.stdout != p.stdout {
		t.Fatalf("pack is not deterministic: %q vs %q", again.stdout, p.stdout)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "capsule.json"))
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != addr {
		t.Fatal("address is not sha256(capsule.json)")
	}
	if fake.Requests() != 0 {
		t.Fatal("pack touched the store")
	}

	// attach refuses while the Capsule is not in the store.
	if r := run(t, repo, env, "capsule", "attach", "HEAD", addr); r.code != ExitError || !strings.Contains(r.stderr, "capsule not in store") || gitOut(t, repo, "rev-parse", "HEAD") != head {
		t.Fatalf("attach before push: %+v", r)
	}

	// push: gate, conditional PUT, readback. Every request is SigV4-verified by the fake.
	u := run(t, repo, env, "capsule", "push", dir)
	if u.code != ExitOK || strings.TrimSpace(u.stdout) != addr || !strings.Contains(u.stderr, "5 uploaded, 0 already present") {
		t.Fatalf("push: %+v", u)
	}
	if fake.Rejected() != 0 || len(fake.Keys()) != 5 {
		t.Fatalf("fake: rejected=%d keys=%v", fake.Rejected(), fake.Keys())
	}
	for key, n := range fake.Writes() {
		if n != 1 || !strings.HasPrefix(key, "capsules/cas/sha256-"+strings.TrimPrefix(addr, "sha256:")+"/") {
			t.Errorf("%s written %d times", key, n)
		}
	}
	if u2 := run(t, repo, env, "capsule", "push", dir); u2.code != ExitOK || !strings.Contains(u2.stderr, "0 uploaded, 5 already present") {
		t.Fatalf("second push: %+v", u2)
	}

	// get: downloads, verifies, writes.
	out := filepath.Join(t.TempDir(), "out")
	g := run(t, repo, env, "capsule", "get", addr, "--out", out, "--json")
	var got struct {
		Schema, Address string
		Verified        bool
		Manifest        capsule.Manifest
	}
	if err := json.Unmarshal([]byte(g.stdout), &got); err != nil || g.code != ExitOK {
		t.Fatalf("get: %+v %v", g, err)
	}
	if got.Schema != "chimera.capsule/v1" || got.Address != addr || !got.Verified || len(got.Manifest.Members) != 4 || got.Manifest.Repo != "acme/widget" {
		t.Fatalf("%+v", got)
	}
	back, _ := os.ReadFile(filepath.Join(out, "capsule.json"))
	if string(back) != string(raw) {
		t.Fatal("downloaded capsule.json differs")
	}
	human := run(t, repo, env, "capsule", "get", addr)
	if human.code != ExitOK || !strings.Contains(human.stdout, "CAPSULE     "+addr[:19]+"\n") || strings.Contains(human.stdout, addr) || !strings.Contains(human.stdout, "MEMBER") {
		t.Fatalf("human get (hashes abbreviate to 12): %+v", human)
	}

	// attach: both trailers, Intent first, on HEAD; the tree is unchanged.
	tree := gitOut(t, repo, "rev-parse", "HEAD^{tree}")
	a := run(t, repo, env, "capsule", "attach", "HEAD", addr, "--intent", fxIntent)
	if a.code != ExitOK {
		t.Fatalf("attach: %+v", a)
	}
	newHead := gitOut(t, repo, "rev-parse", "HEAD")
	if newHead == head || strings.TrimSpace(a.stdout) != newHead || gitOut(t, repo, "rev-parse", "HEAD^{tree}") != tree {
		t.Fatalf("attach did not rewrite HEAD in place: %s → %s", head, newHead)
	}
	msg := gitOut(t, repo, "log", "-1", "--format=%B")
	if !strings.HasSuffix(msg, "Chimera-Intent: "+fxIntent+"\nChimera-Capsule: "+addr) {
		t.Fatalf("trailers:\n%s", msg)
	}
	if gitOut(t, repo, "log", "-1", "--format=%an <%ae>") != "Example <dev@example.com>" || gitOut(t, repo, "status", "--porcelain") != "" {
		t.Fatal("attach changed authorship or the work tree")
	}
	if r := run(t, repo, env, "capsule", "attach", "HEAD", addr, "--intent", "task:"+strings.Repeat("0", 64)); r.code != ExitError || !strings.Contains(r.stderr, "different intent") {
		t.Fatalf("attach with the wrong intent: %+v", r)
	}

	// why: blame → trailers → Capsule.
	w := run(t, repo, env, "why", "pkg/a.go:3")
	if w.code != ExitOK {
		t.Fatalf("why: %+v", w)
	}
	for _, want := range []string{"FILE        pkg/a.go:3", "COMMIT      " + newHead[:12] + "  a: add A", "ANCHOR      HEAD  fresh", "INTENT      folio:9c1e00000000\n",
		"CAPSULE     " + addr[:19] + "\n", "CHECKPOINT  " + fxCheckpoint, "[M1-2]  PASS   A returns one", "[M1-2]  FAIL   vet is clean"} {
		if !strings.Contains(w.stdout, want) {
			t.Errorf("why output lacks %q:\n%s", want, w.stdout)
		}
	}
	var wj whyResult
	if j := run(t, repo, env, "why", "pkg/a.go:3", "--json"); json.Unmarshal([]byte(j.stdout), &wj) != nil || wj.Schema != "chimera.why/v1" ||
		wj.Commit != newHead || len(wj.Proofs) != 1 || wj.Proofs[0].Capsule != addr || wj.Proofs[0].Intent != fxIntent || !wj.Proofs[0].Covers || len(wj.Proofs[0].Verdicts) != 2 {
		t.Fatalf("why --json: %s", j.stdout)
	}
	// A line committed without trailers exits 1: missing proof.
	if r := run(t, repo, env, "why", "pkg/a.go:1"); r.code != ExitError || r.stdout != "" || !strings.HasSuffix(r.stderr, "carries no Chimera-Capsule trailer; missing proof\n") {
		t.Fatalf("why on a line without trailers: %+v", r)
	}
	if r := run(t, repo, env, "why", "README.md"); r.code != ExitError {
		t.Fatalf("why on a file without trailers: %+v", r)
	}
	if r := run(t, repo, env, "why", "pkg/a.go:99"); r.code != ExitError {
		t.Fatalf("why past EOF: %+v", r)
	}
	// From a subdirectory, with a path relative to it.
	if r := run(t, filepath.Join(repo, "pkg"), env, "why", "a.go:3"); r.code != ExitOK || !strings.Contains(r.stdout, "FILE        pkg/a.go:3") {
		t.Fatalf("why from a subdirectory: %+v", r)
	}

	// Anchor drift: two later commits, one of which touches the file.
	writeFiles(t, repo, map[string]string{"README.md": "# widget\n\nmore\n"})
	commitAll(t, repo, "docs: more")
	writeFiles(t, repo, map[string]string{"pkg/a.go": "package a\n\nfunc A() int { return 1 }\n\nfunc B() {}\n"})
	commitAll(t, repo, "a: add B")
	d := run(t, repo, env, "why", "pkg/a.go:3")
	if d.code != ExitOK || !strings.Contains(d.stdout, "ANCHOR      HEAD-2  drift=1") {
		t.Fatalf("drift: %+v", d)
	}
	var dj whyResult
	json.Unmarshal([]byte(run(t, repo, env, "why", "pkg/a.go:3", "--json").stdout), &dj)
	if dj.Anchor.Ref != "HEAD-2" || dj.Anchor.Drift != 1 || dj.Anchor.State != "drift" || dj.Anchor.Commit != newHead {
		t.Fatalf("%+v", dj.Anchor)
	}
	// Whole-file form: the file's last commit has no trailers.
	if r := run(t, repo, env, "why", "pkg/a.go"); r.code != ExitError {
		t.Fatalf("why <file> after an untrailered edit: %+v", r)
	}

	// attach to an unpushed commit below HEAD rewrites the chain above it.
	target := gitOut(t, repo, "rev-parse", "HEAD~1")
	before := gitOut(t, repo, "log", "--format=%s%n%T", "-3")
	r := run(t, repo, env, "capsule", "attach", target, addr)
	if r.code != ExitOK {
		t.Fatalf("attach below HEAD: %+v", r)
	}
	if gitOut(t, repo, "log", "--format=%s%n%T", "-3") != before {
		t.Fatal("subjects or trees changed in the rewritten chain")
	}
	if got := gitOut(t, repo, "log", "-1", "--format=%(trailers:key=Chimera-Capsule,valueonly)", "HEAD~1"); strings.TrimSpace(got) != addr {
		t.Fatalf("HEAD~1 trailers: %q", got)
	}
	if strings.TrimSpace(r.stdout) != gitOut(t, repo, "rev-parse", "HEAD~1") {
		t.Fatalf("attach printed %q", r.stdout)
	}
	if run(t, repo, env, "why", "README.md:3").code != ExitOK {
		t.Fatal("why does not resolve the newly attached commit")
	}
	// A pushed commit is never rewritten.
	git(t, repo, "update-ref", "refs/remotes/origin/main", "HEAD")
	headNow := gitOut(t, repo, "rev-parse", "HEAD")
	if r := run(t, repo, env, "capsule", "attach", "HEAD", addr); r.code != ExitError || !strings.Contains(r.stderr, "already pushed") || gitOut(t, repo, "rev-parse", "HEAD") != headNow {
		t.Fatalf("attach on a pushed commit: %+v", r)
	}
}

func TestM1_2_SecretInTranscriptAbortsPushWithZeroRequests(t *testing.T) {
	repo := widgetRepo(t)
	fake, env := loopback(t)
	token := "ghp_" + strings.Repeat(genTerm(t), 3)[:36]
	dir := capsuleDir(t, repo, `{"event":"output","line":"export GH=`+token+`"}`+"\n")
	if r := run(t, repo, env, "capsule", "pack", dir, "--intent", fxIntent, "--checkpoint", fxCheckpoint); r.code != ExitOK {
		t.Fatalf("%+v", r)
	}
	r := run(t, repo, env, "capsule", "push", dir)
	if r.code != ExitError || r.stdout != "transcript.jsonl.zst:1:37 forge-token\n" {
		t.Fatalf("%+v", r)
	}
	if r.stderr != "chimera: capsule push: secret gate: 1 findings (rule forge-token); nothing uploaded\n" {
		t.Fatalf("stderr=%q", r.stderr)
	}
	if fake.Requests() != 0 {
		t.Fatalf("%d requests reached the store", fake.Requests())
	}
	assertNoTerm(t, r, token)
	j := run(t, repo, env, "capsule", "write", dir, "--intent", fxIntent, "--json")
	if j.code != ExitUsage { // write is not a read command: --json is not in its table
		t.Fatalf("%+v", j)
	}
	// The configured secret itself, and a tenant value, are gate terms too.
	clean := capsuleDir(t, repo, "deployed with "+env["CHIMERA_S3_SECRET_ACCESS_KEY"]+"\n")
	run(t, repo, env, "capsule", "pack", clean, "--intent", fxIntent, "--checkpoint", fxCheckpoint)
	if r := run(t, repo, env, "capsule", "push", clean); r.code != ExitError || !strings.Contains(r.stdout, "configured-secret") || fake.Requests() != 0 {
		t.Fatalf("configured secret in a member: %+v", r)
	}
	assertNoTerm(t, r, env["CHIMERA_S3_SECRET_ACCESS_KEY"])
	// An unreadable denylist fails closed before anything is sent.
	ok := capsuleDir(t, repo, "fine\n")
	run(t, repo, env, "capsule", "pack", ok, "--intent", fxIntent, "--checkpoint", fxCheckpoint)
	env["CHIMERA_TENANT_DENYLIST_FILE"] = filepath.Join(t.TempDir(), "missing.txt")
	if r := run(t, repo, env, "capsule", "push", ok); r.code != ExitError || !strings.Contains(r.stderr, "denylist file: unreadable") || fake.Requests() != 0 {
		t.Fatalf("unreadable denylist: %+v", r)
	}
}

func TestM1_2_CorruptStoreFailsPushGetAndWhy(t *testing.T) {
	repo := widgetRepo(t)
	fake, env := loopback(t)
	dir := capsuleDir(t, repo, "ok\n")
	addr := strings.TrimSpace(run(t, repo, env, "capsule", "pack", dir, "--intent", fxIntent, "--checkpoint", fxCheckpoint).stdout)
	fake.CorruptOnPut(func(key string, body []byte) []byte {
		if strings.HasSuffix(key, "diff.patch") {
			return []byte("corrupted")
		}
		return body
	})
	r := run(t, repo, env, "capsule", "push", dir)
	if r.code != ExitError || r.stderr != "chimera: capsule push: member diff.patch: readback hash mismatch; integrity error; the capsule is not committed\n" {
		t.Fatalf("push through a corrupting store: %+v", r)
	}
	if g := run(t, repo, env, "capsule", "get", addr); g.code != ExitError || !strings.Contains(g.stderr, "capsule not in store") {
		t.Fatalf("capsule.json must not exist after a failed push: %+v", g)
	}

	fake2, env2 := loopback(t)
	if r := run(t, repo, env2, "capsule", "push", dir); r.code != ExitOK {
		t.Fatalf("%+v", r)
	}
	run(t, repo, env2, "capsule", "attach", "HEAD", addr)
	fake2.Corrupt("verdicts.json")
	out := filepath.Join(t.TempDir(), "out")
	g := run(t, repo, env2, "capsule", "get", addr, "--out", out)
	if g.code != ExitError || !strings.Contains(g.stderr, "member verdicts.json: hash mismatch") || g.stdout != "" {
		t.Fatalf("get of a corrupted capsule: %+v", g)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("get wrote files from a corrupted capsule")
	}
	if w := run(t, repo, env2, "why", "pkg/a.go:3"); w.code != ExitError || !strings.Contains(w.stderr, "hash mismatch") {
		t.Fatalf("why over a corrupted capsule: %+v", w)
	}
	if v := run(t, repo, env2, "capsule", "verify", addr); v.code != ExitError {
		t.Fatalf("verify of a corrupted capsule: %+v", v)
	}
}

func TestM1_2_WriteReadVerifyOnDirectoryStore(t *testing.T) {
	repo := widgetRepo(t)
	storeDir := filepath.Join(t.TempDir(), "store")
	env := map[string]string{"CHIMERA_STORE_ENDPOINT": "file://" + storeDir}
	dir := capsuleDir(t, repo, "ok\n")
	w := run(t, repo, env, "capsule", "write", dir, "--intent", fxIntent, "--repo", "acme/widget")
	if w.code != ExitOK || !strings.Contains(w.stderr, "5 uploaded") {
		t.Fatalf("write: %+v", w)
	}
	addr := strings.TrimSpace(w.stdout)
	hexpart := strings.TrimPrefix(addr, "sha256:")
	st, err := os.Stat(filepath.Join(storeDir, "cas", "sha256-"+hexpart, "capsule.json"))
	if err != nil || st.Mode().Perm()&0o222 != 0 {
		t.Fatalf("stored capsule.json: %v %v", st, err)
	}
	if r := run(t, repo, env, "capsule", "read", addr, "--json"); r.code != ExitOK || !strings.Contains(r.stdout, `"verified":true`) || !strings.Contains(r.stdout, `"checkpoint":"ckpt_`) {
		t.Fatalf("read: %+v", r)
	}
	for _, target := range []string{addr, dir} {
		if r := run(t, repo, env, "capsule", "verify", target); r.code != ExitOK || !strings.Contains(r.stderr, "PASS") {
			t.Fatalf("verify %s: %+v", target, r)
		}
	}
	// A member edited after packing no longer verifies, and cannot be pushed.
	os.WriteFile(filepath.Join(dir, "proof", "verifier.log"), []byte("edited\n"), 0o644)
	if r := run(t, repo, env, "capsule", "verify", dir); r.code != ExitError || !strings.Contains(r.stderr, "differs from capsule.json") {
		t.Fatalf("verify of an edited directory: %+v", r)
	}
	if r := run(t, repo, env, "capsule", "push", dir); r.code != ExitError {
		t.Fatalf("push of an edited directory: %+v", r)
	}
	// Tampering with the store is caught on read.
	p := filepath.Join(storeDir, "cas", "sha256-"+hexpart, "diff.patch")
	os.Chmod(p, 0o644)
	os.WriteFile(p, []byte("tampered"), 0o644)
	if r := run(t, repo, env, "capsule", "verify", addr); r.code != ExitError || !strings.Contains(r.stderr, "member diff.patch: hash mismatch") {
		t.Fatalf("verify of a tampered store: %+v", r)
	}
	// Usage errors: nothing attempted.
	for _, args := range [][]string{
		{"capsule", "pack", dir}, {"capsule", "pack", dir, "--intent", "folio:abc", "--checkpoint", fxCheckpoint}, {"capsule", "get", "sha256:nothex"},
		{"capsule", "push"}, {"capsule", "attach", "HEAD"}, {"capsule", "push", filepath.Join(dir, "missing")}, {"why"}, {"why", "a.go:0"},
	} {
		if r := run(t, repo, env, args...); r.code == ExitOK || r.stdout != "" {
			t.Errorf("%v: %+v", args, r)
		}
	}
	if r := run(t, repo, nil, "capsule", "push", dir); r.code != ExitUsage || !strings.Contains(r.stderr, "store.endpoint not configured") {
		t.Fatalf("no store configured: %+v", r)
	}
}
