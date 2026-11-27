package capsule

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"

	"chimera/pkg/objstore"
	"chimera/pkg/secretscan"
)

// RuleUnreadable marks a member the gate could not read through (for example
// a .zst that does not decompress). A gate that cannot decide refuses.
const RuleUnreadable = "unreadable"

// maxDecoded bounds how far the gate decompresses one member.
const maxDecoded = 256 << 20

// GateError is a refused push: the secret gate found something. It carries
// locations and rule IDs only, never matched bytes.
type GateError struct{ Findings []secretscan.Finding }

func (e *GateError) Error() string {
	return fmt.Sprintf("secret gate: %d findings (rule %s)", len(e.Findings), strings.Join(secretscan.Rules(e.Findings), ", "))
}

// IntegrityError is a readback or download whose hash did not match.
type IntegrityError struct{ Member string }

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("member %s: readback hash mismatch", e.Member)
}

// Zstd compresses data.
func Zstd(data []byte) []byte {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	defer enc.Close()
	return enc.EncodeAll(data, nil)
}

// Unzstd decompresses data, refusing output beyond the gate's bound.
func Unzstd(data []byte) ([]byte, error) {
	dec, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDecoded))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return io.ReadAll(io.LimitReader(dec, maxDecoded+1))
}

// maxNesting bounds how many layers of compression or archiving the gate
// opens before it refuses.
const maxNesting = 6

type container int

const (
	plain container = iota
	zstdStream
	gzipStream
	bzip2Stream
	zipArchive
	tarArchive
	opaque // a compressed format the gate cannot open
)

// sniff identifies compressed or archived content by magic bytes, and by a
// name that promises compression the bytes do not deliver.
func sniff(name string, data []byte) container {
	has := func(magic string) bool { return bytes.HasPrefix(data, []byte(magic)) }
	switch {
	case has("\x28\xb5\x2f\xfd"):
		return zstdStream
	case has("\x1f\x8b"):
		return gzipStream
	case has("BZh") && len(data) > 3 && data[3] >= '1' && data[3] <= '9':
		return bzip2Stream
	case has("PK\x03\x04"), has("PK\x05\x06"):
		return zipArchive
	case len(data) > 262 && string(data[257:262]) == "ustar":
		return tarArchive
	case has("\xfd7zXZ\x00"), has("7z\xbc\xaf\x27\x1c"), has("\x04\x22\x4d\x18"), has("Rar!\x1a\x07"), has("LZIP"), has("\x1f\x9d"), has("\x1f\xa0"):
		return opaque
	}
	lower := strings.ToLower(name)
	for _, ext := range []string{".zst", ".zstd", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".lz4", ".lz", ".br", ".7z", ".rar", ".zip", ".tar", ".z"} {
		if strings.HasSuffix(lower, ext) {
			return opaque // named as compressed, but not in a form the gate can open
		}
	}
	return plain
}

// gateWalk scans data, then opens it if it is compressed or an archive and
// scans what is inside, recursively. Anything it cannot open is a finding:
// a gate that cannot read a member refuses the upload.
type gateWalk struct {
	scanner *secretscan.Scanner
	member  string
	budget  int64 // decoded bytes still allowed for this member
	out     []secretscan.Finding
}

func (g *gateWalk) refuse() {
	g.out = append(g.out, secretscan.Finding{Path: g.member, Rule: RuleUnreadable})
}

func (g *gateWalk) readAll(r io.Reader) ([]byte, bool) {
	data, err := io.ReadAll(io.LimitReader(r, g.budget+1))
	if err != nil || int64(len(data)) > g.budget {
		return nil, false
	}
	g.budget -= int64(len(data))
	return data, true
}

func (g *gateWalk) walk(name string, data []byte, depth int) {
	g.out = append(g.out, g.scanner.Scan(g.member, data)...)
	kind := sniff(name, data)
	if kind == plain {
		return
	}
	if kind == opaque || depth >= maxNesting {
		g.refuse()
		return
	}
	inner := strings.TrimSuffix(name, filepath.Ext(name))
	switch kind {
	case zstdStream:
		dec, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDecoded))
		if err != nil {
			g.refuse()
			return
		}
		decoded, ok := g.readAll(dec)
		dec.Close()
		if !ok {
			g.refuse()
			return
		}
		g.walk(inner, decoded, depth+1)
	case gzipStream:
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			g.refuse()
			return
		}
		decoded, ok := g.readAll(zr)
		if !ok {
			g.refuse()
			return
		}
		g.walk(inner, decoded, depth+1)
	case bzip2Stream:
		decoded, ok := g.readAll(bzip2.NewReader(bytes.NewReader(data)))
		if !ok {
			g.refuse()
			return
		}
		g.walk(inner, decoded, depth+1)
	case zipArchive:
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			g.refuse()
			return
		}
		for _, f := range zr.File {
			g.out = append(g.out, g.scanner.Scan(g.member, []byte(f.Name))...)
			if f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				g.refuse()
				return
			}
			content, ok := g.readAll(rc)
			rc.Close()
			if !ok {
				g.refuse()
				return
			}
			g.walk(f.Name, content, depth+1)
		}
	case tarArchive:
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				g.refuse()
				return
			}
			g.out = append(g.out, g.scanner.Scan(g.member, []byte(h.Name+"\n"+h.Linkname))...)
			content, ok := g.readAll(tr)
			if !ok {
				g.refuse()
				return
			}
			g.walk(h.Name, content, depth+1)
		}
	}
}

// Gate scans every byte of a packed Capsule: each member as stored, every
// layer inside a compressed or archived member (zstd, gzip, bzip2, zip, tar,
// recognized by content, not by name), and capsule.json. A member in a
// compressed format the gate cannot open, or nested too deep, is itself a
// finding. Findings are member:line:col rule-id.
//
// One narrow exemption: a tenant or denylist term found inside the value of
// capsule.json's own repo field is not a finding. That field names the
// repository the Capsule is about, which is by definition a tenant value;
// without the exemption no Capsule for a configured repository could ever be
// written. Every other rule still applies to that value, and every rule
// applies to the rest of capsule.json.
func Gate(l *Local, scanner *secretscan.Scanner) []secretscan.Finding {
	var out []secretscan.Finding
	for _, mem := range l.Manifest.Members {
		g := &gateWalk{scanner: scanner, member: mem.Path, budget: maxDecoded}
		g.walk(mem.Path, l.Members[mem.Path], 0)
		out = append(out, g.out...)
	}
	lo, hi := repoValueRange(l.Raw, l.Manifest.Repo)
	for _, f := range scanner.Scan(ManifestName, l.Raw) {
		inRepo := f.Line == 1 && f.Col-1 >= lo && f.Col-1 < hi
		if inRepo && (f.Rule == secretscan.RuleTenantTerm || f.Rule == secretscan.RuleDenylistTerm) {
			continue
		}
		out = append(out, f)
	}
	// A match visible in more than one layer at the same position is one finding.
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	dedup := out[:0]
	for i, f := range out {
		if i == 0 || f != out[i-1] {
			dedup = append(dedup, f)
		}
	}
	secretscan.Sort(dedup)
	return dedup
}

// repoValueRange returns the byte range of the repo value inside canonical
// capsule.json. A quote inside a JSON string is always escaped, so the key
// pattern can only match the real key.
func repoValueRange(raw []byte, repo string) (lo, hi int) {
	enc, err := Canonical(repo)
	if err != nil || repo == "" {
		return -1, -1
	}
	i := bytes.Index(raw, append([]byte(`"repo":`), enc...))
	if i < 0 {
		return -1, -1
	}
	lo = i + len(`"repo":"`)
	return lo, lo + len(enc) - 2
}

// PushResult counts what a push did.
type PushResult struct {
	Address  Address
	Uploaded int // objects this push created
	Existing int // objects already present and verified identical
}

// Push uploads a packed directory following the write protocol:
// (1) the secret gate scans every byte and any finding aborts before the
// first request; (2) members upload first and capsule.json last, so
// capsule.json is the commit point; (3) every PUT is conditional
// (If-None-Match: *); (4) every PUT is followed by a GET and a SHA-256
// comparison. An already-present object is success only if its readback hash
// matches; a mismatch is a fatal integrity error.
func Push(ctx context.Context, store objstore.Store, dir string, scanner *secretscan.Scanner) (PushResult, error) {
	if scanner == nil {
		return PushResult{}, fmt.Errorf("secret gate unavailable")
	}
	l, err := Load(dir)
	if err != nil {
		return PushResult{}, err
	}
	if findings := Gate(l, scanner); len(findings) > 0 {
		return PushResult{Address: l.Address}, &GateError{Findings: findings}
	}
	res := PushResult{Address: l.Address}
	put := func(name string, data []byte) error {
		created, err := store.Put(ctx, l.Address.Key(name), data)
		if err != nil {
			return fmt.Errorf("member %s: %w", name, err)
		}
		back, err := store.Get(ctx, l.Address.Key(name))
		if err != nil {
			return fmt.Errorf("member %s: readback failed: %w", name, err)
		}
		if sha256.Sum256(back) != sha256.Sum256(data) {
			return &IntegrityError{Member: name}
		}
		if created {
			res.Uploaded++
		} else {
			res.Existing++
		}
		return nil
	}
	for _, mem := range l.Manifest.Members {
		if err := put(mem.Path, l.Members[mem.Path]); err != nil {
			return res, err
		}
	}
	if err := put(ManifestName, l.Raw); err != nil {
		return res, err
	}
	return res, nil
}

// ErrNotInStore reports a Capsule whose capsule.json is absent.
var ErrNotInStore = errors.New("capsule not in store")

// Get downloads a Capsule and verifies capsule.json against the address and
// every member against capsule.json.
func Get(ctx context.Context, store objstore.Store, addr Address) (*Local, error) {
	raw, err := store.Get(ctx, addr.Key(ManifestName))
	if errors.Is(err, objstore.ErrNotFound) {
		return nil, ErrNotInStore
	}
	if err != nil {
		return nil, err
	}
	if AddressOf(raw) != addr {
		return nil, &IntegrityError{Member: ManifestName}
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	l := &Local{Address: addr, Manifest: m, Raw: raw, Members: map[string][]byte{}}
	for _, mem := range m.Members {
		data, err := store.Get(ctx, addr.Key(mem.Path))
		if err != nil {
			return nil, fmt.Errorf("member %s: %w", mem.Path, err)
		}
		sum := sha256.Sum256(data)
		if int64(len(data)) != mem.Size || hex.EncodeToString(sum[:]) != mem.SHA256 {
			return nil, &IntegrityError{Member: mem.Path}
		}
		l.Members[mem.Path] = data
	}
	return l, nil
}

// Exists reports whether addr's capsule.json is in the store and hashes to
// the address.
func Exists(ctx context.Context, store objstore.Store, addr Address) (bool, error) {
	raw, err := store.Get(ctx, addr.Key(ManifestName))
	if errors.Is(err, objstore.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if AddressOf(raw) != addr {
		return false, &IntegrityError{Member: ManifestName}
	}
	return true, nil
}

// List returns the address of every committed Capsule in the store, sorted.
func List(ctx context.Context, store objstore.Store) ([]Address, error) {
	keys, err := store.List(ctx, "cas/sha256-")
	if err != nil {
		return nil, err
	}
	var out []Address
	for _, k := range keys {
		rest := strings.TrimPrefix(k, "cas/sha256-")
		hexpart, member, ok := strings.Cut(rest, "/")
		if !ok || member != ManifestName {
			continue
		}
		if a, err := ParseAddress("sha256:" + hexpart); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// TouchedPaths lists the files a git-format diff changes, sorted and without
// duplicates, with the post-image blob ID when the diff carries full index
// lines. It reads the "diff --git" headers git writes with the standard a/
// and b/ prefixes, including C-quoted names.
func TouchedPaths(diff []byte) []Touched {
	byPath := map[string]*Touched{}
	var cur *Touched
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			cur = nil
			path := diffPath(strings.TrimPrefix(line, "diff --git "))
			if path == "" {
				continue
			}
			t, ok := byPath[path]
			if !ok {
				t = &Touched{Path: path}
				byPath[path] = t
			}
			cur = t
		case cur != nil && strings.HasPrefix(line, "index "):
			f := strings.Fields(strings.TrimPrefix(line, "index "))
			if len(f) > 0 {
				if _, post, ok := strings.Cut(f[0], ".."); ok && len(post) == 40 && strings.Trim(post, "0") != "" {
					cur.Blob = post
				}
			}
		case strings.HasPrefix(line, "@@ "), strings.HasPrefix(line, "GIT binary patch"):
			cur = nil // the header is over; hunk content is not parsed
		}
	}
	out := make([]Touched, 0, len(byPath))
	for _, t := range byPath {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// diffPath extracts the path from the remainder of a "diff --git" line:
// either `a/<path> b/<path>` (the two names are equal when renames are off)
// or the same with one or both sides C-quoted.
func diffPath(rest string) string {
	if strings.HasPrefix(rest, `"`) {
		if a, tail, ok := cutQuoted(rest); ok {
			if b := strings.TrimPrefix(tail, " "); strings.HasPrefix(b, `"`) {
				if bq, _, ok := cutQuoted(b); ok {
					return strings.TrimPrefix(bq, "b/")
				}
			}
			return strings.TrimPrefix(a, "a/")
		}
		return ""
	}
	if i := strings.Index(rest, ` "b/`); i >= 0 {
		if b, _, ok := cutQuoted(rest[i+1:]); ok {
			return strings.TrimPrefix(b, "b/")
		}
	}
	// Equal halves: "a/P b/P" is 2*len(P)+5 bytes with a space in the middle.
	if n := len(rest); n >= 5 && n%2 == 1 {
		a, b := rest[:n/2], rest[n/2+1:]
		if rest[n/2] == ' ' && strings.HasPrefix(a, "a/") && strings.HasPrefix(b, "b/") && a[2:] == b[2:] {
			return a[2:]
		}
	}
	if i := strings.LastIndex(rest, " b/"); i >= 0 {
		return rest[i+3:]
	}
	return ""
}

// cutQuoted reads one C-quoted string from the start of s.
func cutQuoted(s string) (value, rest string, ok bool) {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			v, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", "", false
			}
			return v, s[i+1:], true
		}
	}
	return "", "", false
}

// Touched is one file changed by a Capsule's diff.
type Touched struct {
	Path string
	Blob string // post-image blob ID; "" when deleted or not recorded
}
