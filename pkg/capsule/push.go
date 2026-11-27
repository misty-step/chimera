package capsule

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
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

// Gate scans every byte of a packed Capsule: each member as stored, each
// compressed member again after decompression, and capsule.json. It returns
// findings as member:line:col rule-id.
//
// One narrow exemption: capsule.json is scanned with its own repo field
// blanked. That field names the repository the Capsule is about, which is by
// definition a tenant value; without the exemption no Capsule for a
// configured repository could ever be written.
func Gate(l *Local, scanner *secretscan.Scanner) []secretscan.Finding {
	var out []secretscan.Finding
	for _, mem := range l.Manifest.Members {
		data := l.Members[mem.Path]
		out = append(out, scanner.Scan(mem.Path, data)...)
		var decoded []byte
		var err error
		switch {
		case strings.HasSuffix(mem.Path, ".zst"):
			decoded, err = Unzstd(data)
		case strings.HasSuffix(mem.Path, ".gz"):
			var zr *gzip.Reader
			if zr, err = gzip.NewReader(bytes.NewReader(data)); err == nil {
				decoded, err = io.ReadAll(io.LimitReader(zr, maxDecoded+1))
			}
		default:
			continue
		}
		if err != nil || len(decoded) > maxDecoded {
			out = append(out, secretscan.Finding{Path: mem.Path, Rule: RuleUnreadable})
			continue
		}
		out = append(out, scanner.Scan(mem.Path, decoded)...)
	}
	blank := l.Manifest
	blank.Repo = ""
	if raw, err := blank.Bytes(); err != nil {
		out = append(out, secretscan.Finding{Path: ManifestName, Rule: RuleUnreadable})
	} else {
		out = append(out, scanner.Scan(ManifestName, raw)...)
	}
	// A match visible both raw and decoded is one finding.
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

// TouchedPaths lists the files a git-format diff changes (post-image names;
// pre-image for deletions), sorted, with the post-image blob ID when the diff
// carries full index lines.
func TouchedPaths(diff []byte) []Touched {
	var out []Touched
	var cur *Touched
	for _, line := range strings.Split(string(diff), "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			rest := strings.TrimPrefix(line, "diff --git ")
			// "a/<path> b/<path>": the two halves are equal length for plain edits.
			path := ""
			if i := strings.Index(rest, " b/"); i >= 0 {
				path = rest[i+3:]
			}
			out = append(out, Touched{Path: strings.Trim(path, `"`)})
			cur = &out[len(out)-1]
		case cur != nil && strings.HasPrefix(line, "index "):
			f := strings.Fields(strings.TrimPrefix(line, "index "))
			if len(f) > 0 {
				if _, post, ok := strings.Cut(f[0], ".."); ok && len(post) == 40 && strings.Trim(post, "0") != "" {
					cur.Blob = post
				}
			}
		case cur != nil && strings.HasPrefix(line, "rename to "):
			cur.Path = strings.TrimPrefix(line, "rename to ")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Touched is one file changed by a Capsule's diff.
type Touched struct {
	Path string
	Blob string // post-image blob ID; "" when deleted or not recorded
}
