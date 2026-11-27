// Package capsule implements the Capsule: the single immutable evidence atom
// (PRODUCT.md §2.1). A Capsule is a directory of members plus capsule.json,
// whose canonical bytes hash to the Capsule's address.
package capsule

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ManifestName is the member that addresses the Capsule. It is uploaded last.
const ManifestName = "capsule.json"

// Schema identifies the manifest format.
const Schema = "chimera.capsule/v1"

// LaneConfig is the full lane description recorded in every Capsule.
type LaneConfig struct {
	Model         string `json:"model" yaml:"model"`
	Harness       string `json:"harness" yaml:"harness"`
	Skill         string `json:"skill" yaml:"skill"`
	Prompt        string `json:"prompt" yaml:"prompt"`
	Effort        string `json:"effort" yaml:"effort"`
	ContextPolicy string `json:"context_policy" yaml:"context_policy"`
	Runner        string `json:"runner" yaml:"runner"`
}

// Member is one file of the bundle other than capsule.json.
type Member struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is capsule.json.
type Manifest struct {
	Schema     string     `json:"schema"`
	Intent     string     `json:"intent"`
	Checkpoint string     `json:"checkpoint"`
	Repo       string     `json:"repo"`
	BaseSHA    string     `json:"base_sha"`
	Lane       LaneConfig `json:"lane"`
	StartedAt  string     `json:"started_at"`
	EndedAt    string     `json:"ended_at"`
	Tags       []string   `json:"tags"`
	Members    []Member   `json:"members"`
}

// Verdict is one row of verdicts.json.
type Verdict struct {
	ID        string `json:"id"`
	Criterion string `json:"criterion"`
	Pass      bool   `json:"pass"`
	Evidence  string `json:"evidence"`
}

// Metrics is metrics.json: what a lane measured. Usage and CostUSD are null
// when the harness reported no token usage; cost is never estimated.
type Metrics struct {
	WallMS  int64    `json:"wall_ms"`
	Usage   *Usage   `json:"usage"`
	CostUSD *float64 `json:"cost_usd"`
}

// Usage is harness-reported token usage.
type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

// Well-known member names.
const (
	MemberTranscript = "transcript.jsonl.zst"
	MemberDiff       = "diff.patch"
	MemberVerdicts   = "verdicts.json"
	MemberMetrics    = "metrics.json"
	MemberClaims     = "claims.json"
)

var (
	intentRE     = regexp.MustCompile(`^(folio|task):[0-9a-f]{64}$`)
	checkpointRE = regexp.MustCompile(`^ckpt_[0-9A-HJKMNP-TV-Z]{26}$`)
	addressRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidIntent reports whether id is a well-formed Intent ID.
func ValidIntent(id string) bool { return intentRE.MatchString(id) }

// ValidCheckpoint reports whether id is a well-formed checkpoint ID.
func ValidCheckpoint(id string) bool { return checkpointRE.MatchString(id) }

// Address is "sha256:<hex>" of the canonical capsule.json.
type Address string

// ParseAddress validates s as a Capsule address.
func ParseAddress(s string) (Address, error) {
	if !addressRE.MatchString(s) {
		return "", fmt.Errorf("not a capsule address (want sha256:<64 hex>)")
	}
	return Address(s), nil
}

// Hex returns the bare hex digest.
func (a Address) Hex() string { return strings.TrimPrefix(string(a), "sha256:") }

// Key returns the object-store key of a member of this Capsule.
func (a Address) Key(member string) string { return "cas/sha256-" + a.Hex() + "/" + member }

// AddressOf hashes canonical manifest bytes.
func AddressOf(canonical []byte) Address {
	sum := sha256.Sum256(canonical)
	return Address("sha256:" + hex.EncodeToString(sum[:]))
}

// Canonical renders any JSON-encodable value in canonical form: UTF-8, keys
// sorted, no insignificant whitespace, no trailing newline.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil { // maps encode with sorted keys
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Bytes returns the canonical capsule.json for m.
func (m Manifest) Bytes() ([]byte, error) {
	if m.Tags == nil {
		m.Tags = []string{}
	}
	if m.Members == nil {
		m.Members = []Member{}
	}
	return Canonical(m)
}

// ParseManifest decodes capsule.json and insists it is canonical, so the
// address of the bytes read is the address of the bytes anyone would write.
func ParseManifest(raw []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("capsule.json: malformed")
	}
	if m.Schema != Schema {
		return m, fmt.Errorf("capsule.json: unsupported schema")
	}
	canon, err := m.Bytes()
	if err != nil || !bytes.Equal(canon, raw) {
		return m, fmt.Errorf("capsule.json: not in canonical form")
	}
	for _, mem := range m.Members {
		if !validMemberPath(mem.Path) {
			return m, fmt.Errorf("capsule.json: invalid member path")
		}
	}
	return m, nil
}

func validMemberPath(p string) bool {
	if p == "" || p == ManifestName || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Meta is everything in capsule.json that is not derived from the members.
type Meta struct {
	Intent     string
	Checkpoint string
	Repo       string
	BaseSHA    string
	Lane       LaneConfig
	StartedAt  time.Time // zero means unset
	EndedAt    time.Time
	Tags       []string
}

// Pack hashes every file under dir, writes the canonical capsule.json there,
// and returns the Capsule's address. Its output depends only on the member
// bytes and meta, so it is identical across runs and machines.
func Pack(dir string, meta Meta) (Address, error) {
	if !ValidIntent(meta.Intent) {
		return "", fmt.Errorf("intent must be folio:<64 hex> or task:<64 hex>")
	}
	if !ValidCheckpoint(meta.Checkpoint) {
		return "", fmt.Errorf("checkpoint must be ckpt_<ULID>")
	}
	members, err := scanMembers(dir)
	if err != nil {
		return "", err
	}
	tagSet := map[string]bool{}
	for _, t := range meta.Tags {
		if t = strings.TrimSpace(t); t != "" {
			tagSet[t] = true
		}
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	m := Manifest{
		Schema: Schema, Intent: meta.Intent, Checkpoint: meta.Checkpoint, Repo: meta.Repo, BaseSHA: meta.BaseSHA,
		Lane: meta.Lane, StartedAt: stamp(meta.StartedAt), EndedAt: stamp(meta.EndedAt), Tags: tags, Members: members,
	}
	raw, err := m.Bytes()
	if err != nil {
		return "", err
	}
	if err := writeAtomic(filepath.Join(dir, ManifestName), raw); err != nil {
		return "", fmt.Errorf("capsule.json: cannot write")
	}
	return AddressOf(raw), nil
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// scanMembers lists every regular file under dir except capsule.json, sorted
// by path. Anything that is not a regular file is refused.
func scanMembers(dir string) ([]Member, error) {
	var members []Member
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s: unreadable", rel(dir, p))
		}
		if d.IsDir() {
			return nil
		}
		name := rel(dir, p)
		if name == ManifestName {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("member %s: not a regular file", name)
		}
		if !validMemberPath(name) {
			return fmt.Errorf("member %s: invalid path", name)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("member %s: unreadable", name)
		}
		sum := sha256.Sum256(data)
		members = append(members, Member{Path: name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].Path < members[j].Path })
	return members, nil
}

func rel(dir, p string) string {
	r, err := filepath.Rel(dir, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(r)
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Local is a packed Capsule read from a directory and checked against its
// own manifest.
type Local struct {
	Address  Address
	Manifest Manifest
	Raw      []byte            // canonical capsule.json
	Members  map[string][]byte // path → bytes
}

// ErrNotPacked reports a directory without capsule.json.
var ErrNotPacked = errors.New("no capsule.json; run 'chimera capsule pack' first")

// Load reads a packed directory and verifies that it holds exactly the
// members capsule.json lists, with matching sizes and hashes.
func Load(dir string) (*Local, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotPacked
	}
	if err != nil {
		return nil, fmt.Errorf("capsule.json: unreadable")
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	onDisk, err := scanMembers(dir)
	if err != nil {
		return nil, err
	}
	if len(onDisk) != len(m.Members) {
		return nil, fmt.Errorf("directory holds %d members but capsule.json lists %d; pack again", len(onDisk), len(m.Members))
	}
	l := &Local{Address: AddressOf(raw), Manifest: m, Raw: raw, Members: map[string][]byte{}}
	for i, mem := range m.Members {
		if onDisk[i] != mem {
			return nil, fmt.Errorf("member %s: differs from capsule.json; pack again", mem.Path)
		}
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(mem.Path)))
		if err != nil {
			return nil, fmt.Errorf("member %s: unreadable", mem.Path)
		}
		l.Members[mem.Path] = data
	}
	return l, nil
}

// Verdicts decodes verdicts.json; a Capsule without one has none.
func (l *Local) Verdicts() ([]Verdict, error) {
	data, ok := l.Members[MemberVerdicts]
	if !ok {
		return nil, nil
	}
	var vs []Verdict
	if err := json.Unmarshal(data, &vs); err != nil {
		return nil, fmt.Errorf("verdicts.json: malformed")
	}
	return vs, nil
}

// Metrics decodes metrics.json; ok is false when the Capsule has none.
func (l *Local) Metrics() (m Metrics, ok bool) {
	data, has := l.Members[MemberMetrics]
	if !has || json.Unmarshal(data, &m) != nil {
		return Metrics{}, false
	}
	return m, true
}

// WriteDir writes capsule.json and every member under dir.
func (l *Local) WriteDir(dir string) error {
	for _, mem := range l.Manifest.Members {
		if err := writeAtomic(filepath.Join(dir, filepath.FromSlash(mem.Path)), l.Members[mem.Path]); err != nil {
			return fmt.Errorf("member %s: cannot write", mem.Path)
		}
	}
	if err := writeAtomic(filepath.Join(dir, ManifestName), l.Raw); err != nil {
		return fmt.Errorf("capsule.json: cannot write")
	}
	return nil
}

// Tag returns the value of the first tag "<key>:<value>", or "".
func (m Manifest) Tag(key string) string {
	for _, t := range m.Tags {
		if v, ok := strings.CutPrefix(t, key+":"); ok {
			return v
		}
	}
	return ""
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewCheckpoint allocates an opaque checkpoint ID, ckpt_<ULID>. Transcripts
// refer to it; the sealed Capsule records it; the commit records the Capsule.
// Arrows point one way, so there is never a hash cycle.
func NewCheckpoint(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("no entropy for checkpoint id")
	}
	// 128 bits → 26 base32 characters, most significant first.
	out := make([]byte, 26)
	var acc uint
	bits := 2 // pad the 128-bit value to 130 bits
	i := 0
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[i] = crockford[(acc>>uint(bits))&31]
			i++
		}
	}
	return "ckpt_" + string(out), nil
}
