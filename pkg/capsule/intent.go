package capsule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"chimera/pkg/objstore"
)

// TaskVerifier is the verifier a task Intent names.
type TaskVerifier struct {
	Command []string `yaml:"command"`
	Timeout string   `yaml:"timeout"`
}

// TaskManifest is task.yaml: the source bytes of a task Intent (PRODUCT.md
// §1). Its canonical YAML — this struct, fields in this order — hashes to the
// Intent ID. Clause and Acceptance are omitted when empty, so a manifest
// without them hashes exactly as it always has.
type TaskManifest struct {
	Brief    string       `yaml:"brief"`
	Repo     string       `yaml:"repo"`
	BaseSHA  string       `yaml:"base_sha"`
	Verifier TaskVerifier `yaml:"verifier"`
	// Clause names the Folio clause a reconcile order restores, e.g.
	// "DESIGN.md §2.2".
	Clause string `yaml:"clause,omitempty"`
	// Acceptance lists the acceptance IDs the task must prove.
	Acceptance []string `yaml:"acceptance,omitempty"`
}

// Bytes returns the canonical task.yaml.
func (m TaskManifest) Bytes() []byte {
	raw, _ := yaml.Marshal(m)
	return raw
}

// Intent returns the manifest's Intent ID, task:<sha256 of Bytes>.
func (m TaskManifest) Intent() string {
	sum := sha256.Sum256(m.Bytes())
	return "task:" + hex.EncodeToString(sum[:])
}

// AcceptanceIDs returns the acceptance IDs the task carries: the listed
// ones, then any declared in the brief.
func (m TaskManifest) AcceptanceIDs() []string {
	return uniq(append(append([]string{}, m.Acceptance...), AcceptanceIDs(m.Brief)...))
}

// TaskKey is the object-store key of a task Intent's manifest. Task Intents
// are content-addressed and write-once, like Capsules.
func TaskKey(intent string) string {
	return "intent/task-" + strings.TrimPrefix(intent, "task:") + "/task.yaml"
}

// PutTask stores a task manifest write-once and reads it back, returning its
// Intent ID. Storing the same manifest twice is a success.
func PutTask(ctx context.Context, store objstore.Store, m TaskManifest) (string, error) {
	raw, intent := m.Bytes(), m.Intent()
	if _, err := store.Put(ctx, TaskKey(intent), raw); err != nil {
		return "", fmt.Errorf("task manifest: %w", err)
	}
	back, err := store.Get(ctx, TaskKey(intent))
	if err != nil {
		return "", fmt.Errorf("task manifest: readback failed: %w", err)
	}
	if sha256.Sum256(back) != sha256.Sum256(raw) {
		return "", &IntegrityError{Member: "task.yaml"}
	}
	return intent, nil
}

// GetTask fetches a task Intent's manifest and verifies it hashes to the
// Intent ID. It returns ErrNotInStore when no manifest was ever stored.
func GetTask(ctx context.Context, store objstore.Store, intent string) (TaskManifest, error) {
	var m TaskManifest
	if !ValidIntent(intent) || !strings.HasPrefix(intent, "task:") {
		return m, fmt.Errorf("not a task intent")
	}
	raw, err := store.Get(ctx, TaskKey(intent))
	if errors.Is(err, objstore.ErrNotFound) {
		return m, ErrNotInStore
	}
	if err != nil {
		return m, err
	}
	sum := sha256.Sum256(raw)
	if "task:"+hex.EncodeToString(sum[:]) != intent {
		return m, &IntegrityError{Member: "task.yaml"}
	}
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("task.yaml: malformed")
	}
	return m, nil
}

var (
	acceptanceIDRE = regexp.MustCompile(`^\[[A-Z][A-Z0-9]*-[0-9]+\]$`)
	// An ID is declared where it opens a line, after any list, quote, heading,
	// or emphasis markers: "**[M1-2] …**", "- [AUTH-3] …", "## [M2-1]".
	declaredIDRE = regexp.MustCompile(`(?m)^[ \t]*(?:(?:[-*+>]|#+|[0-9]+[.)])[ \t]+)*(?:\*\*|__)?(\[[A-Z][A-Z0-9]*-[0-9]+\])`)
)

// IsAcceptanceID reports whether s has the shape of an acceptance ID: "[M1-2]".
func IsAcceptanceID(s string) bool { return acceptanceIDRE.MatchString(s) }

// AcceptanceIDs returns the acceptance IDs an Intent's text declares, each
// once, in order of first appearance. An ID is declared where it opens a
// line or list item; an ID merely mentioned inside a sentence is a
// reference, not a declaration.
func AcceptanceIDs(text string) []string {
	var ids []string
	for _, m := range declaredIDRE.FindAllStringSubmatch(text, -1) {
		ids = append(ids, m[1])
	}
	return uniq(ids)
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
