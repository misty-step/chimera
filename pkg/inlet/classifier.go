package inlet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"chimera/pkg/capsule"
)

// NitSchema identifies the payload <chimera-nit> posts.
const NitSchema = "chimera.nit/v1"

// Viewport is the window the nit was raised in.
type Viewport struct {
	W   int     `json:"w"`
	H   int     `json:"h"`
	DPR float64 `json:"dpr"`
}

// Nit is one piece of feedback: where on which page, and what the owner said.
type Nit struct {
	Schema   string   `json:"schema"`
	URL      string   `json:"url"`
	Selector string   `json:"selector"`
	Viewport Viewport `json:"viewport"`
	Text     string   `json:"text"`
}

// Limits on an owner nit.
const (
	MaxText     = 4000
	MaxSelector = 1024
	MaxURL      = 2048
)

// Validate checks an owner nit. The message never repeats the input.
func (n Nit) Validate() error {
	switch {
	case n.Schema != "" && n.Schema != NitSchema:
		return fmt.Errorf("unsupported schema")
	case strings.TrimSpace(n.Text) == "" || !utf8.ValidString(n.Text) || utf8.RuneCountInString(n.Text) > MaxText:
		return fmt.Errorf("text must be 1 to %d characters", MaxText)
	case len(n.Selector) > MaxSelector || !utf8.ValidString(n.Selector):
		return fmt.Errorf("selector must be at most %d bytes", MaxSelector)
	case n.Viewport.W < 0 || n.Viewport.H < 0 || n.Viewport.W > 100000 || n.Viewport.H > 100000 || n.Viewport.DPR < 0 || n.Viewport.DPR > 16:
		return fmt.Errorf("viewport out of range")
	case len(n.URL) > MaxURL:
		return fmt.Errorf("url too long")
	}
	u, err := url.Parse(n.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("url must be absolute http or https")
	}
	return nil
}

// FolioSnapshot is the Folio text a classifier judges a nit against.
type FolioSnapshot struct {
	Product string `json:"product"`
	Design  string `json:"design"`
}

// Decision kinds.
const (
	KindViolation = "violation" // the product violates the existing Folio
	KindIntent    = "intent"    // new or changed intent: the Folio should change
)

// Edit is the full new content of one Folio file.
type Edit struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Decision is a classifier's ruling on one owner nit.
type Decision struct {
	Kind       string   `json:"kind"`
	Clause     string   `json:"clause"`     // the violated clause, e.g. "DESIGN.md §2.2"; required for a violation
	Brief      string   `json:"brief"`      // reconcile order text; defaults to the nit text
	Acceptance []string `json:"acceptance"` // acceptance IDs the reconcile order must prove
	Edits      []Edit   `json:"edits"`      // proposed Folio content (intent only)
	Summary    string   `json:"summary"`    // one line
}

// maxEditBytes bounds the Folio content one decision may propose.
const maxEditBytes = 1 << 20

// errFence marks a decision that names a path outside the Folio fence.
var errFence = fmt.Errorf("edit outside the folio path fence")

// Validate checks a decision before anything acts on it. A decision naming
// one path outside the fence is refused whole.
func (d Decision) Validate() error {
	for _, id := range d.Acceptance {
		if !capsule.IsAcceptanceID(id) {
			return fmt.Errorf("malformed acceptance id")
		}
	}
	switch d.Kind {
	case KindViolation:
		if strings.TrimSpace(d.Clause) == "" {
			return fmt.Errorf("violation names no clause")
		}
		if len(d.Edits) > 0 {
			return fmt.Errorf("violation proposes folio edits")
		}
	case KindIntent:
		seen := map[string]bool{}
		total := 0
		for _, e := range d.Edits {
			if !InFence(e.Path) {
				return errFence
			}
			if seen[e.Path] {
				return fmt.Errorf("duplicate edit path")
			}
			seen[e.Path] = true
			if total += len(e.Content); total > maxEditBytes {
				return fmt.Errorf("edits too large")
			}
		}
		// One edit may not be a directory another edit writes into: no tree
		// holds both, and a proposal that can never be staged must not queue.
		for p := range seen {
			for i := strings.IndexByte(p, '/'); i >= 0; {
				if seen[p[:i]] {
					return fmt.Errorf("edit paths conflict: one is a directory of another")
				}
				next := strings.IndexByte(p[i+1:], '/')
				if next < 0 {
					break
				}
				i += 1 + next
			}
		}
	default:
		return fmt.Errorf("unknown decision kind")
	}
	return nil
}

// Classifier decides what an owner nit is. It is the only model call the
// inlet ever makes, and only owner nits that passed every guard reach it.
type Classifier interface {
	Classify(ctx context.Context, nit Nit, folio FolioSnapshot) (Decision, error)
}

// CommandClassifier runs an external command: Chimera embeds no model. The
// command reads {"schema","nit","folio":{"product","design"}} on stdin and
// writes one Decision as JSON on stdout.
type CommandClassifier struct {
	Argv    []string
	Timeout time.Duration // 0 means DefaultClassifierTimeout
	Dir     string        // working directory; "" means the process's
}

// DefaultClassifierTimeout bounds one classification.
const DefaultClassifierTimeout = 60 * time.Second

// maxClassifierOutput caps what is read from the command.
const maxClassifierOutput = 2 << 20

type capBuffer struct {
	buf  bytes.Buffer
	over bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := maxClassifierOutput - b.buf.Len(); room < len(p) {
		if room > 0 {
			b.buf.Write(p[:room])
		}
		b.over = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// Classify implements Classifier. Errors never carry the command's output.
func (c CommandClassifier) Classify(ctx context.Context, nit Nit, folio FolioSnapshot) (Decision, error) {
	if len(c.Argv) == 0 {
		return Decision{}, fmt.Errorf("classifier command not configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultClassifierTimeout
	}
	stdin, err := json.Marshal(struct {
		Schema string        `json:"schema"`
		Nit    Nit           `json:"nit"`
		Folio  FolioSnapshot `json:"folio"`
	}{"chimera.inlet.classify/v1", nit, folio})
	if err != nil {
		return Decision{}, fmt.Errorf("classifier request: cannot encode")
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(tctx, c.Argv[0], c.Argv[1:]...)
	cmd.Dir = c.Dir
	cmd.Stdin = bytes.NewReader(stdin)
	var out capBuffer
	cmd.Stdout, cmd.Stderr = &out, io.Discard
	// The classifier needs none of Chimera's own secrets.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CHIMERA_S3_") && !strings.HasPrefix(kv, "CHIMERA_FORGE_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second
	err = cmd.Run()
	killProcessGroup(cmd)
	switch {
	case tctx.Err() != nil && ctx.Err() == nil:
		return Decision{}, fmt.Errorf("classifier timed out after %s", timeout)
	case ctx.Err() != nil:
		return Decision{}, ctx.Err()
	case err != nil:
		return Decision{}, fmt.Errorf("classifier command failed")
	case out.over:
		return Decision{}, fmt.Errorf("classifier output too large")
	}
	var d Decision
	if json.Unmarshal(out.buf.Bytes(), &d) != nil {
		return Decision{}, fmt.Errorf("classifier output is not a decision")
	}
	return d, nil
}
