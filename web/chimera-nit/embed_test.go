package chimeranit

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

func gzipSize(t *testing.T, data []byte) int {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Len()
}

func TestM2_3_BundleIsAtMost8KBGzipped(t *testing.T) {
	onDisk, err := os.ReadFile("chimera-nit.js")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, Source) || len(Source) == 0 {
		t.Fatal("embedded source is not the shipped file")
	}
	size := gzipSize(t, Source)
	t.Logf("chimera-nit.js: %d bytes, %d bytes gzipped (budget %d)", len(Source), size, MaxGzipBytes)
	if size > MaxGzipBytes || MaxGzipBytes != 8192 {
		t.Fatalf("chimera-nit.js is %d bytes gzipped; the budget is 8192", size)
	}
}

func TestM2_3_ElementCapturesFourThingsAndHoldsNoCredentials(t *testing.T) {
	src := string(Source)
	for _, want := range []string{
		`customElements.define(TAG, ChimeraNit)`, `const TAG = "chimera-nit"`, `customElements.get(TAG)`,
		`schema: "chimera.nit/v1"`, `url: location.origin + location.pathname`, `selector: this.selector`,
		`viewport: { w: innerWidth, h: innerHeight, dpr: devicePixelRatio || 1 }`, `text,`,
		`method: "POST"`, `credentials: "include"`, `"Content-Type": "application/json"`, `"/v1/inlet/nit"`,
		`adoptedStyleSheets`, `attachShadow`, `aria-live`, `"chimera-nit:sent"`, `"chimera-nit:error"`,
		// The word shown is the inlet's verdict, not merely "the request went out".
		`body.status === "task"`, `"SENT"`, `body.status === "folio"`, `"QUEUED"`, `body.status === "triage"`, `"RECEIVED"`, `body.status === "dropped" ? "DROPPED"`,
		// The selector walk is bounded and reads the DOM through prototype getters.
		`getter(Node.prototype, "parentElement")`, `getter(Element.prototype, "localName")`, `depth < 64`, `> 1024) path.shift()`,
		`prefers-color-scheme: dark`, `prefers-reduced-motion: reduce`, `outline: 2px solid var(--accent)`,
		`"IBM Plex Sans", ui-sans-serif`, `"IBM Plex Mono", ui-monospace`,
		`--paper: #F6F5F2`, `--ink: #16171A`, `--muted: #5B5E66`, `--rule: #D8D5CE`, `--accent: #1F45C8`,
		`--paper: #101114`, `--ink: #ECEAE4`, `--muted: #9A9DA4`, `--rule: #2A2C31`, `--accent: #7C9BFF`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("source lacks %q", want)
		}
	}
	// No credentials, no dependencies, nothing a strict CSP would refuse, no
	// third-party request, and never the banned typeface.
	for _, banned := range []string{
		"localStorage", "sessionStorage", "document.cookie", "Authorization", "eval(", "innerHTML", "location.href", "location.search", "location.hash", "outerHTML", "insertAdjacentHTML",
		"http://", "https://", "Inter", "import ", "require(", "<style", "cssText", "box-shadow", "gradient", "XMLHttpRequest",
	} {
		if strings.Contains(src, banned) {
			t.Errorf("source contains %q", banned)
		}
	}
	// No corner is rounder than 2px.
	for _, part := range strings.Split(src, "border-radius:")[1:] {
		if v := strings.TrimSpace(strings.SplitN(part, ";", 2)[0]); v != "2px" {
			t.Errorf("border-radius %q", v)
		}
	}
}
