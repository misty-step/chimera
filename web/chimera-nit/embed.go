// Package chimeranit embeds <chimera-nit>, the dependency-free custom
// element that raises a nit (PRODUCT.md §2.6): it captures the page URL, a
// CSS selector, the viewport, and the text, and POSTs them to the inlet. It
// holds no credentials; the edge session does.
package chimeranit

import _ "embed"

// Source is chimera-nit.js exactly as shipped, for a host to serve.
//
//go:embed chimera-nit.js
var Source []byte

// MaxGzipBytes is the budget the Folio sets for the element: 8 KB gzipped.
const MaxGzipBytes = 8192
