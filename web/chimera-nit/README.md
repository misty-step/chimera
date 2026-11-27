# `<chimera-nit>`

One dependency-free custom element (`PRODUCT.md` §2.6). It captures the page URL, a CSS selector for the
element a nit is about, the viewport, and the text, and POSTs them to the inlet as `chimera.nit/v1`.

```html
<script src="/chimera-nit.js" defer></script>
<chimera-nit endpoint="/v1/inlet/nit"></chimera-nit>
```

| Attribute  | Default          | Meaning                                  |
|------------|------------------|------------------------------------------|
| `endpoint` | `/v1/inlet/nit`  | Where the nit is POSTed.                 |
| `label`    | `Nit`            | Text of the trigger button.              |

- **No credentials.** The element stores nothing and sends no token. The request goes out with
  `credentials: "include"`, so the browser attaches the edge session for the inlet's origin; the edge verifies
  it. Anyone without an owner session lands in the rate-limited triage inbox.
- **Strict CSP.** Works under `Content-Security-Policy: default-src 'self'`: styles are a constructed
  stylesheet adopted by the shadow root; the DOM is built with DOM calls. Serve the script from the page's
  own origin (the Go package `chimera/web/chimera-nit` embeds it as `chimeranit.Source`).
- **Use.** Activate the trigger, click the element (or press Enter for the page's `main`), write the text,
  `Send`. Escape cancels. The status reads `SENT` (a reconcile order was created), `QUEUED` (joined the Folio
  pull request or the triage inbox), or `FAILED` with the HTTP status.
- **Events.** `chimera-nit:sent` and `chimera-nit:error` bubble from the element with
  `detail: { status, body }`.
- **Size.** At most 8 KB gzipped; `go test ./web/...` enforces it.

Posted body:

```json
{"schema":"chimera.nit/v1","url":"https://app.example.com/orders","selector":"#total",
 "viewport":{"w":1440,"h":900,"dpr":2},"text":"Total should use tabular figures."}
```
