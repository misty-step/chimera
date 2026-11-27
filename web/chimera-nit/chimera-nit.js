/* <chimera-nit> — one dependency-free custom element (PRODUCT.md §2.6).
 *
 * It captures four things about a piece of feedback — the page URL, a CSS
 * selector for the element it is about, the viewport, and the text — and
 * POSTs them to the inlet. It holds no credentials: the request is sent with
 * the browser's own session for the inlet's origin, which the edge verifies.
 *
 * Attributes: endpoint (default "/v1/inlet/nit"), label (default "Nit").
 * Events (bubbling, composed): "chimera-nit:sent", "chimera-nit:error";
 * detail is { status, body }.
 *
 * Runs under Content-Security-Policy: default-src 'self' — styles are a
 * constructed stylesheet adopted by the shadow root, and the DOM is built
 * with DOM calls only.
 */
(() => {
  const TAG = "chimera-nit";
  if (typeof customElements === "undefined" || customElements.get(TAG)) return;

  const RULES = `
:host {
  --paper: #F6F5F2; --ink: #16171A; --muted: #5B5E66; --rule: #D8D5CE; --accent: #1F45C8;
  --sans: "IBM Plex Sans", ui-sans-serif, system-ui, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
  position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
  display: block; max-width: calc(100vw - 32px);
  font: 400 14px/1.5 var(--sans); color: var(--ink); font-variant-numeric: tabular-nums;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :host { --paper: #101114; --ink: #ECEAE4; --muted: #9A9DA4; --rule: #2A2C31; --accent: #7C9BFF; }
}
:host([hidden]) { display: none; }
* { box-sizing: border-box; }
[hidden] { display: none !important; }
button, textarea { font: inherit; color: inherit; border-radius: 2px; }
button { background: var(--paper); border: 1px solid var(--rule); padding: 4px 12px; cursor: pointer; }
button:hover { border-color: var(--ink); }
button:disabled { color: var(--muted); cursor: default; border-color: var(--rule); }
button:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.bar { position: relative; display: flex; gap: 8px; align-items: center; justify-content: flex-end; }
.trigger { font: 600 12px/1.5 var(--mono); text-transform: uppercase; letter-spacing: 0.06em; }
.status { margin: 0; font: 400 12px/1.5 var(--mono); letter-spacing: 0.06em; color: var(--muted); }
.status.fail { color: var(--accent); font-weight: 600; }
.veil { position: fixed; inset: 0; cursor: crosshair; }
.box { position: fixed; border: 2px solid var(--accent); pointer-events: none; }
.panel { position: relative; width: 320px; max-width: 100%; margin: 0 0 8px; padding: 16px; background: var(--paper); border: 1px solid var(--rule); border-radius: 2px; }
.panel label, .panel dt { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.panel dl { margin: 0 0 8px; }
.panel dd { margin: 0; font: 400 12px/1.5 var(--mono); overflow-wrap: anywhere; max-height: 4.5em; overflow: auto; }
textarea { display: block; width: 100%; min-height: 96px; margin: 4px 0 8px; padding: 8px; background: var(--paper); border: 1px solid var(--rule); resize: vertical; }
.send { border-color: var(--accent); color: var(--accent); font-weight: 600; }
.hint { position: fixed; left: 16px; bottom: 16px; margin: 0; padding: 4px 8px; background: var(--paper); border: 1px solid var(--rule); border-radius: 2px; font: 400 12px/1.5 var(--mono); color: var(--muted); max-width: calc(100vw - 32px); pointer-events: none; }
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
`;

  // h("tag", {prop: value}, ...children): DOM calls only, never markup strings.
  const h = (tag, props, ...kids) => {
    const n = document.createElement(tag);
    for (const k in props) {
      if (k in n) n[k] = props[k];
      else n.setAttribute(k, props[k]);
    }
    n.append(...kids);
    return n;
  };

  // A selector that finds the element again: the nearest unique id, then a
  // path of tag:nth-of-type(n) steps below it (or below html).
  const selectorOf = (node) => {
    const path = [];
    for (let n = node; n && n.nodeType === 1 && n !== document.documentElement; n = n.parentElement) {
      if (n.id) {
        const id = "#" + CSS.escape(n.id);
        if (document.querySelectorAll(id).length === 1) {
          path.unshift(id);
          return path.join(" > ");
        }
      }
      let i = 1;
      for (let s = n.previousElementSibling; s; s = s.previousElementSibling) {
        if (s.localName === n.localName) i++;
      }
      path.unshift(CSS.escape(n.localName) + ":nth-of-type(" + i + ")");
    }
    path.unshift("html");
    return path.join(" > ");
  };

  class ChimeraNit extends HTMLElement {
    static get observedAttributes() {
      return ["label"];
    }

    constructor() {
      super();
      const root = this.attachShadow({ mode: "open" });
      try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(RULES);
        root.adoptedStyleSheets = [sheet];
      } catch (e) {
        /* No constructed stylesheets: the element still works, unstyled. */
      }
      this.target = null;
      this.selector = "";
      this.trigger = h("button", { type: "button", className: "trigger", part: "trigger" });
      this.status = h("p", { className: "status", role: "status" });
      this.status.setAttribute("aria-live", "polite");
      this.box = h("div", { className: "box", hidden: true });
      this.veil = h("div", { className: "veil", hidden: true });
      this.hint = h("p", { className: "hint", hidden: true }, "Element: click, or Enter. Escape cancels.");
      this.where = h("dd", {});
      this.text = h("textarea", { id: "t", name: "text", maxLength: 4000, required: true });
      this.send = h("button", { type: "submit", className: "send", disabled: true }, "Send");
      this.cancel = h("button", { type: "button" }, "Cancel");
      this.panel = h(
        "form",
        { className: "panel", hidden: true, noValidate: true },
        h("dl", {}, h("dt", {}, "Selector"), this.where),
        h("label", { htmlFor: "t" }, "Text"),
        this.text,
        h("div", { className: "bar" }, this.cancel, this.send)
      );
      this.panel.setAttribute("aria-label", "Nit");
      root.append(this.veil, this.box, this.hint, this.panel, h("div", { className: "bar" }, this.status, this.trigger));

      this.trigger.addEventListener("click", () => (this.picking || !this.panel.hidden ? this.close() : this.pick()));
      this.cancel.addEventListener("click", () => this.close());
      this.text.addEventListener("input", () => (this.send.disabled = !this.text.value.trim()));
      this.panel.addEventListener("submit", (e) => {
        e.preventDefault();
        this.submit();
      });
      this.veil.addEventListener("pointermove", (e) => this.hover(e.clientX, e.clientY));
      this.veil.addEventListener("click", (e) => {
        this.hover(e.clientX, e.clientY);
        this.choose();
      });
      this.onKey = (e) => {
        if (e.key === "Escape" && (this.picking || !this.panel.hidden)) {
          e.preventDefault();
          this.close();
        } else if (e.key === "Enter" && this.picking) {
          e.preventDefault();
          this.choose();
        }
      };
    }

    connectedCallback() {
      this.trigger.textContent = this.getAttribute("label") || "Nit";
      document.addEventListener("keydown", this.onKey, true);
    }

    disconnectedCallback() {
      document.removeEventListener("keydown", this.onKey, true);
    }

    attributeChangedCallback() {
      this.trigger.textContent = this.getAttribute("label") || "Nit";
    }

    get picking() {
      return !this.veil.hidden;
    }

    // Pick mode: a veil takes the pointer; the element under it is outlined.
    pick() {
      this.say("");
      this.target = null;
      this.veil.hidden = this.hint.hidden = false;
      this.trigger.setAttribute("aria-pressed", "true");
    }

    hover(x, y) {
      const under = document.elementsFromPoint(x, y).find((n) => n !== this && !this.contains(n));
      if (!under) return;
      this.target = under;
      const r = under.getBoundingClientRect();
      const s = this.box.style;
      s.left = r.left + "px";
      s.top = r.top + "px";
      s.width = r.width + "px";
      s.height = r.height + "px";
      this.box.hidden = false;
    }

    choose() {
      const node = this.target || document.querySelector("main") || document.body;
      this.selector = selectorOf(node);
      this.veil.hidden = this.hint.hidden = true;
      this.where.textContent = this.selector;
      this.panel.hidden = false;
      this.text.focus();
    }

    close() {
      this.veil.hidden = this.hint.hidden = this.box.hidden = this.panel.hidden = true;
      this.trigger.removeAttribute("aria-pressed");
      this.trigger.focus();
    }

    say(word, failed) {
      this.status.textContent = word;
      this.status.classList.toggle("fail", !!failed);
    }

    async submit() {
      const text = this.text.value.trim();
      if (!text || this.send.disabled) return;
      this.send.disabled = true;
      this.say("SENDING");
      const nit = {
        schema: "chimera.nit/v1",
        url: location.href,
        selector: this.selector,
        viewport: { w: innerWidth, h: innerHeight, dpr: devicePixelRatio || 1 },
        text,
      };
      let status = 0;
      let body = {};
      try {
        const res = await fetch(this.getAttribute("endpoint") || "/v1/inlet/nit", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(nit),
        });
        status = res.status;
        body = await res.json().catch(() => ({}));
      } catch (e) {
        /* status stays 0: the request never completed */
      }
      const ok = status === 201 || status === 202;
      const detail = { status, body };
      if (ok) {
        this.text.value = "";
        this.close();
        this.say(status === 201 ? "SENT" : "QUEUED");
      } else {
        this.send.disabled = false;
        this.say(status ? "FAILED " + status : "FAILED", true);
      }
      this.dispatchEvent(new CustomEvent(ok ? "chimera-nit:sent" : "chimera-nit:error", { bubbles: true, composed: true, detail }));
    }
  }

  customElements.define(TAG, ChimeraNit);
})();
