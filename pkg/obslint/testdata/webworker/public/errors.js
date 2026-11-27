// Browser error capture with no external dependency: scrub, then send to the
// same-origin beacon the worker forwards.
(function () {
  const BEACON = "/api/client-errors";
  function scrub(text) {
    return String(text || "").replace(/[?#].*$/, "").slice(0, 2048);
  }
  function send(kind, detail) {
    const body = JSON.stringify({ kind, page: scrub(location.href), detail: scrub(detail) });
    if (!navigator.sendBeacon("/api/client-errors", body)) {
      fetch(BEACON, { method: "POST", body, keepalive: true });
    }
  }
  window.addEventListener("error", (e) => send("error", e.message));
  window.addEventListener("unhandledrejection", (e) => send("unhandledrejection", e.reason));
  document.addEventListener("securitypolicyviolation", (e) => send("csp", e.violatedDirective + " " + e.blockedURI));
})();
