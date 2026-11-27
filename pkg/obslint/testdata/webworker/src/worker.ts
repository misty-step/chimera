// The same-origin beacon pattern: the browser posts scrubbed events to
// /api/client-errors on its own origin (allowed by connect-src 'self'), and the
// worker forwards them to the operator's sink as an envelope. The sink's DSN
// comes from the runtime env only.

interface Env {
  ENVIRONMENT: string;
  RELEASE: string;
  SENTRY_DSN?: string;
}

const MAX_EVENT_BYTES = 16 * 1024;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/health") {
        return Response.json({ status: "ok", environment: env.ENVIRONMENT, release: env.RELEASE });
      }
      if (url.pathname === "/api/client-errors" && request.method === "POST") {
        const body = (await request.text()).slice(0, MAX_EVENT_BYTES);
        ctx.waitUntil(forward(env, "client", body));
        return new Response(null, { status: 204 });
      }
      return new Response("not found", { status: 404 });
    } catch (err) {
      ctx.waitUntil(forward(env, "server", String(err)));
      return new Response("internal error", { status: 500 });
    }
  },
};

async function forward(env: Env, source: string, message: string): Promise<void> {
  const dsn = env.SENTRY_DSN;
  if (!dsn) return;
  const u = new URL(dsn);
  const project = u.pathname.replace(/\//g, "");
  const endpoint = `${u.protocol}//${u.host}/api/${project}/envelope/`;
  const event = { level: "error", environment: env.ENVIRONMENT, release: env.RELEASE, tags: { source }, message };
  const envelope = JSON.stringify({ dsn }) + "\n" + JSON.stringify({ type: "event" }) + "\n" + JSON.stringify(event);
  await fetch(endpoint, { method: "POST", body: envelope });
}
