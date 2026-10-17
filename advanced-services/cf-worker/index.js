// Secret-path gateway in front of a cloudflared quick tunnel.
//
//   https://<worker>/<URL_SECRET>.<SERVICE_SECRET>/<service path...>
//   https://<worker>/<URL_SECRET>/<service path...>     (service without a secret)
//
// What the Worker does, in order:
//   1. Splits the first path segment into <URL_SECRET>.<SERVICE_SECRET>
//      ("." is not allowed in either secret, so the split is unambiguous).
//   2. Checks the URL secret against the Secrets Store. Wrong or missing ->
//      401 with a message, before the tunnel or nginx is ever bothered.
//      This is the gate that stops scanners/fake traffic at the edge.
//   3. Reads the current trycloudflare URL from KV (the cftunnel container
//      republishes it there on every tunnel restart) and forwards the
//      request there as /<service path...>, with:
//        X-Tunnel-Secret   = PROXY_TUNNEL_SECRET   (nginx 444s anything without
//                                                   it: direct hits on the raw
//                                                   trycloudflare URL die there)
//        X-Service-Secret  = <SERVICE_SECRET>      (nginx checks it per service)
//      Both secrets come from the Secrets Store too. Neither ever appears in
//      a path, query or access log past this point; nginx strips both headers
//      before proxying to the actual service.
//
// Bindings (provisioned by deploy.sh, which also fills the store):
//   URL_SECRET, PROXY_TUNNEL_SECRET   Secrets Store secrets
//                                     (plain Worker secrets also work - readSecret())
//   TUNNEL_KV                         KV namespace holding CF_TUNNEL_REDIRECT

const KV_URL_KEY = "CF_TUNNEL_REDIRECT";
const SEPARATOR = "."; // joins the two secrets; clients never percent-encode it
const CACHE_MS = 60_000;

const enc = new TextEncoder();
let cache = { at: 0, urlSecret: null, tunnelSecret: null, tunnelUrl: null, urlAt: 0 };

const text = (body, status) =>
  new Response(body + "\n", { status, headers: { "content-type": "text/plain; charset=utf-8" } });

const unauthorized = () => text("401 Unauthorized: missing or invalid access secret.", 401);

// Secrets Store bindings expose an async .get(); plain Worker secrets are strings.
async function readSecret(binding) {
  if (typeof binding === "string") return binding.length ? binding : null;
  if (binding && typeof binding.get === "function") {
    try {
      const v = await binding.get();
      return typeof v === "string" && v.length ? v : null;
    } catch {
      return null; // store unreachable -> report "not configured", not a 500
    }
  }
  return null;
}

async function loadSecrets(env) {
  if (cache.urlSecret && cache.tunnelSecret && Date.now() - cache.at < CACHE_MS) return cache;
  const [urlSecret, tunnelSecret] = await Promise.all([
    readSecret(env.URL_SECRET),
    readSecret(env.PROXY_TUNNEL_SECRET),
  ]);
  cache.urlSecret = urlSecret;
  cache.tunnelSecret = tunnelSecret;
  cache.at = Date.now();
  return cache;
}

// Hash both sides first so the comparison is constant-time AND length-independent.
async function secretsEqual(given, expected) {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

async function loadTunnelUrl(env) {
  if (cache.tunnelUrl && Date.now() - cache.urlAt < CACHE_MS) return cache.tunnelUrl;
  const v = (await env.personal.get(KV_URL_KEY))?.trim() || null;
  cache.tunnelUrl = v;
  cache.urlAt = Date.now();
  return v;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // /<token>/<service path...>   with token = <URL_SECRET>[.<SERVICE_SECRET>]
    const [token = "", ...pathSegs] = url.pathname.split("/").slice(1);
    let givenUrlSecret = token,
      serviceSecret = "";
    const i = token.indexOf(SEPARATOR);
    if (i !== -1) {
      givenUrlSecret = token.slice(0, i);
      serviceSecret = token.slice(i + 1);
    }

    const { urlSecret, tunnelSecret } = await loadSecrets(env);
    if (!urlSecret || !tunnelSecret) return text("503 Worker secrets are not configured.", 503);

    // 1. The gate. Everything below only runs for callers who know the URL secret.
    if (!givenUrlSecret || !(await secretsEqual(givenUrlSecret, urlSecret))) {
      return unauthorized();
    }

    if (pathSegs.length === 0 || pathSegs[0] === "") return text("404 No service path.", 404);

    // 2. Where is the tunnel right now?
    const tunnelUrl = await loadTunnelUrl(env);
    if (!tunnelUrl) return text("502 Tunnel offline.", 502);

    // 3. Forward. Client-supplied copies of our headers are overwritten, never trusted.
    const target = new URL(tunnelUrl);
    target.pathname = "/" + pathSegs.join("/");
    target.search = url.search;

    const headers = new Headers(request.headers);
    headers.set("Host", target.hostname); // the edge routes the subrequest by tunnel host
    headers.set("X-Tunnel-Secret", tunnelSecret);
    if (serviceSecret) headers.set("X-Service-Secret", serviceSecret);
    else headers.delete("X-Service-Secret");
    headers.set("X-Client-IP", request.headers.get("CF-Connecting-IP") ?? "");
    headers.set("X-Forwarded-Host", url.host);
    headers.set("X-Forwarded-Proto", "https");

    try {
      const res = await fetch(
        new Request(target, {
          method: request.method,
          headers,
          body: request.body,
          redirect: "manual",
        }),
      );
      if (res.status === 530) cache.urlAt = 0; // tunnel gone: re-read its URL next time
      return res;
    } catch {
      cache.urlAt = 0;
      return text("502 Upstream error.", 502);
    }
  },
};
