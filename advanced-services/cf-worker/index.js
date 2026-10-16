// Secret-path gateway in front of a cloudflared quick tunnel.
//
//   https://<worker>/<URL_SECRET>/<route path>/<service secret>/<rest...>
//
// The Worker has no secrets of its own. Everything lives in the KV namespace
// bound as TUNNEL_KV, written by the containers:
//   CF_TUNNEL_REDIRECT  current trycloudflare URL   (cftunnel container)
//   CF_TUNNEL_CONFIG    routes + secret hashes      (proxy container, from services.ini)
//
// Secrets are stored as SHA-256 hashes, so reading KV doesn't reveal them.

const KV_URL_KEY = "CF_TUNNEL_REDIRECT";
const KV_CONFIG_KEY = "CF_TUNNEL_CONFIG";
const CACHE_MS = 30_000;

const enc = new TextEncoder();
let cache = { at: 0, tunnel: null, config: null };

const text = (body, status) => new Response(body, { status });
const notFound = () => text("Not found", 404);

async function sha256Hex(s) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  return x.byteLength === y.byteLength && crypto.subtle.timingSafeEqual(x, y);
}

async function secretMatches(given, expectedHash) {
  if (!given || typeof expectedHash !== "string") return false;
  return safeEqual(await sha256Hex(given), expectedHash);
}

async function load(env) {
  if (cache.config && cache.tunnel && Date.now() - cache.at < CACHE_MS) return cache;

  const [tunnel, config] = await Promise.all([
    env.TUNNEL_KV.get(KV_URL_KEY),
    env.TUNNEL_KV.get(KV_CONFIG_KEY, "json").catch(() => null),
  ]);
  cache = { at: Date.now(), tunnel: tunnel?.trim() || null, config };
  return cache;
}

// Longest route whose path segments are a prefix of the request's segments.
function findRoute(routes, segments) {
  let best = null;
  for (const r of routes) {
    const segs = r.path.split("/").slice(1);
    if (segs.length <= (best?.segs.length ?? 0)) continue;
    if (segs.every((s, i) => segments[i] === s)) best = { ...r, segs };
  }
  return best;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { tunnel, config } = await load(env);

    if (
      !config || config.v !== 1 || !Array.isArray(config.routes) ||
      typeof config.tunnel_secret !== "string"
    ) {
      return text("Not configured", 503);
    }

    // /<url secret>/<route path...>/<service secret>/<rest...>
    const [urlSecret, ...tail] = url.pathname.split("/").slice(1);
    if (!(await secretMatches(urlSecret, config.url_secret_sha256))) return notFound();

    const route = findRoute(config.routes, tail);
    if (!route) return notFound();

    let rest = tail.slice(route.segs.length);
    if (route.secret_sha256) {
      if (!(await secretMatches(rest[0], route.secret_sha256))) return notFound();
      rest = rest.slice(1);
    }

    if (!tunnel) return text("Tunnel offline", 502);

    // Secrets are stripped: the backend only sees <route path>/<rest>.
    const target = new URL(tunnel);
    target.pathname = route.path + (rest.length ? "/" + rest.join("/") : "");
    target.search = url.search;

    const headers = new Headers(request.headers);
    headers.set("X-Tunnel-Secret", config.tunnel_secret);
    headers.set("X-Client-IP", request.headers.get("CF-Connecting-IP") ?? "");
    headers.set("X-Forwarded-Host", url.host);

    try {
      const res = await fetch(
        new Request(target, {
          method: request.method,
          headers,
          body: request.body,
          redirect: "manual",
        }),
      );
      if (res.status === 530) cache.at = 0; // tunnel gone: re-read its URL next time
      return res;
    } catch {
      cache.at = 0;
      return text("Upstream error", 502);
    }
  },
};
