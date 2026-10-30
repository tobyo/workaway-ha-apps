// Local captive-portal agent. UniFi sends unauthorised guests here (External Portal Server); we proxy the
// portal pages from the central Worker and, when the Worker returns a signed authorisation, grant access
// on the local UniFi console. Guests only ever talk to this agent, so nothing else needs pre-auth access.
import http from "node:http";
import { readFileSync } from "node:fs";
import { signToken, verifyToken } from "./token.mjs";
import { UniFi } from "./unifi.mjs";

const config = JSON.parse(readFileSync(process.env.CONFIG_FILE ?? "/data/options.json", "utf8"));
const PORT = Number(process.env.PORT ?? 80);
const COOKIE = "obp_ctx";
const CONTEXT_MAX_AGE_S = 6 * 60 * 60;
const MAX_BODY_BYTES = 64 * 1024;
const MAC_RE = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/;

for (const key of ["property", "property_key", "worker_url", "unifi_url", "unifi_api_key"]) {
  if (!config[key]) fail(`Missing required option: ${key}`);
}
if (config.property_key.length < 32) fail("property_key must be at least 32 characters (use `openssl rand -hex 32`)");

const workerOrigin = new URL(config.worker_url).origin;
const unifi = new UniFi({
  url: config.unifi_url,
  site: config.unifi_site || "default",
  apiKey: config.unifi_api_key,
  verifyTls: Boolean(config.verify_unifi_tls),
});

function fail(message) {
  console.error(`[agent] ${message}`);
  process.exit(1);
}

const log = (...args) => console.log(new Date().toISOString(), ...args);
const now = () => Math.floor(Date.now() / 1000);

function page(res, status, title, text, link) {
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style>body{margin:0;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f4;color:#1c1917}
main{max-width:440px;margin:0 auto;padding:32px 16px}div{background:#fff;border:1px solid #d6d3d1;border-radius:16px;padding:28px 24px}h1{font-size:1.5rem;margin:0 0 8px}
a{display:block;margin-top:20px;padding:14px;border-radius:10px;background:#1c1917;color:#fff;text-align:center;text-decoration:none;font-weight:600}
@media (prefers-color-scheme:dark){body{background:#0c0a09;color:#fafaf9}div{background:#1c1917;border-color:#44403c}a{background:#fafaf9;color:#1c1917}}</style></head>
<body><main><div><h1>${esc(title)}</h1><p>${esc(text)}</p>${link ? `<a href="${esc(link.href)}">${esc(link.label)}</a>` : ""}</div></main></body></html>`);
}

function cookies(req) {
  return Object.fromEntries(
    (req.headers.cookie ?? "")
      .split(";")
      .map((c) => c.trim().split("="))
      .filter(([k, v]) => k && v)
      .map(([k, ...v]) => [k, v.join("=")]),
  );
}

function clientIp(req) {
  return (req.socket.remoteAddress ?? "").replace(/^::ffff:/, "");
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("Request body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function readContext(req) {
  const token = cookies(req)[COOKIE];
  const ctx = token && verifyToken(token, config.property_key);
  if (!ctx || ctx.property !== config.property || now() - ctx.iat > CONTEXT_MAX_AGE_S) return null;
  return { token, ctx };
}

// UniFi redirects here: /guest/s/<site>/?id=<client mac>&ap=<ap mac>&ssid=<ssid>&url=<original url>
async function handleLanding(req, res, url) {
  const mac = (url.searchParams.get("id") ?? "").toLowerCase();
  if (!MAC_RE.test(mac)) return page(res, 400, "Something went wrong", "We couldn't identify your device. Please disconnect from the WiFi and reconnect.");

  if (config.verify_client_ip) {
    // Stops someone on the guest network authorising a different device by editing ?id=.
    try {
      const client = await unifi.getClient(mac);
      if (client?.ipAddress && client.ipAddress !== clientIp(req)) {
        log(`rejected landing: ${mac} is at ${client.ipAddress}, request came from ${clientIp(req)}`);
        return page(res, 403, "Something went wrong", "Please open the sign-in page from the device you want to connect.");
      }
    } catch (err) {
      log(`client lookup failed, continuing: ${err.message}`);
    }
  }

  const ctx = {
    v: 1,
    property: config.property,
    mac,
    ap: url.searchParams.get("ap")?.toLowerCase() || undefined,
    ssid: url.searchParams.get("ssid")?.slice(0, 64) || undefined,
    url: url.searchParams.get("url")?.slice(0, 2000) || undefined,
    iat: now(),
  };
  res.writeHead(302, {
    Location: "/portal",
    "Set-Cookie": `${COOKIE}=${signToken(ctx, config.property_key)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${CONTEXT_MAX_AGE_S}`,
    "Cache-Control": "no-store",
  });
  res.end();
}

async function authorize(token, ctx) {
  const a = verifyToken(token, config.property_key);
  const valid =
    a && a.v === 1 && a.property === config.property && a.mac === ctx.mac && a.exp >= now() && Number.isInteger(a.minutes) && a.minutes > 0;
  if (!valid) throw new Error("Invalid authorisation from portal");

  await unifi.authorizeGuest({ mac: a.mac, minutes: a.minutes, down: a.down, up: a.up });
  log(`authorised ${a.mac} for ${a.minutes} min`);

  if (config.ha_event && process.env.SUPERVISOR_TOKEN) {
    fetch(`http://supervisor/core/api/events/${encodeURIComponent(config.ha_event)}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${process.env.SUPERVISOR_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ property: config.property, mac: a.mac, name: a.name, minutes: a.minutes, ap: ctx.ap ?? null }),
    }).catch((err) => log(`Home Assistant event failed: ${err.message}`));
  }
}

async function handlePortal(req, res, url) {
  const found = readContext(req);
  if (!found && url.pathname !== "/portal/terms") {
    return page(res, 400, "Let's try that again", "Your sign-in session has expired. Disconnect from the WiFi and reconnect to sign in again.");
  }

  const headers = { "X-Portal-Context": found?.token ?? "" };
  for (const h of ["accept", "accept-language", "content-type", "user-agent"]) {
    if (req.headers[h]) headers[h] = req.headers[h];
  }
  const hasBody = req.method !== "GET" && req.method !== "HEAD";

  let upstream;
  try {
    upstream = await fetch(workerOrigin + url.pathname + url.search, {
      method: req.method,
      headers,
      body: hasBody ? await readBody(req) : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    log(`portal request failed: ${err.message}`);
    return page(res, 502, "Sign-in is unavailable", "We couldn't load the sign-in page. Please try again in a minute.", { href: "/portal", label: "Try again" });
  }

  const authorization = upstream.headers.get("x-portal-authorize");
  if (authorization) {
    try {
      await authorize(authorization, found.ctx);
    } catch (err) {
      log(`authorisation failed for ${found.ctx.mac}: ${err.message}`);
      return page(res, 502, "We couldn't connect you", "Something went wrong while connecting your device. Please try again.", { href: "/portal", label: "Try again" });
    }
  }

  const out = { "Cache-Control": upstream.headers.get("cache-control") ?? "no-store" };
  const contentType = upstream.headers.get("content-type");
  if (contentType) out["Content-Type"] = contentType;
  const location = upstream.headers.get("location");
  if (location) {
    const target = new URL(location, workerOrigin);
    out.Location = target.origin === workerOrigin ? target.pathname + target.search : target.href;
  }
  const body = Buffer.from(await upstream.arrayBuffer());
  res.writeHead(upstream.status, out);
  res.end(req.method === "HEAD" ? undefined : body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://agent.local");
  try {
    if (url.pathname === "/healthz") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      return res.end("ok");
    }
    if (url.pathname.startsWith("/guest/s/")) return await handleLanding(req, res, url);
    if (url.pathname === "/portal" || url.pathname.startsWith("/portal/")) return await handlePortal(req, res, url);
    if (readContext(req)) {
      res.writeHead(302, { Location: "/portal" });
      return res.end();
    }
    page(res, 404, "Guest WiFi", "Open any website to get to the sign-in page.");
  } catch (err) {
    log(`unhandled error on ${req.method} ${url.pathname}: ${err.stack ?? err}`);
    if (!res.headersSent) page(res, 500, "Something went wrong", "Please try again.", { href: "/portal", label: "Try again" });
    else res.destroy();
  }
});

server.requestTimeout = 30_000;
server.listen(PORT, () => log(`WiFi portal agent for "${config.property}" listening on :${PORT}, portal at ${workerOrigin}`));
