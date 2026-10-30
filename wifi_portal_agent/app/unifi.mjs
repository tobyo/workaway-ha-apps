// Minimal client for the official UniFi Network API (API key) on a UniFi OS console.
import http from "node:http";
import https from "node:https";

const API_PREFIX = "/proxy/network/integration/v1";

export class UniFi {
  constructor({ url, site, apiKey, verifyTls }) {
    this.base = new URL(url);
    this.site = site;
    this.apiKey = apiKey;
    this.agent = this.base.protocol === "https:" ? new https.Agent({ rejectUnauthorized: verifyTls, keepAlive: true }) : undefined;
    this.siteLookup = null;
  }

  #api(method, path, body) {
    const url = new URL(API_PREFIX + path, this.base);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers = { Accept: "application/json", "X-API-Key": this.apiKey };
    if (payload) headers["Content-Type"] = "application/json";
    const lib = url.protocol === "https:" ? https : http;
    return new Promise((resolve, reject) => {
      const req = lib.request(url, { method, headers, agent: this.agent, timeout: 10_000 }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch {}
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`UniFi ${method} ${url.pathname} failed (HTTP ${res.statusCode}): ${json?.message ?? json?.statusName ?? "unknown error"}`));
          } else resolve(json);
        });
      });
      req.on("timeout", () => req.destroy(new Error(`UniFi request timed out: ${method} ${url.pathname}`)));
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  /** The API addresses sites by UUID, so resolve the configured name (e.g. "default") once. */
  #siteId() {
    this.siteLookup ??= this.#api("GET", "/sites?limit=200")
      .then(({ data }) => {
        const site = data.find((s) => s.internalReference === this.site);
        if (!site) throw new Error(`UniFi site "${this.site}" not found (available: ${data.map((s) => s.internalReference).join(", ") || "none"})`);
        return site.id;
      })
      .catch((err) => {
        this.siteLookup = null;
        throw err;
      });
    return this.siteLookup;
  }

  /** Returns UniFi's view of a connected client, or null if it isn't connected. */
  async getClient(mac) {
    const filter = encodeURIComponent(`macAddress.eq('${mac}')`);
    const { data } = await this.#api("GET", `/sites/${await this.#siteId()}/clients?filter=${filter}`);
    return data[0] ?? null;
  }

  /** Grants a guest device internet access for `minutes`. Bandwidth limits are in Kbps. */
  async authorizeGuest({ mac, minutes, down, up }) {
    const client = await this.getClient(mac);
    if (!client) throw new Error(`UniFi has no connected client with MAC ${mac}`);
    const body = { action: "AUTHORIZE_GUEST_ACCESS", timeLimitMinutes: minutes };
    if (down) body.rxRateLimitKbps = down;
    if (up) body.txRateLimitKbps = up;
    await this.#api("POST", `/sites/${await this.#siteId()}/clients/${client.id}/actions`, body);
  }
}
