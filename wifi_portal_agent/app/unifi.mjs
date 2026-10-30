// Minimal client for the UniFi Network API on a UniFi OS console (UDM, UCG, UDR, Cloud Key Gen2+).
import http from "node:http";
import https from "node:https";

export class UniFi {
  constructor({ url, site, username, password, verifyTls }) {
    this.base = new URL(url);
    this.site = site;
    this.username = username;
    this.password = password;
    this.agent = this.base.protocol === "https:" ? new https.Agent({ rejectUnauthorized: verifyTls, keepAlive: true }) : undefined;
    this.cookie = null;
    this.csrf = null;
    this.loggingIn = null;
  }

  #send(method, path, body) {
    const url = new URL(path, this.base);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers = { Accept: "application/json" };
    if (payload) headers["Content-Type"] = "application/json";
    if (this.cookie) headers.Cookie = this.cookie;
    if (this.csrf) headers["X-CSRF-Token"] = this.csrf;
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
          const csrf = res.headers["x-updated-csrf-token"] ?? res.headers["x-csrf-token"];
          if (csrf) this.csrf = csrf;
          resolve({ status: res.statusCode, headers: res.headers, json });
        });
      });
      req.on("timeout", () => req.destroy(new Error(`UniFi request timed out: ${method} ${path}`)));
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  async login() {
    // Share one in-flight login between concurrent requests; UniFi OS rate-limits logins.
    this.loggingIn ??= (async () => {
      this.cookie = null;
      this.csrf = null;
      const res = await this.#send("POST", "/api/auth/login", { username: this.username, password: this.password, rememberMe: true });
      if (res.status !== 200) throw new Error(`UniFi login failed (HTTP ${res.status})`);
      const setCookie = [].concat(res.headers["set-cookie"] ?? []);
      const token = setCookie.map((c) => c.split(";")[0]).find((c) => c.startsWith("TOKEN="));
      if (!token) throw new Error("UniFi login returned no TOKEN cookie");
      this.cookie = token;
    })().finally(() => {
      this.loggingIn = null;
    });
    return this.loggingIn;
  }

  async #api(method, path, body) {
    if (!this.cookie) await this.login();
    let res = await this.#send(method, path, body);
    if (res.status === 401) {
      await this.login();
      res = await this.#send(method, path, body);
    }
    if (res.status < 200 || res.status >= 300 || res.json?.meta?.rc !== "ok") {
      throw new Error(`UniFi ${method} ${path} failed (HTTP ${res.status}): ${res.json?.meta?.msg ?? "unknown error"}`);
    }
    return res.json.data ?? [];
  }

  /** Grants a guest device internet access for `minutes`. Bandwidth limits are in Kbps. */
  async authorizeGuest({ mac, minutes, down, up, ap }) {
    const body = { cmd: "authorize-guest", mac, minutes };
    if (down) body.down = down;
    if (up) body.up = up;
    if (ap) body.ap_mac = ap;
    await this.#api("POST", `/proxy/network/api/s/${encodeURIComponent(this.site)}/cmd/stamgr`, body);
  }

  /** Returns UniFi's view of a connected client, or null if it isn't connected. */
  async getClient(mac) {
    const [client] = await this.#api("GET", `/proxy/network/api/s/${encodeURIComponent(this.site)}/stat/sta/${encodeURIComponent(mac)}`);
    return client ?? null;
  }
}
