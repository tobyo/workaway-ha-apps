// Same format as worker/src/token.ts: base64url(JSON payload) + "." + base64url(HMAC-SHA256(key, payload part)).
import { createHmac, timingSafeEqual } from "node:crypto";

const mac = (secret, body) => createHmac("sha256", secret).update(body).digest();

export function signToken(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${body}.${mac(secret, body).toString("base64url")}`;
}

/** Returns the payload if the signature is valid for `secret`, else null. */
export function verifyToken(token, secret) {
  const [body, sig, extra] = String(token ?? "").split(".");
  if (!body || !sig || extra !== undefined) return null;
  const expected = mac(secret, body);
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}
