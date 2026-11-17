// The web server reaches the API from a few shared Vercel addresses, so it
// names the real client in a header it signs with a key only it and the
// API hold (audit run-6). The API uses it for rate limits only.
//
//   x-nexusinbox-client: <ip>.<unix seconds>.<base64url HMAC-SHA256>

export const CLIENT_IP_HEADER = "x-nexusinbox-client";

function base64Url(bytes: ArrayBuffer): string {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The signed header value, or null without a key or an address. */
export async function signedClientIp(ip: string | null, key: string | undefined, now = Date.now()): Promise<string | null> {
  if (!ip || !key || key.length < 32) return null;
  const signed = `${ip}.${Math.floor(now / 1000)}`;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(signed));
  return `${signed}.${base64Url(mac)}`;
}

/** The client address Vercel saw (it sets these; a client's own values are replaced). */
export function vercelClientIp(headers: Headers): string | null {
  const real = headers.get("x-real-ip")?.trim();
  if (real) return real;
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded || null;
}
