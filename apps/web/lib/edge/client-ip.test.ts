import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signedClientIp, vercelClientIp } from "./client-ip";

const KEY = "0123456789abcdef0123456789abcdef";

describe("signed client address (audit run-6)", () => {
  it("signs <ip>.<seconds> with HMAC-SHA256 as the API checks it", async () => {
    const value = await signedClientIp("203.0.113.9", KEY, 1_800_000_000_000);
    expect(value).not.toBeNull();
    const [ip, ts, mac] = value!.split(/\.(?=[^.]+\.[^.]+$)|\.(?=[^.]+$)/);
    expect(`${ip}.${ts}`).toBe("203.0.113.9.1800000000");
    const expected = createHmac("sha256", KEY).update("203.0.113.9.1800000000").digest("base64url");
    expect(mac).toBe(expected);
  });

  it("signs nothing without a key, a long enough key, or an address", async () => {
    expect(await signedClientIp("203.0.113.9", undefined)).toBeNull();
    expect(await signedClientIp("203.0.113.9", "short")).toBeNull();
    expect(await signedClientIp(null, KEY)).toBeNull();
  });

  it("takes the address Vercel saw", () => {
    expect(vercelClientIp(new Headers({ "x-real-ip": "203.0.113.9", "x-forwarded-for": "198.51.100.1" }))).toBe(
      "203.0.113.9",
    );
    expect(vercelClientIp(new Headers({ "x-forwarded-for": "198.51.100.1, 10.0.0.1" }))).toBe("198.51.100.1");
    expect(vercelClientIp(new Headers())).toBeNull();
  });
});
