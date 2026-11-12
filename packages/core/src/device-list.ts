/**
 * Signed device lists (docs/40 §4.2), browser-safe.
 *
 * An agent's root key (the browser key it was created with, the agent's
 * DID) signs the whole list of devices that may read the agent's
 * messages: each device's DID and the X25519 key senders wrap for. The
 * server stores and returns the list but cannot sign one, so a client
 * that checks the list against the root it trusts wraps only for
 * devices the person approved.
 *
 * Format: compact JWS, header {"alg":"EdDSA","typ":DEVICE_LIST_TYP,
 * "kid":<root DID>}, payload DeviceListPayload. The server checks the
 * same things in services/api verify_device_list_jws.
 *
 * Kept free of runtime imports so the Web UI can import it without the
 * Node-only API client.
 */

export const DEVICE_LIST_TYP = "nexusinbox-device-list";

/** Most devices one list may name (matches the server's wrap limit). */
export const MAX_LIST_DEVICES = 10;

export type DeviceListKind = "browser" | "computer" | "other";

export type DeviceListDevice = {
  did: string;
  /** The device's X25519 public key as the server returns it. */
  enc: string;
  kind: DeviceListKind;
};

export type DeviceListPayload = {
  v: 1;
  aid: string;
  root: string;
  version: number;
  issued_at: string;
  devices: DeviceListDevice[];
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(value: string): Uint8Array | null {
  // Little-endian digits of the number, base 256.
  const bytes: number[] = [];
  for (const char of value) {
    let carry = BASE58.indexOf(char);
    if (carry < 0) return null;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[out.length - 1 - i] = bytes[i];
  return out;
}

/** The Ed25519 public key inside a did:key, or null if it is not one. */
export function ed25519KeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith("did:key:z")) return null;
  const decoded = base58Decode(did.slice("did:key:z".length));
  if (!decoded || decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.slice(2);
}

/** Sign a device list with the root's private key (Ed25519). */
export async function signDeviceList(
  rootPrivateKey: CryptoKey,
  payload: DeviceListPayload,
): Promise<string> {
  const header = { alg: "EdDSA", typ: DEVICE_LIST_TYP, kid: payload.root };
  const input = `${toBase64Url(encoder.encode(JSON.stringify(header)))}.${toBase64Url(
    encoder.encode(JSON.stringify(payload)),
  )}`;
  const signature = await crypto.subtle.sign("Ed25519", rootPrivateKey, asArrayBuffer(encoder.encode(input)));
  return `${input}.${toBase64Url(new Uint8Array(signature))}`;
}

function isDevice(value: unknown): value is DeviceListDevice {
  if (!value || typeof value !== "object") return false;
  const d = value as Record<string, unknown>;
  return (
    Object.keys(d).length === 3 &&
    typeof d.did === "string" &&
    d.did.startsWith("did:key:z") &&
    typeof d.enc === "string" &&
    d.enc.length > 0 &&
    (d.kind === "browser" || d.kind === "computer" || d.kind === "other")
  );
}

/**
 * Check a signed device list against the agent and the root the caller
 * trusts. Returns the list, or null if anything does not hold: the
 * header, the signature by `root`, the agent, the shape, or a DID named
 * twice. Version ordering is the caller's check.
 */
export async function verifyDeviceList(
  jws: string,
  expected: { aid: string; root: string },
): Promise<DeviceListPayload | null> {
  const parts = jws.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    const headerBytes = fromBase64Url(headerB64);
    const payloadBytes = fromBase64Url(payloadB64);
    if (!headerBytes || !payloadBytes) return null;
    header = JSON.parse(decoder.decode(headerBytes));
    payload = JSON.parse(decoder.decode(payloadBytes));
  } catch {
    return null;
  }
  if (header.alg !== "EdDSA" || header.typ !== DEVICE_LIST_TYP || header.kid !== expected.root) return null;

  const rootKey = ed25519KeyFromDidKey(expected.root);
  const signature = fromBase64Url(signatureB64);
  if (!rootKey || !signature || signature.length !== 64) return null;
  let valid = false;
  try {
    const key = await crypto.subtle.importKey("raw", asArrayBuffer(rootKey), { name: "Ed25519" }, false, ["verify"]);
    valid = await crypto.subtle.verify(
      "Ed25519",
      key,
      asArrayBuffer(signature),
      asArrayBuffer(encoder.encode(`${headerB64}.${payloadB64}`)),
    );
  } catch {
    return null;
  }
  if (!valid) return null;

  if (
    Object.keys(payload).length !== 6 ||
    payload.v !== 1 ||
    payload.aid !== expected.aid ||
    payload.root !== expected.root ||
    typeof payload.version !== "number" ||
    !Number.isSafeInteger(payload.version) ||
    payload.version < 1 ||
    typeof payload.issued_at !== "string" ||
    !Array.isArray(payload.devices) ||
    payload.devices.length < 1 ||
    payload.devices.length > MAX_LIST_DEVICES ||
    !payload.devices.every(isDevice)
  ) {
    return null;
  }
  const devices = payload.devices as DeviceListDevice[];
  if (new Set(devices.map((d) => d.did)).size !== devices.length) return null;
  return payload as unknown as DeviceListPayload;
}

/** Read a list's version without checking it (to pick the next one). */
export function deviceListVersion(jws: string): number | null {
  const payloadBytes = fromBase64Url(jws.split(".")[1] ?? "");
  if (!payloadBytes) return null;
  try {
    const version = JSON.parse(decoder.decode(payloadBytes)).version;
    return Number.isSafeInteger(version) && version > 0 ? version : null;
  } catch {
    return null;
  }
}
