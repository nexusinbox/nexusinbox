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

// ---------------------------------------------------------------------------
// Deciding whom to wrap for (docs/40 §12.3). Senders check the recipient's
// list against the root they remember and wrap only for devices it names
// that the server still returns: the server can take devices away, but
// cannot add one or swap a key.

/** What a sender remembers of an agent: its root and the newest list version seen. */
export type DevicePin = { root: string; version: number };

/** The part of a resolved agent (`GET /recipients/resolve`) the decision reads. */
export type ServedAgent = {
  aid: string;
  /** The device `encrypted_key` used to be wrapped for (the newest one). */
  did: string;
  encryption_public_key: string;
  devices?: Array<{ did: string; encryption_public_key: string }> | null;
  device_list?: { version: number; jws: string } | null;
};

export type WrapTarget = { did: string; encryption_public_key: string };

/**
 * Why a send stops:
 *  - root_changed: the list is signed by a root other than the remembered one;
 *  - signature: it does not verify, or is for another agent than the one asked for
 *    (an AID asked for, or the agent a DID asked for was seen under before);
 *  - rollback: it is older than one seen before;
 *  - removed: there was a list before and now there is none;
 *  - no_device: none of the listed devices is still active.
 */
export type StopReason = "root_changed" | "signature" | "rollback" | "removed" | "no_device";

export type WrapDecision =
  /** Checked: wrap for `targets`; `single` is the one `encrypted_key` goes to. */
  | { kind: "listed"; list: DeviceListPayload; targets: WrapTarget[]; single: WrapTarget }
  /** The agent has no list yet (and none was seen): wrap as the server says. */
  | { kind: "unlisted"; targets: WrapTarget[]; single: WrapTarget }
  | { kind: "stop"; reason: StopReason; root?: string };

function listRoot(jws: string): string | null {
  const headerBytes = fromBase64Url(jws.split(".")[0] ?? "");
  if (!headerBytes) return null;
  try {
    const kid = JSON.parse(decoder.decode(headerBytes)).kid;
    return typeof kid === "string" ? kid : null;
  } catch {
    return null;
  }
}

/**
 * Decide which devices of `served` to wrap a message's key for.
 * `requested` is what the sender asked to resolve (an AID or a DID);
 * `knownAid` the agent a requested DID was seen under before, if any;
 * `pin` what it remembers of this agent; `acceptRoot` a new root the
 * person has just accepted (§12.5).
 */
export async function decideWrapTargets(input: {
  served: ServedAgent;
  requested: string;
  knownAid?: string | null;
  pin: DevicePin | null;
  acceptRoot?: string;
}): Promise<WrapDecision> {
  const { served, requested, pin } = input;
  // A DID belongs to one agent for good: the server may not move it.
  if (requested.startsWith("aid:") && requested !== served.aid) return { kind: "stop", reason: "signature" };
  if (input.knownAid && input.knownAid !== served.aid) return { kind: "stop", reason: "signature" };
  const active = served.devices && served.devices.length > 0
    ? served.devices
    : [{ did: served.did, encryption_public_key: served.encryption_public_key }];

  const ref = served.device_list;
  if (!ref) {
    if (pin) return { kind: "stop", reason: "removed" };
    const targets = active.filter((d) => d.encryption_public_key);
    return {
      kind: "unlisted",
      targets,
      single: { did: served.did, encryption_public_key: served.encryption_public_key },
    };
  }

  const root = listRoot(ref.jws);
  const list = root ? await verifyDeviceList(ref.jws, { aid: served.aid, root }) : null;
  if (!list || list.version !== ref.version) return { kind: "stop", reason: "signature" };

  if (pin && pin.root !== list.root) {
    if (input.acceptRoot !== list.root) return { kind: "stop", reason: "root_changed", root: list.root };
  } else if (pin && list.version < pin.version) {
    return { kind: "stop", reason: "rollback" };
  }

  const activeDids = new Set(active.map((d) => d.did));
  const targets = list.devices
    .filter((d) => activeDids.has(d.did))
    .map((d) => ({ did: d.did, encryption_public_key: d.enc }));
  if (targets.length === 0) return { kind: "stop", reason: "no_device" };
  const single =
    targets.find((d) => d.did === served.did) ?? targets.find((d) => d.did === list.root) ?? targets[0];
  return { kind: "listed", list, targets, single };
}

/** What to remember after a decision (the pin only moves forward). */
export function pinAfter(pin: DevicePin | null, decision: WrapDecision): DevicePin | null {
  if (decision.kind !== "listed") return pin;
  const { root, version } = decision.list;
  if (pin && pin.root === root) return { root, version: Math.max(pin.version, version) };
  return { root, version };
}
