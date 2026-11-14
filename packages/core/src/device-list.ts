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
 * "kid":<signer DID>}, payload DeviceListPayload. The server checks the
 * same things in services/api verify_device_list_jws.
 *
 * Signers (docs/40 §17.3): a v1 list is signed by the root. A v2 list
 * names `signers` (browsers among its devices), and version N is signed
 * by one of the signers of version N-1, so a reader follows the versions
 * from the one it remembers (or from version 1, which the root signs).
 * The root stays the agent's identity even after its device is removed.
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
  v: 1 | 2;
  aid: string;
  root: string;
  version: number;
  issued_at: string;
  devices: DeviceListDevice[];
  /** v2 only: the devices that may sign the next version. */
  signers?: string[];
};

/** Who may sign the version after this one (a v1 list: its root). */
export function listSigners(list: DeviceListPayload): string[] {
  return list.v === 2 && list.signers ? list.signers : [list.root];
}

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

/** The did:key of a raw Ed25519 public key (32 bytes). */
export function didKeyFromEd25519(raw: Uint8Array): string {
  const bytes = new Uint8Array(2 + raw.length);
  bytes[0] = 0xed;
  bytes[1] = 0x01;
  bytes.set(raw, 2);
  // Big-endian base 256 to base 58, then one "1" per leading zero byte.
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) out += "1";
  for (let i = digits.length - 1; i >= 0; i -= 1) out += BASE58[digits[i]];
  return `did:key:z${out}`;
}

/** The Ed25519 public key inside a did:key, or null if it is not one. */
export function ed25519KeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith("did:key:z")) return null;
  const decoded = base58Decode(did.slice("did:key:z".length));
  if (!decoded || decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
  return decoded.slice(2);
}

/**
 * Sign a device list (Ed25519). `signerDid` is the signing device, by
 * default the root; it must be a signer of the version before.
 */
export async function signDeviceList(
  signerPrivateKey: CryptoKey,
  payload: DeviceListPayload,
  signerDid: string = payload.root,
): Promise<string> {
  const header = { alg: "EdDSA", typ: DEVICE_LIST_TYP, kid: signerDid };
  const input = `${toBase64Url(encoder.encode(JSON.stringify(header)))}.${toBase64Url(
    encoder.encode(JSON.stringify(payload)),
  )}`;
  const signature = await crypto.subtle.sign("Ed25519", signerPrivateKey, asArrayBuffer(encoder.encode(input)));
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
 * Read a signed device list for `aid`: the header, the signature by the
 * key it names (`kid`), and the shape. Returns the list and its signer,
 * or null. Whether that signer may sign it is the caller's check
 * (`verifyDeviceList`, `checkDeviceList`).
 */
export async function readDeviceList(
  jws: string,
  aid: string,
): Promise<{ list: DeviceListPayload; signer: string } | null> {
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
  if (header.alg !== "EdDSA" || header.typ !== DEVICE_LIST_TYP || typeof header.kid !== "string") return null;
  const signer = header.kid;

  const signerKey = ed25519KeyFromDidKey(signer);
  const signature = fromBase64Url(signatureB64);
  if (!signerKey || !signature || signature.length !== 64) return null;
  let valid = false;
  try {
    const key = await crypto.subtle.importKey("raw", asArrayBuffer(signerKey), { name: "Ed25519" }, false, ["verify"]);
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

  const v2 = payload.v === 2;
  if (
    Object.keys(payload).length !== (v2 ? 7 : 6) ||
    (payload.v !== 1 && !v2) ||
    payload.aid !== aid ||
    typeof payload.root !== "string" ||
    !payload.root.startsWith("did:key:z") ||
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
  if (v2) {
    // Signers are browsers the list names, at least one, none twice.
    const signers = payload.signers;
    const browsers = new Set(devices.filter((d) => d.kind === "browser").map((d) => d.did));
    if (
      !Array.isArray(signers) ||
      signers.length < 1 ||
      !signers.every((d) => typeof d === "string" && browsers.has(d)) ||
      new Set(signers).size !== signers.length
    ) {
      return null;
    }
  } else if (signer !== payload.root) {
    return null;
  }
  return { list: payload as unknown as DeviceListPayload, signer };
}

/**
 * Check a signed device list against the agent, the root the caller
 * trusts, and who may sign it (`signers`, by default the root alone).
 * Returns the list, or null. Version ordering is the caller's check.
 */
export async function verifyDeviceList(
  jws: string,
  expected: { aid: string; root: string; signers?: string[] },
): Promise<DeviceListPayload | null> {
  const read = await readDeviceList(jws, expected.aid);
  if (!read || read.list.root !== expected.root) return null;
  if (!(expected.signers ?? [expected.root]).includes(read.signer)) return null;
  return read.list;
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

/**
 * What a sender remembers of an agent: its root, the newest list version
 * seen, and who may sign the next one when that is not just the root
 * (docs/40 §17.3).
 */
export type DevicePin = { root: string; version: number; signers?: string[] };

/**
 * The agent's list versions after `after`, oldest first, as the server
 * returns them (`GET /recipients/device-lists`), or null if it cannot.
 */
export type DeviceListHistory = (
  aid: string,
  after: number,
) => Promise<Array<{ version: number; jws: string }> | null>;

export type ListCheck =
  | { ok: true; list: DeviceListPayload }
  | { ok: false; reason: "signature" | "root_changed" | "rollback"; root?: string };

/**
 * Check an agent's current list (`ref`) against what the caller
 * remembers (`pin`). A list signed by a signer the pin trusts (or, seen
 * for the first time, by the root it names) is checked directly; any
 * other signer is followed version by version from the pin (or from
 * version 1) through `history`. `acceptRoot` is a new root the person
 * has just accepted (§12.5).
 */
export async function checkDeviceList(input: {
  aid: string;
  ref: { version: number; jws: string };
  pin: DevicePin | null;
  acceptRoot?: string;
  history?: DeviceListHistory;
}): Promise<ListCheck> {
  const read = await readDeviceList(input.ref.jws, input.aid);
  if (!read || read.list.version !== input.ref.version) return { ok: false, reason: "signature" };
  const { list, signer } = read;

  let pin = input.pin;
  if (pin && pin.root !== list.root) {
    if (input.acceptRoot !== list.root) return { ok: false, reason: "root_changed", root: list.root };
    pin = null;
  }
  if (pin && list.version < pin.version) return { ok: false, reason: "rollback" };

  const trusted = pin ? (pin.signers ?? [pin.root]) : [list.root];
  if (trusted.includes(signer)) return { ok: true, list };

  const chain = await followVersions(input.aid, list.root, pin, list.version, input.history);
  if (!chain || chain[chain.length - 1].jws !== input.ref.jws) return { ok: false, reason: "signature" };
  return { ok: true, list };
}

/**
 * The versions after `pin` (or from version 1) up to `upto`, each signed
 * by a signer of the one before (version 1 by the root). Null if any is
 * missing or does not hold.
 */
export async function followVersions(
  aid: string,
  root: string,
  pin: DevicePin | null,
  upto: number,
  history: DeviceListHistory | undefined,
): Promise<Array<{ list: DeviceListPayload; jws: string }> | null> {
  if (!history) return null;
  const after = pin ? pin.version : 0;
  if (upto <= after) return null;
  const fetched = await history(aid, after).catch(() => null);
  if (!fetched) return null;
  const wanted = fetched.filter((r) => r.version > after && r.version <= upto).sort((a, b) => a.version - b.version);
  if (wanted.length !== upto - after) return null;
  let allowed = pin ? (pin.signers ?? [pin.root]) : [root];
  const out: Array<{ list: DeviceListPayload; jws: string }> = [];
  for (let i = 0; i < wanted.length; i += 1) {
    const read = await readDeviceList(wanted[i].jws, aid);
    if (!read || read.list.root !== root || read.list.version !== after + i + 1) return null;
    if (read.list.version !== wanted[i].version || !allowed.includes(read.signer)) return null;
    allowed = listSigners(read.list);
    out.push({ list: read.list, jws: wanted[i].jws });
  }
  return out;
}

/** The pin to keep after `list` checked (it only moves forward). */
export function pinFor(pin: DevicePin | null, list: DeviceListPayload): DevicePin {
  if (pin && pin.root === list.root && pin.version > list.version) return pin;
  const signers = listSigners(list);
  const onlyRoot = signers.length === 1 && signers[0] === list.root;
  return { root: list.root, version: list.version, ...(onlyRoot ? {} : { signers }) };
}

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
 *  - no_list: the agent has no list yet (since stage 5, docs/40 §15.2: not
 *    sent to until it makes one, which it does when it opens NexusInbox);
 *  - no_device: none of the listed devices is still active.
 */
export type StopReason = "root_changed" | "signature" | "rollback" | "removed" | "no_list" | "no_device";

export type WrapDecision =
  /** Checked: wrap for `targets`; `single` is the one `encrypted_key` goes to. */
  | { kind: "listed"; list: DeviceListPayload; targets: WrapTarget[]; single: WrapTarget }
  | { kind: "stop"; reason: StopReason; root?: string };

/** The root a list names, unchecked. */
export function deviceListRoot(jws: string): string | null {
  const payloadBytes = fromBase64Url(jws.split(".")[1] ?? "");
  if (!payloadBytes) return null;
  try {
    const root = JSON.parse(decoder.decode(payloadBytes)).root;
    return typeof root === "string" ? root : null;
  } catch {
    return null;
  }
}

/**
 * Decide which devices of `served` to wrap a message's key for.
 * `requested` is what the sender asked to resolve (an AID or a DID);
 * `knownAid` the agent a requested DID was seen under before, if any;
 * `pin` what it remembers of this agent; `acceptRoot` a new root the
 * person has just accepted (§12.5); `history` how to fetch the versions
 * between, when the list is signed by a signer the pin does not trust
 * yet (§17.3).
 */
export async function decideWrapTargets(input: {
  served: ServedAgent;
  requested: string;
  knownAid?: string | null;
  pin: DevicePin | null;
  acceptRoot?: string;
  history?: DeviceListHistory;
}): Promise<WrapDecision> {
  const { served, requested, pin } = input;
  // A DID belongs to one agent for good: the server may not move it.
  if (requested.startsWith("aid:") && requested !== served.aid) return { kind: "stop", reason: "signature" };
  if (input.knownAid && input.knownAid !== served.aid) return { kind: "stop", reason: "signature" };
  const active = served.devices && served.devices.length > 0
    ? served.devices
    : [{ did: served.did, encryption_public_key: served.encryption_public_key }];

  const ref = served.device_list;
  if (!ref) return { kind: "stop", reason: pin ? "removed" : "no_list" };

  const checked = await checkDeviceList({
    aid: served.aid,
    ref,
    pin,
    acceptRoot: input.acceptRoot,
    history: input.history,
  });
  if (!checked.ok) {
    return { kind: "stop", reason: checked.reason, ...(checked.root ? { root: checked.root } : {}) };
  }
  const list = checked.list;

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
  return pinFor(pin, decision.list);
}
