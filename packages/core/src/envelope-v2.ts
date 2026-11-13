/**
 * Envelope signature v2 and checking the sender (docs/40 §14), browser-safe.
 *
 * The sending device signs the whole envelope: both agents, the time it
 * sent, the content type and thread, the encrypted subject, a hash of
 * the encrypted body, every key wrap and every attachment. The signed
 * bytes are ENVELOPE_V2_PREFIX followed by the JSON object below with its
 * keys sorted and no whitespace (RFC 8785). The prefix keeps a v2
 * signature from passing for anything else the same key signs (JWS
 * inputs start with "eyJ").
 *
 * A reader checks the signature, then that the sending device is on the
 * sender's device list signed by the root it remembers. Readers that
 * cannot check a message mark it and do not reply to it automatically.
 *
 * services/api, services/agent-gateway and services/signer-daemon build
 * the same bytes (tests/vectors/envelope_v2.json); the Rust gateway makes
 * the same decisions (tests/vectors/sender_check_decisions.json).
 */

import {
  deviceListRoot,
  ed25519KeyFromDidKey,
  verifyDeviceList,
  type DeviceListPayload,
  type DevicePin,
  type ServedAgent,
} from "./device-list.js";

export const ENVELOPE_V2_PREFIX = "nexusinbox-envelope-v2\n";

/** How far ahead of the reader's clock a message may say it was sent. */
export const MAX_CLOCK_AHEAD_MS = 10 * 60 * 1000;
/** Automatic replies only answer messages sent within this time. */
export const AUTO_REPLY_MAX_AGE_MS = 24 * 60 * 60 * 1000;

export type KeyWrapV2 = { did: string; key: string };
export type AttachmentRefV2 = { id: string; metadata_encrypted: string; metadata_nonce: string };

/** Everything a v2 signature covers. */
export type EnvelopeV2Fields = {
  sender_aid: string;
  sender_did: string;
  recipient_aid: string;
  recipient_did: string;
  /** RFC 3339 UTC with milliseconds, e.g. 2026-11-13T10:00:00.000Z. */
  sent_at: string;
  content_type: string;
  thread_id: string | null;
  subject_encrypted: string;
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  sender_encrypted_key: string | null;
  encrypted_keys: KeyWrapV2[];
  sender_encrypted_keys: KeyWrapV2[];
  attachments: AttachmentRefV2[];
};

/** What a sender adds to the envelope, and the server returns with the content. */
export type SignatureV2 = {
  signature: string;
  sent_at: string;
  sender_aid: string;
  recipient_aid: string;
};

const encoder = new TextEncoder();

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

async function sha256(text: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", asArrayBuffer(encoder.encode(text)))));
}

const str = (value: string) => JSON.stringify(value);
const strOrNull = (value: string | null) => (value === null ? "null" : str(value));
const byCodeUnits = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function wraps(list: KeyWrapV2[]): string {
  const sorted = [...list].sort((a, b) => byCodeUnits(a.did, b.did));
  return `[${sorted.map((w) => `{"did":${str(w.did)},"key":${str(w.key)}}`).join(",")}]`;
}

/** The time now as a v2 `sent_at`. */
export function sentAtNow(now: number = Date.now()): string {
  return new Date(now).toISOString();
}

/**
 * The bytes a v2 signature covers, as text: the prefix and the canonical
 * JSON. Keys are written in sorted order; lists are sorted by DID or id.
 */
export async function envelopeV2SigningInput(f: EnvelopeV2Fields): Promise<string> {
  const attachments = await Promise.all(
    [...f.attachments]
      .sort((a, b) => byCodeUnits(a.id, b.id))
      .map(
        async (a) =>
          `{"id":${str(a.id)},"metadata_nonce":${str(a.metadata_nonce)},"metadata_sha256":${str(
            await sha256(a.metadata_encrypted),
          )}}`,
      ),
  );
  const json =
    `{"attachments":[${attachments.join(",")}]` +
    `,"content_sha256":${str(await sha256(f.encrypted_content))}` +
    `,"content_type":${str(f.content_type)}` +
    `,"encrypted_key":${str(f.encrypted_key)}` +
    `,"encrypted_keys":${wraps(f.encrypted_keys)}` +
    `,"nonce":${str(f.nonce)}` +
    `,"recipient_aid":${str(f.recipient_aid)}` +
    `,"recipient_did":${str(f.recipient_did)}` +
    `,"sender_aid":${str(f.sender_aid)}` +
    `,"sender_did":${str(f.sender_did)}` +
    `,"sender_encrypted_key":${strOrNull(f.sender_encrypted_key)}` +
    `,"sender_encrypted_keys":${wraps(f.sender_encrypted_keys)}` +
    `,"sent_at":${str(f.sent_at)}` +
    `,"subject_encrypted":${str(f.subject_encrypted)}` +
    `,"thread_id":${strOrNull(f.thread_id)}` +
    `,"v":2}`;
  return ENVELOPE_V2_PREFIX + json;
}

/** Sign with the sending device's Ed25519 key. */
export async function signEnvelopeV2(signingPrivateKey: CryptoKey, f: EnvelopeV2Fields): Promise<string> {
  const input = encoder.encode(await envelopeV2SigningInput(f));
  return toBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519", signingPrivateKey, asArrayBuffer(input))));
}

/** Whether `signature` is `f.sender_did`'s signature over `f`. */
export async function verifyEnvelopeV2Signature(f: EnvelopeV2Fields, signature: string): Promise<boolean> {
  const key = ed25519KeyFromDidKey(f.sender_did);
  const sig = fromBase64Url(signature);
  if (!key || !sig || sig.length !== 64) return false;
  try {
    const publicKey = await crypto.subtle.importKey("raw", asArrayBuffer(key), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      asArrayBuffer(sig),
      asArrayBuffer(encoder.encode(await envelopeV2SigningInput(f))),
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Checking the sender (docs/40 §14.5).

/**
 *  - verified: signed by a device on the sender's list, under the root remembered;
 *  - unsigned: no v2 signature (an older sender);
 *  - no_list: signed, but the sender's agent has no device list yet;
 *  - altered: the signature does not match what was delivered, or names other agents;
 *  - not_listed: the signing device is not on the sender's list;
 *  - root_changed: the sender's list is signed by a root other than the remembered one;
 *  - broken: the sender's list does not verify, is older than one seen, or disappeared.
 */
export type SenderCheckState =
  | "verified"
  | "unsigned"
  | "no_list"
  | "altered"
  | "not_listed"
  | "root_changed"
  | "broken";

/** The part of `GET /messages/:id/content` the check reads. */
export type DeliveredContent = {
  sender_did: string;
  recipient_did: string;
  subject_encrypted: string;
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  content_type?: string | null;
  thread_id?: string | null;
  sender_encrypted_key?: string | null;
  encrypted_keys?: KeyWrapV2[] | null;
  sender_encrypted_keys?: KeyWrapV2[] | null;
  attachments?: AttachmentRefV2[] | null;
  signature_v2?: SignatureV2 | null;
  /** The sender's device list as it was when the message was sent. */
  sender_device_list?: { version: number; jws: string } | null;
};

export type SenderCheck = {
  state: SenderCheckState;
  /** The sender's current list, when it verified (to move the pin forward). */
  list?: DeviceListPayload;
};

/** The fields a delivered message's v2 signature should cover. */
export function deliveredFields(content: DeliveredContent, sig: SignatureV2): EnvelopeV2Fields {
  return {
    sender_aid: sig.sender_aid,
    sender_did: content.sender_did,
    recipient_aid: sig.recipient_aid,
    recipient_did: content.recipient_did,
    sent_at: sig.sent_at,
    content_type: content.content_type ?? "text/plain",
    thread_id: content.thread_id ?? null,
    subject_encrypted: content.subject_encrypted,
    encrypted_content: content.encrypted_content,
    encrypted_key: content.encrypted_key,
    nonce: content.nonce,
    sender_encrypted_key: content.sender_encrypted_key ?? null,
    encrypted_keys: content.encrypted_keys ?? [],
    sender_encrypted_keys: content.sender_encrypted_keys ?? [],
    attachments: content.attachments ?? [],
  };
}

/**
 * Check who sent a delivered message. `readerAids` are the agents the
 * reader acts for (the recipient, or the sender for its own copy);
 * `sender` is the sender's agent as `GET /recipients/resolve` returns it
 * for `content.signature_v2.sender_aid`, or null when the server has none;
 * `pin` what the reader remembers of the sender.
 */
export async function checkSender(input: {
  content: DeliveredContent;
  readerAids: string[];
  sender: ServedAgent | null;
  pin: DevicePin | null;
  now?: number;
}): Promise<SenderCheck> {
  const { content, sender, pin } = input;
  const sig = content.signature_v2;
  if (!sig) return { state: "unsigned" };

  const ownCopy = input.readerAids.includes(sig.sender_aid);
  if (!ownCopy && !input.readerAids.includes(sig.recipient_aid)) return { state: "altered" };
  const sentAt = Date.parse(sig.sent_at);
  if (!Number.isFinite(sentAt) || sentAt > (input.now ?? Date.now()) + MAX_CLOCK_AHEAD_MS) {
    return { state: "altered" };
  }
  if (!(await verifyEnvelopeV2Signature(deliveredFields(content, sig), sig.signature))) {
    return { state: "altered" };
  }

  if (sender && sender.aid !== sig.sender_aid) return { state: "altered" };
  const ref = sender?.device_list;
  if (!ref) return { state: pin ? "broken" : "no_list" };
  const root = deviceListRoot(ref.jws);
  const list = root ? await verifyDeviceList(ref.jws, { aid: sig.sender_aid, root }) : null;
  if (!list || list.version !== ref.version) return { state: "broken" };
  if (pin && pin.root !== list.root) return { state: "root_changed" };
  if (pin && list.version < pin.version) return { state: "broken" };

  // The list as it was when the message was sent: same root, not newer.
  let sentWith = list;
  const sentRef = content.sender_device_list;
  if (sentRef && sentRef.version !== list.version) {
    const old = await verifyDeviceList(sentRef.jws, { aid: sig.sender_aid, root: list.root });
    if (!old || old.version !== sentRef.version || old.version > list.version) return { state: "broken", list };
    sentWith = old;
  }
  if (!sentWith.devices.some((d) => d.did === content.sender_did)) return { state: "not_listed", list };
  return { state: "verified", list };
}

/** What to remember after a check (the pin only moves forward). */
export function pinAfterCheck(pin: DevicePin | null, check: SenderCheck): DevicePin | null {
  if (!check.list || check.state === "root_changed") return pin;
  const { root, version } = check.list;
  if (pin && pin.root === root) return { root, version: Math.max(pin.version, version) };
  return { root, version };
}

/** Why an automatic reply is left to the person (recorded as the skip reason). */
export type AutoReplyBlock = "unsigned" | "altered" | "not_listed" | "stale" | "root_changed" | "signature";

/** Null when an automatic reply may answer; otherwise the reason it may not. */
export function autoReplyBlock(
  check: SenderCheckState,
  sentAt: string | null | undefined,
  now: number = Date.now(),
): AutoReplyBlock | null {
  switch (check) {
    case "verified": {
      const at = sentAt ? Date.parse(sentAt) : NaN;
      return Number.isFinite(at) && now - at <= AUTO_REPLY_MAX_AGE_MS ? null : "stale";
    }
    case "unsigned":
    case "no_list":
      return "unsigned";
    case "altered":
      return "altered";
    case "not_listed":
      return "not_listed";
    case "root_changed":
      return "root_changed";
    case "broken":
      return "signature";
  }
}

/** Whether a reader should show a warning (as opposed to a quiet note, or nothing). */
export function senderCheckWarns(state: SenderCheckState): boolean {
  return state !== "verified" && state !== "unsigned" && state !== "no_list";
}
