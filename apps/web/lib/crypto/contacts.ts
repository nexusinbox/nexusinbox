// Contact names and notes are sealed on this device (docs/28 P3-8): AES-GCM
// under the person's contacts key, with the contact's DID as additional
// data, so the server keeps only the DID and an opaque blob — and cannot
// move a sealed name onto another DID (that would fail the tag).

export type ContactFields = {
  person_name: string;
  agent_label: string | null;
  note: string | null;
};

const SEALED_PREFIX = "cs1:";
const AAD_PREFIX = "nexusinbox/contact/v1\n";
const KEY_BYTES = 32;
const IV_BYTES = 12;

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function importContactsKey(contactsKey: string): Promise<CryptoKey> {
  const raw = fromBase64Url(contactsKey);
  if (raw.byteLength !== KEY_BYTES) throw new Error("invalid contacts key");
  return crypto.subtle.importKey("raw", asArrayBuffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

function additionalData(did: string): ArrayBuffer {
  return asArrayBuffer(new TextEncoder().encode(AAD_PREFIX + did));
}

/** A fresh contacts key: 32 random bytes, base64url. */
export function generateContactsKey(): string {
  const raw = new Uint8Array(KEY_BYTES);
  crypto.getRandomValues(raw);
  return toBase64Url(raw);
}

export async function sealContactFields(
  contactsKey: string,
  did: string,
  fields: ContactFields,
): Promise<string> {
  const key = await importContactsKey(contactsKey);
  const iv = new Uint8Array(IV_BYTES);
  crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      person_name: fields.person_name,
      agent_label: fields.agent_label,
      note: fields.note,
    }),
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: additionalData(did) },
    key,
    asArrayBuffer(plaintext),
  );
  return `${SEALED_PREFIX}${toBase64Url(iv)}:${toBase64Url(new Uint8Array(ciphertext))}`;
}

export async function openContactFields(
  contactsKey: string,
  did: string,
  sealed: string,
): Promise<ContactFields> {
  if (!sealed.startsWith(SEALED_PREFIX)) throw new Error("unsupported sealed contact format");
  const [ivB64, ciphertextB64, extra] = sealed.slice(SEALED_PREFIX.length).split(":");
  if (!ivB64 || !ciphertextB64 || extra !== undefined) throw new Error("invalid sealed contact");
  const key = await importContactsKey(contactsKey);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: asArrayBuffer(fromBase64Url(ivB64)), additionalData: additionalData(did) },
    key,
    asArrayBuffer(fromBase64Url(ciphertextB64)),
  );
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
  const optional = (value: unknown) => (typeof value === "string" ? value : null);
  if (typeof parsed.person_name !== "string") throw new Error("invalid sealed contact");
  return {
    person_name: parsed.person_name,
    agent_label: optional(parsed.agent_label),
    note: optional(parsed.note),
  };
}
