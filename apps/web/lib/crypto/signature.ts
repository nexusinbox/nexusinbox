function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function isValidEd25519PublicKeyB64Url(publicKey: string): boolean {
  try {
    return fromBase64Url(publicKey).byteLength === 32;
  } catch {
    return false;
  }
}

export async function signEnvelopePayload(params: {
  signingPrivateKey: CryptoKey;
  senderDid: string;
  recipientDid: string;
  subjectEncrypted: string;
  encryptedContent: string;
  encryptedKey: string;
  nonce: string;
}): Promise<string> {
  const payload = [
    params.senderDid,
    params.recipientDid,
    params.subjectEncrypted,
    params.encryptedContent,
    params.encryptedKey,
    params.nonce,
  ].join("\n");
  const signature = await crypto.subtle.sign("Ed25519", params.signingPrivateKey, asArrayBuffer(new TextEncoder().encode(payload)));
  return toBase64Url(new Uint8Array(signature));
}
