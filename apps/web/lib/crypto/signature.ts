function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function isValidEd25519PublicKeyB64Url(publicKey: string): boolean {
  try {
    return fromBase64Url(publicKey).byteLength === 32;
  } catch {
    return false;
  }
}
