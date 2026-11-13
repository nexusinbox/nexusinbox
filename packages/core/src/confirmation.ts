/**
 * Confirmation numbers (docs/40 §16.2), browser-safe.
 *
 * Two people read the number aloud (in person, on the phone) to check that
 * each sees the other's real agent: it is made from both agents' roots, so
 * a server that swapped either root shows a different number.
 *
 *   SHA-256("nexusinbox-confirm-v1\n" + smaller root + "\n" + larger root)
 *   → the first 9 bytes as a number, mod 10^20 → 20 digits, 5 per group.
 *
 * 20 digits (about 66 bits) keep a forger from finding a key that gives
 * the same number; 12 would not (docs/40 §16.6 Q23). The gateway's
 * `nexusinbox verify` computes the same (tests/vectors/confirmation_number.json).
 */

const PREFIX = "nexusinbox-confirm-v1\n";
const DIGITS = 20n;

/** The number both sides see, as "48210 93755 62014 70388". */
export async function confirmationNumber(rootA: string, rootB: string): Promise<string> {
  const [first, second] = [rootA, rootB].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const input = new TextEncoder().encode(`${PREFIX}${first}\n${second}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  let value = 0n;
  for (const byte of digest.slice(0, 9)) value = (value << 8n) | BigInt(byte);
  const digits = (value % 10n ** DIGITS).toString().padStart(Number(DIGITS), "0");
  return digits.match(/.{5}/g)!.join(" ");
}
