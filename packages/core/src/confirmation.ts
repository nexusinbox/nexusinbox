/**
 * Confirmation numbers (docs/40 §16.2), browser-safe.
 *
 * Two people read the number aloud (in person, on the phone) to check that
 * each sees the other's real agent: it is made from both agents' roots, so
 * a server that swapped either root shows a different number.
 *
 *   SHA-256("nexusinbox-confirm-v2\n" + smaller root + "\n" + larger root)
 *   → bytes 0-8 and 9-17, each as a number mod 10^20 → 20 digits each,
 *   joined: 40 digits, 5 per group.
 *
 * 40 digits (about 133 bits): a server that swaps both roots at first
 * contact makes keys on both sides until two numbers meet, so it needs
 * about the square root of the number space; 20 digits (v1) fell to about
 * 10^10 tries a side (audit run-4, docs/40 §16.2). The gateway's
 * `nexusinbox verify` computes the same (tests/vectors/confirmation_number.json).
 */

const PREFIX = "nexusinbox-confirm-v2\n";
const HALF_DIGITS = 20n;

/** The number both sides see, as "48210 93755 … 70388" (8 groups of 5). */
export async function confirmationNumber(rootA: string, rootB: string): Promise<string> {
  const [first, second] = [rootA, rootB].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const input = new TextEncoder().encode(`${PREFIX}${first}\n${second}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
  const half = (bytes: Uint8Array) => {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return (value % 10n ** HALF_DIGITS).toString().padStart(Number(HALF_DIGITS), "0");
  };
  const digits = half(digest.slice(0, 9)) + half(digest.slice(9, 18));
  return digits.match(/.{5}/g)!.join(" ");
}
