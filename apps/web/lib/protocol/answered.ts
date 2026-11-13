// Messages this browser's automatic reply already answered (docs/40
// §14.5). The server can deliver the same signed message again under a new
// id; a reply goes to it once. Kept by v2 signature for a little longer than
// automatic replies answer at all (24 hours).

const KEY = "nexusinbox.autoreply.answered";
const KEEP_MS = 25 * 60 * 60 * 1000;

function load(now: number): Record<string, number> {
  try {
    const value = JSON.parse(window.localStorage.getItem(KEY) ?? "{}") as Record<string, unknown>;
    const out: Record<string, number> = {};
    for (const [signature, until] of Object.entries(value)) {
      if (typeof until === "number" && until > now) out[signature] = until;
    }
    return out;
  } catch {
    return {};
  }
}

export const answeredReplies = {
  has(signature: string, now: number = Date.now()): boolean {
    return signature in load(now);
  },
  add(signature: string, now: number = Date.now()): void {
    const map = load(now);
    map[signature] = now + KEEP_MS;
    try {
      window.localStorage.setItem(KEY, JSON.stringify(map));
    } catch {
      // Storage blocked: the server's claim still stops a second reply to
      // the same delivery.
    }
  },
};
