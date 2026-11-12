// Auto-replies this browser did not send because the other agent's device
// list did not hold (docs/40 §12.5). Kept in this browser only, so the
// conversation can say so instead of staying silent.

import type { StopReason } from "@nexusinbox/core/device-list";

const KEY = "nexusinbox.autoreply.skipped";
const EVENT = "nexusinbox:autoreply-skipped";
const MAX = 50;

export type AutoReplySkip = { own: string; peer: string; reason: StopReason; at: number };

function load(): AutoReplySkip[] {
  try {
    const value = JSON.parse(window.localStorage.getItem(KEY) ?? "[]");
    return Array.isArray(value) ? (value as AutoReplySkip[]) : [];
  } catch {
    return [];
  }
}

export function recordAutoReplySkip(own: string, peer: string, reason: StopReason, now = Date.now()): void {
  const kept = load().filter((s) => !(s.own === own && s.peer === peer));
  kept.push({ own, peer, reason, at: now });
  try {
    window.localStorage.setItem(KEY, JSON.stringify(kept.slice(-MAX)));
    window.dispatchEvent(new Event(EVENT));
  } catch {
    // Storage blocked: the conversation just won't say so.
  }
}

/** The latest skip between one of `ownDids` and `peer`, if any. */
export function latestAutoReplySkip(ownDids: string[], peer: string): AutoReplySkip | null {
  const own = new Set(ownDids);
  const found = load().filter((s) => s.peer === peer && own.has(s.own));
  return found.length > 0 ? found[found.length - 1] : null;
}

/** Call `listener` whenever a skip is recorded in this tab. */
export function onAutoReplySkip(listener: () => void): () => void {
  window.addEventListener(EVENT, listener);
  return () => window.removeEventListener(EVENT, listener);
}
