// What the agent page's status card says (docs/31 §4 step 3): where the
// agent runs, which auto-reply preset is on, and its latest automatic
// replies. Pure functions over what the API already returns.

import type { AgentCredential, AuditLogEntry, AutoReplyPolicy } from "../api/types";
import { presetSettings, type AutoReplyPreset } from "./auto-reply-presets";

/** A computer's gateway asks the API every 30 s while it runs. */
export const CONNECTED_WITHIN_MS = 2 * 60_000;

/**
 * Parse a timestamp as the API prints it — RFC 3339, or Postgres text such
 * as `2026-11-08 02:34:07.123456+00`, which Safari does not read as is.
 */
export function parseServerTime(value: string | null | undefined): number | null {
  if (!value) return null;
  const iso = value
    .trim()
    .replace(" ", "T")
    .replace(/(\.\d{3})\d+/, "$1")
    .replace(/([+-]\d{2})$/, "$1:00");
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

export type ComputerStatus =
  | { kind: "browser" }
  | { kind: "connected"; device: string; lastSeenAt: number }
  | { kind: "silent"; device: string; lastSeenAt: number | null };

/**
 * Where an agent runs. A computer is an active credential whose keys a
 * signer daemon holds; the one heard from most recently speaks for it.
 */
export function computerStatus(
  credentials: AgentCredential[],
  aid: string,
  now: number,
): ComputerStatus {
  const latest = latestComputer(credentials, aid);
  if (!latest) return { kind: "browser" };
  const seen = lastContact(latest);
  if (seen !== null && now - seen <= CONNECTED_WITHIN_MS) {
    return { kind: "connected", device: latest.label, lastSeenAt: seen };
  }
  return { kind: "silent", device: latest.label, lastSeenAt: seen };
}

// Activating the credential is the computer's first contact; before its
// first API call that is all there is.
function lastContact(c: AgentCredential): number | null {
  return parseServerTime(c.last_used_at) ?? parseServerTime(c.activated_at);
}

/** The computer holding this agent's keys that was heard from last. */
function latestComputer(credentials: AgentCredential[], aid: string): AgentCredential | null {
  const computers = credentials.filter(
    (c) => c.aid === aid && c.status === "active" && c.key_holder === "signer_daemon",
  );
  let latest: AgentCredential | null = null;
  for (const c of computers) {
    if (!latest || (lastContact(c) ?? 0) > (lastContact(latest) ?? 0)) latest = c;
  }
  return latest;
}

/** The computer says every 30 s (5 s while getting ready) whether it serves. */
export const SERVING_WITHIN_MS = 2 * 60_000;

export type CloudAccessStatus =
  | { kind: "unavailable" }
  | { kind: "off"; credentialId: string }
  | { kind: "preparing"; credentialId: string }
  | { kind: "ready"; credentialId: string; url: string }
  | { kind: "stopped"; credentialId: string };

/**
 * Whether cloud AIs can reach this agent through the relay (docs/33 §12).
 * It runs on the agent's computer, so a browser-only agent cannot.
 */
export function cloudAccessStatus(
  credentials: AgentCredential[],
  aid: string,
  now: number,
): CloudAccessStatus {
  const latest = latestComputer(credentials, aid);
  if (!latest) return { kind: "unavailable" };
  const credentialId = latest.credential_id;
  if (!latest.cloud_access) return { kind: "off", credentialId };
  const seen = lastContact(latest);
  if (seen === null || now - seen > CONNECTED_WITHIN_MS) return { kind: "stopped", credentialId };
  const serving = parseServerTime(latest.cloud_serving_at);
  if (latest.cloud_url && serving !== null && now - serving <= SERVING_WITHIN_MS) {
    return { kind: "ready", credentialId, url: latest.cloud_url };
  }
  return { kind: "preparing", credentialId };
}

/** Key order does not matter when comparing policies. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** Which first-run preset the agent's settings amount to, if any. */
export function presetFromSettings(
  autoReply: boolean,
  policy: AutoReplyPolicy | Record<string, never> | null | undefined,
): AutoReplyPreset | "custom" {
  if (!autoReply) return "manual";
  for (const preset of ["contacts", "all"] as const) {
    if (canonical(policy ?? {}) === canonical(presetSettings(preset).policy)) return preset;
  }
  return "custom";
}

export type AutoReplyRecord = {
  messageId: string;
  at: number | null;
  senderDid: string;
  action: "accept" | "decline" | "reply";
};

/**
 * The latest automatic replies, newest first, from `auto_reply_sent` audit
 * events. Rows the executor handled without answering carry no reply id
 * and are left out; a message marked twice counts once.
 */
export function recentAutoReplies(events: AuditLogEntry[], limit = 3): AutoReplyRecord[] {
  const seen = new Set<string>();
  const out: AutoReplyRecord[] = [];
  for (const event of events) {
    if (event.event !== "auto_reply_sent") continue;
    const detail = event.detail;
    const messageId = typeof detail.message_id === "string" ? detail.message_id : null;
    if (!messageId || !detail.reply_message_id || seen.has(messageId)) continue;
    seen.add(messageId);
    out.push({
      messageId,
      at:
        parseServerTime(typeof detail.auto_reply_sent_at === "string" ? detail.auto_reply_sent_at : null) ??
        parseServerTime(event.created_at),
      senderDid: typeof detail.sender_did === "string" ? detail.sender_did : "",
      action:
        detail.decision === "auto_accept"
          ? "accept"
          : detail.decision === "auto_decline"
            ? "decline"
            : "reply",
    });
    if (out.length === limit) break;
  }
  return out;
}

export type Elapsed = { unit: "seconds" | "minutes" | "hours" | "days"; value: number };

/** How long ago, in the largest whole unit. */
export function elapsed(since: number, now: number): Elapsed {
  const seconds = Math.max(0, Math.floor((now - since) / 1000));
  if (seconds < 60) return { unit: "seconds", value: seconds };
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return { unit: "minutes", value: minutes };
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return { unit: "hours", value: hours };
  return { unit: "days", value: Math.floor(hours / 24) };
}
