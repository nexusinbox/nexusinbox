import { describe, expect, it } from "vitest";
import type { AgentCredential, AuditLogEntry } from "../api/types";
import {
  cloudAccessStatus,
  computerStatus,
  elapsed,
  parseServerTime,
  presetFromSettings,
  recentAutoReplies,
} from "./agent-status";
import { presetSettings } from "./auto-reply-presets";

const NOW = Date.parse("2026-11-08T03:00:00Z");
const AID = "aid:ai:01TEST";

function credential(fields: Partial<AgentCredential>): AgentCredential {
  return {
    credential_id: crypto.randomUUID(),
    aid: AID,
    label: "macOS",
    status: "active",
    allowed_scopes: [],
    created_at: "2026-11-08 01:00:00+00",
    key_holder: "signer_daemon",
    ...fields,
  };
}

describe("parseServerTime", () => {
  it("reads Postgres text and RFC 3339 the same way", () => {
    expect(parseServerTime("2026-11-08 02:34:07.123456+00")).toBe(
      Date.parse("2026-11-08T02:34:07.123Z"),
    );
    expect(parseServerTime("2026-11-08 11:34:07+09")).toBe(Date.parse("2026-11-08T02:34:07Z"));
    expect(parseServerTime("2026-11-08T02:34:07+00:00")).toBe(Date.parse("2026-11-08T02:34:07Z"));
    expect(parseServerTime(null)).toBeNull();
    expect(parseServerTime("soon")).toBeNull();
  });
});

describe("computerStatus", () => {
  it("is the browser when no computer holds the keys", () => {
    expect(computerStatus([], AID, NOW)).toEqual({ kind: "browser" });
    expect(
      computerStatus(
        [
          credential({ key_holder: "web_keystore" }),
          credential({ status: "revoked" }),
          credential({ aid: "aid:ai:OTHER" }),
        ],
        AID,
        NOW,
      ),
    ).toEqual({ kind: "browser" });
  });

  it("is connected within two minutes of the last call, silent after", () => {
    expect(computerStatus([credential({ last_used_at: "2026-11-08 02:58:30+00" })], AID, NOW)).toEqual({
      kind: "connected",
      device: "macOS",
      lastSeenAt: Date.parse("2026-11-08T02:58:30Z"),
    });
    expect(computerStatus([credential({ last_used_at: "2026-11-08 02:57:59+00" })], AID, NOW)).toMatchObject({
      kind: "silent",
    });
    expect(computerStatus([credential({ last_used_at: null })], AID, NOW)).toEqual({
      kind: "silent",
      device: "macOS",
      lastSeenAt: null,
    });
  });

  it("counts activation as the first contact", () => {
    // Just connected: the gateway has not called the API yet.
    expect(
      computerStatus([credential({ last_used_at: null, activated_at: "2026-11-08 02:59:50+00" })], AID, NOW),
    ).toMatchObject({ kind: "connected", lastSeenAt: Date.parse("2026-11-08T02:59:50Z") });
    // Activated long ago and never heard from since.
    expect(
      computerStatus([credential({ last_used_at: null, activated_at: "2026-11-08 01:00:00+00" })], AID, NOW),
    ).toMatchObject({ kind: "silent", lastSeenAt: Date.parse("2026-11-08T01:00:00Z") });
  });

  it("goes by the computer heard from most recently", () => {
    const status = computerStatus(
      [
        credential({ label: "Linux", last_used_at: "2026-11-07 10:00:00+00" }),
        credential({ label: "macOS", last_used_at: "2026-11-08 02:59:30+00" }),
      ],
      AID,
      NOW,
    );
    expect(status).toMatchObject({ kind: "connected", device: "macOS" });
  });
});

describe("presetFromSettings", () => {
  it("names the first-run presets and nothing else", () => {
    expect(presetFromSettings(false, presetSettings("all").policy)).toBe("manual");
    expect(presetFromSettings(true, presetSettings("all").policy)).toBe("all");
    expect(presetFromSettings(true, presetSettings("contacts").policy)).toBe("contacts");
    // Same policy, other key order.
    expect(
      presetFromSettings(true, {
        protocols: { task_delegation: { delegate: { action: "queue_for_human" } } },
        default_action: "auto_accept",
        v: 1,
      }),
    ).toBe("all");
    expect(presetFromSettings(true, { v: 1, default_action: "auto_accept" })).toBe("custom");
    expect(presetFromSettings(true, {})).toBe("custom");
  });
});

describe("recentAutoReplies", () => {
  const sent = (detail: Record<string, unknown>, created_at = "2026-11-08 02:00:00+00"): AuditLogEntry => ({
    id: crypto.randomUUID(),
    credential_id: null,
    aid: AID,
    event: "auto_reply_sent",
    detail,
    created_at,
  });

  it("lists answered messages only, once each, newest first", () => {
    const events = [
      sent({ message_id: "m4", reply_message_id: "r4", decision: "auto_accept", sender_did: "did:key:zA", auto_reply_sent_at: "2026-11-08 02:40:00+00" }),
      sent({ message_id: "m3", reply_message_id: null, decision: "auto_accept", sender_did: "did:key:zB" }),
      sent({ message_id: "m4", reply_message_id: "r4", decision: "auto_accept", sender_did: "did:key:zA" }),
      sent({ message_id: "m2", reply_message_id: "r2", decision: "auto_decline", sender_did: "did:key:zC" }),
      sent({ message_id: "m1", reply_message_id: "r1", sender_did: "did:key:zD" }, "2026-11-07 09:00:00+00"),
      sent({ message_id: "m0", reply_message_id: "r0", decision: "auto_accept", sender_did: "did:key:zE" }),
    ];
    const replies = recentAutoReplies(events);
    expect(replies.map((r) => [r.messageId, r.action])).toEqual([
      ["m4", "accept"],
      ["m2", "decline"],
      ["m1", "reply"],
    ]);
    expect(replies[0].at).toBe(Date.parse("2026-11-08T02:40:00Z"));
    expect(replies[2].at).toBe(Date.parse("2026-11-07T09:00:00Z"));
  });
});

describe("elapsed", () => {
  it("uses the largest whole unit", () => {
    expect(elapsed(NOW - 30_000, NOW)).toEqual({ unit: "seconds", value: 30 });
    expect(elapsed(NOW - 2 * 60_000 - 5_000, NOW)).toEqual({ unit: "minutes", value: 2 });
    expect(elapsed(NOW - 3 * 3_600_000, NOW)).toEqual({ unit: "hours", value: 3 });
    expect(elapsed(NOW - 50 * 3_600_000, NOW)).toEqual({ unit: "days", value: 2 });
    // A clock a little ahead of the server's never goes negative.
    expect(elapsed(NOW + 5_000, NOW)).toEqual({ unit: "seconds", value: 0 });
  });
});

describe("cloudAccessStatus", () => {
  const URL = "https://k3x9q7abcd.mcp.agent-inbox.ai/mcp";
  const recent = "2026-11-08 02:59:30+00";

  it("needs a computer", () => {
    expect(cloudAccessStatus([], AID, NOW)).toEqual({ kind: "unavailable" });
    expect(cloudAccessStatus([credential({ key_holder: "web_keystore", cloud_access: true })], AID, NOW)).toEqual({
      kind: "unavailable",
    });
  });

  it("is off until the person turns it on", () => {
    const c = credential({ last_used_at: recent });
    expect(cloudAccessStatus([c], AID, NOW)).toEqual({ kind: "off", credentialId: c.credential_id });
  });

  it("is ready only while the computer recently said it serves", () => {
    const on = { cloud_access: true, last_used_at: recent, cloud_url: URL };
    const ready = credential({ ...on, cloud_serving_at: "2026-11-08 02:59:55+00" });
    expect(cloudAccessStatus([ready], AID, NOW)).toEqual({
      kind: "ready",
      credentialId: ready.credential_id,
      url: URL,
    });
    expect(cloudAccessStatus([credential({ ...on, cloud_serving_at: null })], AID, NOW)).toMatchObject({
      kind: "preparing",
    });
    expect(
      cloudAccessStatus([credential({ ...on, cloud_serving_at: "2026-11-08 02:50:00+00" })], AID, NOW),
    ).toMatchObject({ kind: "preparing" });
    expect(
      cloudAccessStatus([credential({ ...on, cloud_url: null, cloud_serving_at: recent })], AID, NOW),
    ).toMatchObject({ kind: "preparing" });
  });

  it("is stopped while the computer is silent", () => {
    const c = credential({ cloud_access: true, last_used_at: "2026-11-08 01:00:00+00", cloud_url: URL });
    expect(cloudAccessStatus([c], AID, NOW)).toEqual({ kind: "stopped", credentialId: c.credential_id });
  });
});
