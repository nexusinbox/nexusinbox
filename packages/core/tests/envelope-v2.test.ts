import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  autoReplyBlock,
  checkSender,
  envelopeV2SigningInput,
  pinAfterCheck,
  senderCheckWarns,
  signEnvelopeV2,
  verifyEnvelopeV2Signature,
  type EnvelopeV2Fields,
} from "../src/envelope-v2";

const signing = JSON.parse(readFileSync(new URL("../../../tests/vectors/envelope_v2.json", import.meta.url), "utf8"));
const decisions = JSON.parse(
  readFileSync(new URL("../../../tests/vectors/sender_check_decisions.json", import.meta.url), "utf8"),
);

async function keyFromSeed(seedHex: string): Promise<CryptoKey> {
  const prefix = "302e020100300506032b657004220420";
  const bytes = Uint8Array.from((prefix + seedHex).match(/../g)!.map((h) => parseInt(h, 16)));
  return crypto.subtle.importKey("pkcs8", bytes, { name: "Ed25519" }, false, ["sign"]);
}

describe("envelope signature v2 (docs/40 §14.2)", () => {
  it("builds and signs the shared vectors", async () => {
    const key = await keyFromSeed(signing.signing_seed_hex);
    for (const c of signing.cases) {
      expect(await envelopeV2SigningInput(c.fields)).toBe(c.signing_input);
      expect(await signEnvelopeV2(key, c.fields)).toBe(c.signature);
      expect(await verifyEnvelopeV2Signature(c.fields, c.signature)).toBe(true);
    }
  });

  it("refuses a signature once any covered field changes", async () => {
    const c = signing.cases[0];
    const changes: Array<Partial<EnvelopeV2Fields>> = [
      { recipient_aid: "aid:ai:other" },
      { sent_at: "2026-11-20T10:41:00.001Z" },
      { content_type: "text/plain" },
      { thread_id: null },
      { encrypted_content: `${c.fields.encrypted_content}x` },
      { encrypted_keys: c.fields.encrypted_keys.slice(1) },
      { sender_encrypted_key: null },
      { attachments: [] },
    ];
    for (const change of changes) {
      expect(await verifyEnvelopeV2Signature({ ...c.fields, ...change }, c.signature)).toBe(false);
    }
    // Order of the lists does not matter: they are sorted before signing.
    const reordered = { ...c.fields, encrypted_keys: [...c.fields.encrypted_keys].reverse() };
    expect(await verifyEnvelopeV2Signature(reordered, c.signature)).toBe(true);
  });
});

type History = Array<{ version: number; jws: string }> | null | undefined;
/** A case's history as GET /recipients/device-lists would answer it (docs/40 §17). */
function historyOf(history: History) {
  if (history === undefined) return undefined;
  return async (_aid: string, after: number) => (history ? history.filter((h) => h.version > after) : null);
}

describe("checking the sender (docs/40 §14.5)", () => {
  const now = Date.parse(decisions.now);
  for (const c of decisions.cases) {
    it(c.name, async () => {
      const result = await checkSender({
        content: c.content,
        readerAids: c.reader_aids,
        sender: c.sender,
        pin: c.pin,
        signedBefore: c.signed_before ?? false,
        now: c.now ? Date.parse(c.now) : now,
        history: historyOf(c.history),
      });
      expect(result.state).toBe(c.expected.state);
      expect(pinAfterCheck(c.pin, result)).toEqual(c.expected.pin_after);
    });
  }

  it("leaves automatic replies to the person unless verified and recent", () => {
    for (const c of decisions.auto_reply) {
      expect(autoReplyBlock(c.state, c.sent_at, now), c.name).toBe(c.expected);
    }
  });

  it("warns only when something does not match", () => {
    expect(senderCheckWarns("verified")).toBe(false);
    expect(senderCheckWarns("no_list")).toBe(false);
    expect(senderCheckWarns("altered")).toBe(true);
    expect(senderCheckWarns("not_listed")).toBe(true);
    expect(senderCheckWarns("root_changed")).toBe(true);
    expect(senderCheckWarns("broken")).toBe(true);
    expect(senderCheckWarns("downgraded")).toBe(true);
    expect(senderCheckWarns("missing_signature")).toBe(true);
  });
});
