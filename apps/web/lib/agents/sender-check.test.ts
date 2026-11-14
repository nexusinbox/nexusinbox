import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { resolveRecipient } = vi.hoisted(() => ({ resolveRecipient: vi.fn() }));
vi.mock("../api/client", () => ({
  defaultApiClient: { resolveRecipient },
  deviceListHistory: async () => null,
  ApiError: class ApiError extends Error {
    constructor(
      message: string,
      readonly status: number,
    ) {
      super(message);
    }
  },
}));
vi.mock("../contacts/address-book", () => ({ loadAddressBook: vi.fn(async () => undefined) }));

import { ApiError } from "../api/client";
import type { MessageContentResponse } from "../api/types";
import { loadPin } from "./peer-pins";
import { checkReceived, receivedNoList, receivedWarns } from "./sender-check";

// The shared decisions (docs/40 §14.5), through this browser's pins.
const vectors = JSON.parse(
  readFileSync(new URL("../../../../tests/vectors/sender_check_decisions.json", import.meta.url), "utf8"),
) as {
  now: string;
  cases: { name: string; content: MessageContentResponse; reader_aids: string[]; sender: { aid: string } }[];
};
const find = (prefix: string) => vectors.cases.find((c) => c.name.startsWith(prefix))!;

describe("checkReceived", () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
        removeItem: (k: string) => void store.delete(k),
      },
    });
    resolveRecipient.mockReset();
    vi.useFakeTimers({ now: Date.parse(vectors.now), toFake: ["Date"] });
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("verifies a signed message and remembers the sender's root", async () => {
    const c = find("verified: first time");
    resolveRecipient.mockResolvedValue(c.sender);
    const me = [{ aid: c.reader_aids[0], did: "did:key:zMe" }];
    expect(await checkReceived(c.content, me)).toBe("verified");
    expect(loadPin(c.sender.aid)).toEqual({ root: (vectors as unknown as { root: string }).root, version: 1 });
  });

  it("warns when the envelope was changed or has no signature", async () => {
    const altered = find("altered: the server added a key wrap");
    resolveRecipient.mockResolvedValue(altered.sender);
    const me = [{ aid: altered.reader_aids[0], did: "did:key:zMe" }];
    const state = await checkReceived(altered.content, me);
    expect(state).toBe("altered");
    expect(receivedWarns(state)).toBe(true);

    // Every sender signs since stage 4 (docs/40 §15.2): no signature warns.
    const unsigned = find("missing_signature: no v2 signature (docs");
    const unsignedState = await checkReceived(unsigned.content, me);
    expect(unsignedState).toBe("missing_signature");
    expect(receivedWarns(unsignedState)).toBe(true);
    expect(receivedNoList(unsignedState)).toBe(false);
  });

  it("is quiet when the sender cannot be looked up just now, and tries again", async () => {
    const c = find("verified: first time");
    const me = [{ aid: c.reader_aids[0], did: "did:key:zMe" }];
    // Past the few minutes a lookup is shared for.
    vi.setSystemTime(Date.parse(vectors.now) + 6 * 60 * 1000);
    resolveRecipient.mockRejectedValueOnce(new ApiError("down", 503));
    const state = await checkReceived({ ...c.content }, me);
    expect(state).toBe("unchecked");
    expect(receivedWarns(state)).toBe(false);
    resolveRecipient.mockResolvedValue(c.sender);
    expect(await checkReceived(c.content, me)).toBe("verified");
  });

  it("warns about a message without a signature from a sender seen signing (docs/40 §15.2)", async () => {
    const c = find("verified: first time");
    resolveRecipient.mockResolvedValue(c.sender);
    const me = [{ aid: c.reader_aids[0], did: "did:key:zMe" }];
    const stripped = { ...c.content, signature_v2: null };
    // Never seen signing: a warning without the reason.
    expect(await checkReceived(stripped, me)).toBe("missing_signature");
    expect(await checkReceived(c.content, me)).toBe("verified");
    const state = await checkReceived(stripped, me);
    expect(state).toBe("downgraded");
    expect(receivedWarns(state)).toBe(true);
    expect(receivedNoList(state)).toBe(false);
  });
});
