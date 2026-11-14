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
import { checkReceived, receivedOldFormat, receivedWarns } from "./sender-check";

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

  it("warns when the envelope was changed, and only notes the old format", async () => {
    const altered = find("altered: the server added a key wrap");
    resolveRecipient.mockResolvedValue(altered.sender);
    const me = [{ aid: altered.reader_aids[0], did: "did:key:zMe" }];
    const state = await checkReceived(altered.content, me);
    expect(state).toBe("altered");
    expect(receivedWarns(state)).toBe(true);

    const old = find("unsigned");
    const oldState = await checkReceived(old.content, me);
    expect(oldState).toBe("unsigned");
    expect(receivedWarns(oldState)).toBe(false);
    expect(receivedOldFormat(oldState)).toBe(true);
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
    // Never seen signing: only the old-format note.
    expect(await checkReceived(stripped, me)).toBe("unsigned");
    expect(await checkReceived(c.content, me)).toBe("verified");
    const state = await checkReceived(stripped, me);
    expect(state).toBe("downgraded");
    expect(receivedWarns(state)).toBe(true);
    expect(receivedOldFormat(state)).toBe(false);
  });

  it("warns about every message without a signature from 2027-02-11", async () => {
    const c = find("unsigned");
    vi.setSystemTime(Date.parse("2027-02-11T00:00:00Z"));
    const state = await checkReceived(c.content, [{ aid: c.reader_aids[0], did: "did:key:zMe" }]);
    expect(state).toBe("missing_signature");
    expect(receivedWarns(state)).toBe(true);
  });
});
