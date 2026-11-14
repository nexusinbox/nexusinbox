import { beforeEach, describe, expect, it, vi } from "vitest";

const { resolveRecipient, getRecipientPrivateKey, secureDeleteKey } = vi.hoisted(() => ({
  resolveRecipient: vi.fn(),
  getRecipientPrivateKey: vi.fn(),
  secureDeleteKey: vi.fn(async () => undefined),
}));
vi.mock("../api/client", () => ({ defaultApiClient: { resolveRecipient } }));
vi.mock("./recipient-keyring", () => ({ getRecipientPrivateKey }));
vi.mock("./keystore", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./keystore")>()),
  isKeystoreAvailable: () => true,
  secureDeleteKey,
}));

import type { Agent, AgentDraft } from "../api/types";
import { encryptEnvelopeText, generateContentKey } from "./envelope";
import { unwrapContentKeyWithRecipientPrivateKey, wrapContentKeyForRecipient } from "./keywrap";
import { forgetOldReviewKey, openDraftHere, senderCopyForDraft } from "./review-key";

async function keyPair(): Promise<{ pair: CryptoKeyPair; pub: string }> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const pub = btoa(String.fromCharCode(...raw))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  return { pair, pub };
}

const draft = { aid: "aid:ai:me", sender_did: "did:key:zSigner" } as AgentDraft;
const draft0 = draft;
const opened = { subject: "s", body: "b", contentKey: "content-key-1" };

describe("senderCopyForDraft", () => {
  beforeEach(() => {
    resolveRecipient.mockReset();
  });

  it("wraps for the key of the DID the draft is sent from", async () => {
    const signer = await keyPair();
    const browserEra = await keyPair();
    resolveRecipient.mockResolvedValue({ did: draft.sender_did, encryption_public_key: signer.pub });
    const agents = [{ aid: "aid:ai:me", encryption_key: browserEra.pub } as Agent];

    const wrapped = await senderCopyForDraft(draft, opened, agents);

    expect(resolveRecipient).toHaveBeenCalledWith(draft.sender_did);
    expect(await unwrapContentKeyWithRecipientPrivateKey(wrapped!, signer.pair.privateKey)).toBe(
      "content-key-1",
    );
  });

  it("falls back to the agent's key when the DID cannot be resolved", async () => {
    const browserEra = await keyPair();
    resolveRecipient.mockImplementation(async () => {
      throw new Error("not found");
    });
    const agents = [{ aid: "aid:ai:me", encryption_key: browserEra.pub } as Agent];

    const wrapped = await senderCopyForDraft(draft, opened, agents);

    expect(
      await unwrapContentKeyWithRecipientPrivateKey(wrapped!, browserEra.pair.privateKey),
    ).toBe("content-key-1");
  });

  it("adds nothing to a draft the computer signed with its wraps (docs/40 §14.4)", async () => {
    const agents = [{ aid: "aid:ai:me", encryption_key: (await keyPair()).pub } as Agent];
    expect(await senderCopyForDraft({ ...draft, signed_v2: true }, opened, agents)).toBeUndefined();
    expect(resolveRecipient).not.toHaveBeenCalled();
  });
});

describe("openDraftHere (docs/40 §16.3)", () => {
  it("opens a draft with the key of a listed device this browser holds, and not otherwise", async () => {
    const device = await keyPair();
    const contentKey = generateContentKey();
    const subject = await encryptEnvelopeText("Next week", { contentKey });
    const body = await encryptEnvelopeText("How about Thursday?", { contentKey });
    const wrapped = await wrapContentKeyForRecipient(contentKey, device.pub);
    const draft = {
      ...draft0,
      subject_encrypted: subject.serialized,
      encrypted_content: body.serialized,
      sender_encrypted_keys: [
        { did: "did:key:zComputer", key: "x25519v1:not:for:this:browser" },
        { did: "did:key:zBrowser", key: wrapped.wrappedKey },
      ],
    } as AgentDraft;
    getRecipientPrivateKey.mockImplementation(async (did: string) =>
      did === "did:key:zBrowser" ? device.pair.privateKey : null,
    );
    await expect(openDraftHere(draft)).resolves.toMatchObject({
      subject: "Next week",
      body: "How about Thursday?",
      contentKey,
    });
    // A browser that is not on the agent's list cannot open it.
    getRecipientPrivateKey.mockResolvedValue(null);
    await expect(openDraftHere(draft)).resolves.toBeNull();
  });
});

describe("forgetOldReviewKey (docs/40 §16.3)", () => {
  function stubStorage(entries: Record<string, string>) {
    const store = new Map(Object.entries(entries));
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        removeItem: (k: string) => void store.delete(k),
      },
    });
    return store;
  }

  beforeEach(() => secureDeleteKey.mockClear());

  it("removes the review key an older version kept here", async () => {
    const store = stubStorage({ "nexusinbox.review-key.pub.v1": "pub", other: "x" });
    await forgetOldReviewKey();
    expect(store.has("nexusinbox.review-key.pub.v1")).toBe(false);
    expect(store.get("other")).toBe("x");
    expect(secureDeleteKey).toHaveBeenCalledWith("nexusinbox.review-key.v1");
    vi.unstubAllGlobals();
  });

  it("does nothing when there is none", async () => {
    stubStorage({});
    await forgetOldReviewKey();
    expect(secureDeleteKey).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });
});
