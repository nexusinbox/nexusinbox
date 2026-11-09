import { beforeEach, describe, expect, it, vi } from "vitest";

const { resolveRecipient } = vi.hoisted(() => ({ resolveRecipient: vi.fn() }));
vi.mock("../api/client", () => ({ defaultApiClient: { resolveRecipient } }));

import type { Agent, AgentDraft } from "../api/types";
import { unwrapContentKeyWithRecipientPrivateKey } from "./keywrap";
import { senderCopyForDraft } from "./review-key";

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
});
