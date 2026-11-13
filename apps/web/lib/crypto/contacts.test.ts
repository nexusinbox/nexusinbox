import { describe, expect, it } from "vitest";
import { generateContactsKey, openContactFields, sealContactFields } from "./contacts";
import {
  unwrapContactsKey,
  unwrapContentKeyWithRecipientPrivateKey,
  wrapContactsKeyForAgent,
  wrapContentKeyForRecipient,
} from "./keywrap";
import { generateX25519KeyPairMaterial } from "./recipient-keyring";

const DID_A = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const DID_B = "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG";
const fields = { person_name: "山田さん", agent_label: "秘書", note: "会議の調整役" };

describe("sealed contacts", () => {
  it("opens what it sealed, and the blob carries no plaintext", async () => {
    const key = generateContactsKey();
    const sealed = await sealContactFields(key, DID_A, fields);
    expect(sealed.startsWith("cs1:")).toBe(true);
    expect(sealed).not.toContain("山田");
    await expect(openContactFields(key, DID_A, sealed)).resolves.toEqual(fields);
  });

  it("carries the contact's agent and root when known (docs/40 §12.4)", async () => {
    const key = generateContactsKey();
    const pinned = { ...fields, aid: "aid:ai:01ALEX", root: DID_B };
    await expect(openContactFields(key, DID_A, await sealContactFields(key, DID_A, pinned))).resolves.toEqual(pinned);
    // A root without its agent is not sealed.
    await expect(
      openContactFields(key, DID_A, await sealContactFields(key, DID_A, { ...fields, aid: null, root: DID_B })),
    ).resolves.toEqual(fields);
  });

  it("carries the confirmation-number check (docs/40 §16.2)", async () => {
    const key = generateContactsKey();
    const checked = {
      ...fields,
      aid: "aid:ai:01ALEX",
      root: DID_B,
      verified: { root: DID_B, at: "2026-11-14T10:00:00.000Z" },
      distrusted_root: "did:key:z6MkSwapped",
    };
    await expect(openContactFields(key, DID_A, await sealContactFields(key, DID_A, checked))).resolves.toEqual(checked);
  });

  it("refuses a sealed name moved onto another DID", async () => {
    const key = generateContactsKey();
    const sealed = await sealContactFields(key, DID_A, fields);
    await expect(openContactFields(key, DID_B, sealed)).rejects.toThrow();
  });

  it("refuses another person's key", async () => {
    const sealed = await sealContactFields(generateContactsKey(), DID_A, fields);
    await expect(openContactFields(generateContactsKey(), DID_A, sealed)).rejects.toThrow();
  });
});

describe("contacts key wraps", () => {
  it("round-trips through an agent's X25519 key", async () => {
    const agent = await generateX25519KeyPairMaterial();
    const key = generateContactsKey();
    const wrapped = await wrapContactsKeyForAgent(key, agent.publicKey);
    expect(wrapped.startsWith("ckx25519v1:")).toBe(true);
    await expect(unwrapContactsKey(wrapped, agent.privateKey)).resolves.toBe(key);
  });

  it("never opens a message's wrapped content key as a contacts key", async () => {
    const agent = await generateX25519KeyPairMaterial();
    const messageWrap = (await wrapContentKeyForRecipient(generateContactsKey(), agent.publicKey))
      .wrappedKey;
    await expect(unwrapContactsKey(messageWrap, agent.privateKey)).rejects.toThrow();
    // Even with the prefix swapped, the HKDF info differs and the tag fails.
    const relabeled = "ckx25519v1:" + messageWrap.slice("x25519v1:".length);
    await expect(unwrapContactsKey(relabeled, agent.privateKey)).rejects.toThrow();
    const contactsWrap = await wrapContactsKeyForAgent(generateContactsKey(), agent.publicKey);
    const asMessage = "x25519v1:" + contactsWrap.slice("ckx25519v1:".length);
    await expect(
      unwrapContentKeyWithRecipientPrivateKey(asMessage, agent.privateKey),
    ).rejects.toThrow();
  });
});
