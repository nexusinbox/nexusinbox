import { afterEach, describe, expect, it, vi } from "vitest";
import { deliveredFields, verifyEnvelopeV2Signature } from "@nexusinbox/core/envelope-v2";
import { deriveDidKeyFromPublicKey } from "@nexusinbox/core";
import { NexusInboxApiClient, ApiError } from "./client";

describe("NexusInboxApiClient", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends listMessages request with auth header and query params", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          messages: [],
          total: 0,
          page: 1,
          per_page: 50,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.listMessages({ agentDid: "all", status: "all", page: 1, perPage: 50 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/messages?");
    expect(String(url)).toContain("agent_did=all");

    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer dev-user-test");
    expect(init?.credentials).toBe("include");
  });

  it("throws ApiError on non-2xx response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ message: "missing bearer token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "bad-token",
    });

    await expect(client.listMessages({ agentDid: "all" })).rejects.toBeInstanceOf(ApiError);
  });

  it("posts createAgent payload", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "agent-id", did: "did:key:new" }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.createAgent({
      label: "営業アシスタント",
      public_key: "pk",
      encryption_key: "ek",
    });

    const [, init] = fetchMock.mock.calls[0];
    expect(init?.method).toBe("POST");
    expect(String(init?.body)).toContain("営業アシスタント");
  });

  it("patches message status", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "m-1", status: "read" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.updateMessageStatus("m-1", "read");

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/messages/m-1");
    expect(init?.method).toBe("PATCH");
    expect(String(init?.body)).toContain("\"status\":\"read\"");
  });

  it("calls auth verify without authorization header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          user: {
            id: "u-1",
            display_name: null,
            verification_level: "orb",
            created_at: "2026-04-11T00:00:00Z",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.verifyAuth({
      idkit_result: {
        protocol_version: "3.0",
        nonce: "test",
        responses: [{ identifier: "orb", proof: "p", merkle_root: "r", nullifier: "n" }],
      },
      action: "login",
    });

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });

  it("does not attach authorization header when no bearer token exists", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ agents: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "",
    });

    await client.listAgents();

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });

  it("calls auth logout without authorization header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.logoutAuth();

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/auth/logout");
    expect(init?.method).toBe("POST");
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });

  it("percent-encodes path ids so a crafted id cannot escape its route", async () => {
    // A fresh Response per call — a body can only be consumed once.
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      async () =>
        new Response(JSON.stringify({}), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.getMessageContent("../auth/session?x=1");
    await client.getAttachmentDownloadUrl("m/1", "a/2");

    const urls = fetchMock.mock.calls.map(([url]) => String(url));
    expect(urls).toEqual([
      "http://localhost:8080/messages/..%2Fauth%2Fsession%3Fx%3D1/content",
      "http://localhost:8080/messages/m%2F1/attachments/a%2F2/download",
    ]);
  });
  it("signs the whole envelope with signature v2 (docs/40 §14.2)", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ message_id: "m1", status: "delivered" }), {
        status: 202,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
    const did = await deriveDidKeyFromPublicKey(pair.publicKey);
    const client = new NexusInboxApiClient({ baseUrl: "http://localhost:8080", bearerToken: "t" });
    await client.seedMessage({
      senderDid: did,
      recipientDid: "did:key:zRecipient",
      subjectEncrypted: "enc:v1:s:s",
      encryptedContent: "enc:v1:b:b",
      encryptedKey: "x25519v1:a:b:c:d",
      nonce: "b",
      signing: { key: pair.privateKey, senderAid: "aid:ai:me", recipientAid: "aid:ai:them" },
      threadId: "0193f1d2-7c4a-7b3e-9a10-5d2f8e6c4b21",
      contentType: "text/plain",
      encryptedKeys: [{ did: "did:key:zRecipient", key: "x25519v1:r" }],
      senderEncryptedKeys: [{ did, key: "x25519v1:s" }],
      attachments: [{ attachment_id: "att-1", metadata_encrypted: "enc:v1:m:m", metadata_nonce: "mn" }],
    });
    const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
    const sig = body.envelope.signature_v2;
    expect(body.envelope.signature).toBeUndefined();
    expect(sig).toMatchObject({ sender_aid: "aid:ai:me", recipient_aid: "aid:ai:them" });
    const delivered = {
      sender_did: did,
      recipient_did: "did:key:zRecipient",
      subject_encrypted: "enc:v1:s:s",
      encrypted_content: "enc:v1:b:b",
      encrypted_key: "x25519v1:a:b:c:d",
      nonce: "b",
      content_type: "text/plain",
      thread_id: "0193f1d2-7c4a-7b3e-9a10-5d2f8e6c4b21",
      encrypted_keys: body.envelope.encrypted_keys,
      sender_encrypted_keys: body.envelope.sender_encrypted_keys,
      attachments: [{ id: "att-1", metadata_encrypted: "enc:v1:m:m", metadata_nonce: "mn" }],
    };
    expect(await verifyEnvelopeV2Signature(deliveredFields(delivered, sig), sig.signature)).toBe(true);
    // The server cannot add a wrap the sender did not sign.
    const added = { ...delivered, encrypted_keys: [...delivered.encrypted_keys, { did: "did:key:zEvil", key: "k" }] };
    expect(await verifyEnvelopeV2Signature(deliveredFields(added, sig), sig.signature)).toBe(false);
  });
});
