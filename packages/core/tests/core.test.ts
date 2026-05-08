import { describe, expect, it } from "vitest";
import {
  activateAgentCredential,
  NexusInboxApiClient,
  NexusInboxGatewayClient,
  buildEncryptedTextEnvelope,
  buildEnrollmentProof,
  buildAgentAssertion,
  createAuthenticatedApiClient,
  createDpopKeyPair,
  createEd25519KeyPair,
  createX25519KeyPair,
  deriveDidKeyFromPublicKey,
  exchangeAgentToken,
  exportRawPublicKeyBase64Url,
  generateContentKey,
  isValidEd25519PublicKeyB64Url,
  isValidX25519PublicKeyB64Url,
  wrapContentKeyForRecipient,
} from "../src/index";
import { deriveMessageState } from "../src/visibility";

describe("@nexusinbox/core", () => {
  it("generates a content key", () => {
    expect(generateContentKey().length).toBeGreaterThan(20);
  });

  it("creates a DPoP keypair with public JWK", async () => {
    const dpop = await createDpopKeyPair();
    expect(dpop.publicJwk.kty).toBe("OKP");
    expect(dpop.publicJwk.crv).toBe("Ed25519");
    expect(dpop.publicJwk.x.length).toBeGreaterThan(10);
  });

  it("exports raw public keys and derives did:key", async () => {
    const signing = await createEd25519KeyPair();
    const encryption = await createX25519KeyPair();

    const signingPublic = await exportRawPublicKeyBase64Url(signing.publicKey);
    const encryptionPublic = await exportRawPublicKeyBase64Url(encryption.publicKey);
    const did = await deriveDidKeyFromPublicKey(signing.publicKey);

    expect(isValidEd25519PublicKeyB64Url(signingPublic)).toBe(true);
    expect(isValidX25519PublicKeyB64Url(encryptionPublic)).toBe(true);
    expect(did.startsWith("did:key:z")).toBe(true);
  });

  it("builds enrollment proof and agent assertion", async () => {
    const signing = await createEd25519KeyPair();

    const proof = await buildEnrollmentProof({
      credentialId: "00000000-0000-0000-0000-000000000001",
      signingPrivateKey: signing.privateKey,
      now: 1_700_000_000,
    });
    const assertion = await buildAgentAssertion({
      aid: "aid:ai:test",
      credentialId: "00000000-0000-0000-0000-000000000001",
      signingPrivateKey: signing.privateKey,
      audience: "https://app.nexusinbox.ai/api/agent-auth/token",
      scopes: ["messages.read", "messages.send"],
      now: 1_700_000_000,
    });

    const proofParts = proof.split(".");
    const assertionParts = assertion.split(".");
    expect(proofParts).toHaveLength(3);
    expect(assertionParts).toHaveLength(3);

    const proofPayload = JSON.parse(Buffer.from(proofParts[1], "base64url").toString("utf8"));
    const assertionPayload = JSON.parse(Buffer.from(assertionParts[1], "base64url").toString("utf8"));
    expect(proofPayload.credential_id).toBe("00000000-0000-0000-0000-000000000001");
    expect(assertionPayload.iss).toBe("aid:ai:test");
    expect(assertionPayload.sub).toBe("00000000-0000-0000-0000-000000000001");
  });

  it("wraps a content key for an X25519 recipient", async () => {
    const recipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const publicKeyB64 = Buffer.from(raw).toString("base64url");

    expect(isValidX25519PublicKeyB64Url(publicKeyB64)).toBe(true);
    const wrapped = await wrapContentKeyForRecipient("content-key", publicKeyB64);
    expect(wrapped.startsWith("x25519v1:")).toBe(true);
  });

  it("builds an encrypted envelope for text messages", async () => {
    const signingKeyPair = await createEd25519KeyPair();
    const recipient = (await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    )) as CryptoKeyPair;
    const recipientRaw = new Uint8Array(await crypto.subtle.exportKey("raw", recipient.publicKey));
    const recipientPublicKey = Buffer.from(recipientRaw).toString("base64url");

    const senderPubJwk = (await crypto.subtle.exportKey("jwk", signingKeyPair.publicKey)) as JsonWebKey;
    expect(isValidEd25519PublicKeyB64Url(String(senderPubJwk.x))).toBe(true);

    const envelope = await buildEncryptedTextEnvelope({
      senderDid: "did:key:zSender",
      recipientDid: "did:key:zRecipient",
      recipientEncryptionPublicKey: recipientPublicKey,
      senderSigningPrivateKey: signingKeyPair.privateKey,
      subject: "hello",
      body: "world",
    });

    expect(envelope.metadata.subject_encrypted.startsWith("enc:v1:")).toBe(true);
    expect(envelope.encrypted_content.startsWith("enc:v1:")).toBe(true);
    expect(envelope.encrypted_key.startsWith("x25519v1:")).toBe(true);
    expect(envelope.signature?.length).toBeGreaterThan(20);
  });

  it("builds API request paths for list and resolve", async () => {
    const requests: Array<{ url: string; method: string; headers: HeadersInit }> = [];
    const client = new NexusInboxApiClient({
      baseUrl: "https://app.nexusinbox.ai/api",
      accessToken: "agt_test_token",
      dpop: await createDpopKeyPair(),
      fetchImpl: async (input, init) => {
        requests.push({
          url: String(input),
          method: String(init?.method ?? "GET"),
          headers: init?.headers ?? {},
        });
        return new Response(JSON.stringify({ messages: [], total: 0, page: 1, per_page: 20 }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    await client.listMessages({ agentDid: "aid:ai:test" });
    expect(requests[0]?.url).toContain("/messages?agent_did=aid%3Aai%3Atest");
    expect(requests[0]?.method).toBe("GET");
  });

  it("transparently refreshes tokens on 401 and retries the request", async () => {
    // Simulates a long-running MCP server whose access token has expired
    // mid-session. The client should call `onUnauthorized`, swap to the
    // fresh credentials, and re-issue the same request — without the
    // tool handler ever seeing the 401.
    const calls: Array<{ token: string; jwk: string }> = [];
    const freshDpop = await createDpopKeyPair();
    let refreshCount = 0;

    const fetchImpl: typeof fetch = async (input, init) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      const auth = headers["Authorization"] ?? "";
      const dpopHeader = headers["DPoP"] ?? "";
      const jwk = (() => {
        try {
          const [header] = dpopHeader.split(".");
          const json = Buffer.from(
            header.replace(/-/g, "+").replace(/_/g, "/"),
            "base64",
          ).toString("utf8");
          return JSON.parse(json).jwk?.x ?? "";
        } catch {
          return "";
        }
      })();
      calls.push({ token: auth.replace(/^DPoP\s+/, ""), jwk });
      // First call gets 401; subsequent calls succeed.
      if (calls.length === 1) {
        return new Response(
          JSON.stringify({ error: "agent token has expired" }),
          { status: 401, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ messages: [], total: 0, page: 1, per_page: 20 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };

    const client = new NexusInboxApiClient({
      baseUrl: "https://app.nexusinbox.ai/api",
      accessToken: "agt_expired",
      dpop: await createDpopKeyPair(),
      fetchImpl,
      onUnauthorized: async () => {
        refreshCount += 1;
        return { accessToken: "agt_fresh", dpop: freshDpop };
      },
    });

    const result = await client.listMessages({ agentDid: "aid:ai:test" });
    expect(result.total).toBe(0);
    expect(refreshCount).toBe(1);
    expect(calls).toHaveLength(2);
    expect(calls[0]?.token).toBe("agt_expired");
    expect(calls[1]?.token).toBe("agt_fresh");
    // DPoP keypair must rotate together with the access token (DPoP
    // proofs bind the request to a specific keypair via JWK Thumbprint).
    expect(calls[0]?.jwk).not.toBe(calls[1]?.jwk);
  });

  it("does not retry when no onUnauthorized callback is wired", async () => {
    // Pre-existing behaviour: surface 401 directly so legacy SDK
    // consumers that didn't ask for refresh keep the same contract.
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      return new Response(JSON.stringify({ error: "expired" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new NexusInboxApiClient({
      baseUrl: "https://app.nexusinbox.ai/api",
      accessToken: "agt_expired",
      dpop: await createDpopKeyPair(),
      fetchImpl,
    });
    await expect(
      client.listMessages({ agentDid: "aid:ai:test" }),
    ).rejects.toThrow(/401/);
    expect(calls).toBe(1);
  });

  it("activates a credential with exported public keys", async () => {
    const signing = await createEd25519KeyPair();
    const encryption = await createX25519KeyPair();
    let requestBody = "";

    const response = await activateAgentCredential({
      baseUrl: "https://app.nexusinbox.ai/api",
      credentialId: "00000000-0000-0000-0000-000000000001",
      enrollmentSecret: "ens_test_secret",
      signingKeyPair: signing,
      encryptionKeyPair: encryption,
      fetchImpl: async (_input, init) => {
        requestBody = String(init?.body ?? "");
        return new Response(
          JSON.stringify({
            aid: "aid:ai:test",
            did: "did:key:zTest",
            credential_id: "00000000-0000-0000-0000-000000000001",
            status: "active",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      },
    });

    const parsed = JSON.parse(requestBody);
    expect(parsed.enrollment_secret).toBe("ens_test_secret");
    expect(parsed.signing_public_key).toBeTruthy();
    expect(parsed.encryption_public_key).toBeTruthy();
    expect(parsed.enrollment_proof.split(".")).toHaveLength(3);
    expect(response.status).toBe("active");
  });

  it("exchanges a token and creates an authenticated API client", async () => {
    const signing = await createEd25519KeyPair();
    const requests: Array<{ url: string; body: string }> = [];

    const fetchImpl: typeof fetch = async (input, init) => {
      requests.push({ url: String(input), body: String(init?.body ?? "") });
      if (String(input).endsWith("/agent-auth/token")) {
        return new Response(
          JSON.stringify({
            access_token: "agt_test_token",
            refresh_token: "agr_test_token",
            token_type: "DPoP",
            expires_in: 900,
            scope: "messages.read messages.send",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(JSON.stringify({ messages: [], total: 0, page: 1, per_page: 20 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const exchanged = await exchangeAgentToken({
      baseUrl: "https://app.nexusinbox.ai/api",
      aid: "aid:ai:test",
      credentialId: "00000000-0000-0000-0000-000000000001",
      signingPrivateKey: signing.privateKey,
      fetchImpl,
    });
    expect(exchanged.access_token).toBe("agt_test_token");

    const authed = await createAuthenticatedApiClient({
      baseUrl: "https://app.nexusinbox.ai/api",
      aid: "aid:ai:test",
      credentialId: "00000000-0000-0000-0000-000000000001",
      signingPrivateKey: signing.privateKey,
      fetchImpl,
    });
    await authed.client.listMessages({ agentDid: "aid:ai:test" });

    const tokenRequest = requests.find((request) => request.url.endsWith("/agent-auth/token"));
    expect(tokenRequest).toBeTruthy();
    const tokenBody = JSON.parse(String(tokenRequest?.body));
    expect(tokenBody.assertion.split(".")).toHaveLength(3);
    expect(tokenBody.dpop_jwk.kty).toBe("OKP");
    expect(authed.tokens.access_token).toBe("agt_test_token");
  });

  it("gateway client parses RPC responses", async () => {
    const writes: string[] = [];
    const client = new NexusInboxGatewayClient({
      rpcTransport: async (method, params) => {
        writes.push(JSON.stringify({ method, params }));
        return { aid: "aid:ai:test", did: "did:key:zTest" };
      },
    });
    const whoami = await client.whoami();
    expect(whoami.aid).toBe("aid:ai:test");
    expect(writes[0]).toContain('"method":"whoami"');
  });

  describe("deriveMessageState", () => {
    it("maps pending decrypt outcome to `decrypting` regardless of mode", () => {
      expect(
        deriveMessageState({
          recipientKeyHolder: "web_keystore",
          localHasPrivateKey: true,
          decryptOutcome: "pending",
        }),
      ).toBe("decrypting");
      expect(
        deriveMessageState({
          recipientKeyHolder: "signer_daemon",
          localHasPrivateKey: false,
          decryptOutcome: "pending",
        }),
      ).toBe("decrypting");
    });

    it("maps ok outcome to `readable`", () => {
      expect(
        deriveMessageState({
          recipientKeyHolder: "web_keystore",
          localHasPrivateKey: true,
          decryptOutcome: "ok",
        }),
      ).toBe("readable");
    });

    it("maps no_key to `unavailable_on_this_device` for Standard mode second browser", () => {
      // Same credential, different browser profile → no key in this
      // keystore but we expect Standard mode behaviour (not a daemon).
      expect(
        deriveMessageState({
          recipientKeyHolder: "web_keystore",
          localHasPrivateKey: false,
          decryptOutcome: "no_key",
        }),
      ).toBe("unavailable_on_this_device");
    });

    it("maps no_key to `unavailable_on_this_device` for Isolated mode (daemon-isolated)", () => {
      expect(
        deriveMessageState({
          recipientKeyHolder: "signer_daemon",
          localHasPrivateKey: false,
          decryptOutcome: "no_key",
        }),
      ).toBe("unavailable_on_this_device");
    });

    it("treats error with a daemon-holder and no local key as unavailable (expected Isolated mode UX)", () => {
      expect(
        deriveMessageState({
          recipientKeyHolder: "signer_daemon",
          localHasPrivateKey: false,
          decryptOutcome: "error",
        }),
      ).toBe("unavailable_on_this_device");
    });

    it("treats error with a local key as `decrypt_failed` (genuine failure)", () => {
      expect(
        deriveMessageState({
          recipientKeyHolder: "web_keystore",
          localHasPrivateKey: true,
          decryptOutcome: "error",
        }),
      ).toBe("decrypt_failed");
    });

    it("falls back to Standard mode behaviour when the holder is unknown", () => {
      // Legacy credential where the backend didn't record a hint — we
      // don't want every existing row in the inbox to suddenly show
      // "Daemon-isolated". Treat unknown as web_keystore.
      expect(
        deriveMessageState({
          recipientKeyHolder: "unknown",
          localHasPrivateKey: true,
          decryptOutcome: "error",
        }),
      ).toBe("decrypt_failed");
    });
  });
});
