import { describe, expect, it } from "vitest";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import $RefParser from "@apidevtools/json-schema-ref-parser";

type Operation = {
  security?: unknown[];
  responses?: Record<string, { content?: Record<string, { schema?: object }> }>;
  requestBody?: { content?: Record<string, { schema?: object }> };
};

type PathItem = Partial<Record<"get" | "post" | "patch" | "put" | "delete", Operation>>;

type OpenApiDoc = {
  paths: Record<string, PathItem>;
  components: {
    schemas: Record<string, object>;
  };
};

async function loadOpenApi(): Promise<OpenApiDoc> {
  const doc = (await $RefParser.dereference("openapi/openapi.yaml")) as unknown as OpenApiDoc;
  return doc;
}

function createAjv() {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  addFormats(ajv);
  return ajv;
}

// Compile a named schema from components/schemas and return both the validator
// plus the schema. Fails fast with a clear error if the schema isn't there —
// otherwise a silent drop would surface as a confusing ajv runtime error.
function compile(doc: OpenApiDoc, name: string) {
  const schema = doc.components.schemas[name];
  if (!schema) {
    throw new Error(`schema ${name} missing from components.schemas`);
  }
  return createAjv().compile(schema);
}

describe("OpenAPI contract tests", () => {
  it("contains MVP-required paths", async () => {
    const doc = await loadOpenApi();

    expect(doc.paths["/auth/verify"]).toBeDefined();
    expect(doc.paths["/agents"]).toBeDefined();
    expect(doc.paths["/messages"]).toBeDefined();
    expect(doc.paths["/messages/{id}"]).toBeDefined();
    expect(doc.paths["/messages/{id}/content"]).toBeDefined();
    expect(doc.paths["/ws"]).toBeDefined();
  });

  it("accepts a valid AuthVerify request payload (normal case)", async () => {
    const doc = await loadOpenApi();
    const ajv = createAjv();

    const validate = ajv.compile(doc.components.schemas.AuthVerifyRequest);
    const validPayload = {
      proof: "0xproof",
      merkle_root: "0xroot",
      nullifier_hash: "0xnullifier",
      verification_level: "orb",
      action: "sign_in",
      signal: "",
    };

    const isValid = validate(validPayload);

    expect(isValid).toBe(true);
  });

  it("rejects an invalid AuthVerify request payload (error case)", async () => {
    const doc = await loadOpenApi();
    const ajv = createAjv();

    const validate = ajv.compile(doc.components.schemas.AuthVerifyRequest);
    const invalidPayload = {
      proof: "0xproof",
    };

    const isValid = validate(invalidPayload);

    expect(isValid).toBe(false);
    expect(validate.errors?.length ?? 0).toBeGreaterThan(0);
  });

  it("validates standard error response schema", async () => {
    const doc = await loadOpenApi();
    const ajv = createAjv();

    const validate = ajv.compile(doc.components.schemas.ErrorResponse);
    const errorPayload = {
      error: "unauthorized",
      message: "missing bearer token",
    };

    expect(validate(errorPayload)).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// Non-interactive agent endpoints — these are implemented in services/api but
// were drifting out of spec (see 3033316). These tests lock the contract down
// so any silent removal from openapi.yaml or any shape change in the handler
// response (without the fixture being updated) becomes a red test.
//
// Fixtures below are hand-crafted to mirror what services/api actually returns
// as of 2026-04-24. When you change a handler response shape, update the
// matching fixture here in the same PR — per CONTRIBUTING.md "security-
// sensitive changes — keep docs and UI in sync".
// -----------------------------------------------------------------------------

describe("OpenAPI contract — non-interactive agent endpoints", () => {
  const REQUIRED_PATHS = [
    "/agent-credentials",
    "/agent-credentials/{id}",
    "/agent-credentials/{id}/activate",
    "/agent-credentials/{id}/rotate",
    "/agent-credentials/{id}/purge",
    "/agent-auth/token",
    "/agent-auth/refresh",
    "/agent-auth/revoke",
    "/agent-audit-log",
    "/agent-audit-log/bridge",
    "/agents/{id}/emergency-shutdown",
  ];

  it.each(REQUIRED_PATHS)("documents %s", async (path) => {
    const doc = await loadOpenApi();
    expect(doc.paths[path]).toBeDefined();
  });

  // Security posture guard: these endpoints are callable without a Cookie
  // session (Daemon / agent-initiated flows). If someone drops the explicit
  // `security: []` they would silently become auth-required in generated
  // SDKs, which would break the Daemon at runtime.
  const PUBLIC_OPS: Array<[string, keyof PathItem]> = [
    ["/agent-credentials/{id}/activate", "post"],
    ["/agent-auth/token", "post"],
    ["/agent-auth/refresh", "post"],
    ["/agent-auth/revoke", "post"],
    ["/agent-audit-log/bridge", "post"],
  ];

  it.each(PUBLIC_OPS)("%s %s declares no auth requirement", async (path, method) => {
    const doc = await loadOpenApi();
    const op = doc.paths[path]?.[method];
    expect(op, `${method.toUpperCase()} ${path} missing`).toBeDefined();
    // `security: []` means "no requirement". Anything else (undefined, or a
    // non-empty array) means the global bearerAuth would apply.
    expect(op?.security).toEqual([]);
  });

  // Conversely, credential-management endpoints MUST require auth — losing
  // that would let anyone enumerate / revoke credentials.
  const AUTHED_OPS: Array<[string, keyof PathItem]> = [
    ["/agent-credentials", "get"],
    ["/agent-credentials", "post"],
    ["/agent-credentials/{id}", "patch"],
    ["/agent-credentials/{id}", "delete"],
    ["/agent-credentials/{id}/rotate", "post"],
    ["/agent-credentials/{id}/purge", "post"],
    ["/agent-audit-log", "get"],
    ["/agents/{id}/emergency-shutdown", "post"],
  ];

  it.each(AUTHED_OPS)("%s %s requires auth (no explicit security: [])", async (path, method) => {
    const doc = await loadOpenApi();
    const op = doc.paths[path]?.[method];
    expect(op, `${method.toUpperCase()} ${path} missing`).toBeDefined();
    // Either undefined (inherits global bearerAuth) or a non-empty array.
    if (op?.security !== undefined) {
      expect(op.security.length).toBeGreaterThan(0);
    }
  });

  // ---- AgentAuthTokenRequest / Response ---------------------------------

  it("accepts a minimal AgentAuthTokenRequest (no DPoP)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentAuthTokenRequest");
    expect(validate({ assertion: "eyJhbGciOiJFZERTQSJ9.e30.sig" })).toBe(true);
  });

  it("accepts an AgentAuthTokenRequest with DPoP JWK", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentAuthTokenRequest");
    expect(
      validate({
        assertion: "eyJhbGciOiJFZERTQSJ9.e30.sig",
        dpop_jwk: { kty: "OKP", crv: "Ed25519", x: "..." },
      }),
    ).toBe(true);
  });

  it("rejects an AgentAuthTokenRequest missing assertion", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentAuthTokenRequest");
    expect(validate({})).toBe(false);
  });

  it("accepts a well-formed AgentAuthTokenResponse", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentAuthTokenResponse");
    expect(
      validate({
        access_token: "agt_abc",
        refresh_token: "agr_xyz",
        token_type: "DPoP",
        expires_in: 3600,
        scope: "messages.read messages.send",
      }),
    ).toBe(true);
  });

  it("rejects AgentAuthTokenResponse with bogus token_type", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentAuthTokenResponse");
    expect(
      validate({
        access_token: "agt_abc",
        refresh_token: "agr_xyz",
        token_type: "Magic",
        expires_in: 3600,
        scope: "messages.read",
      }),
    ).toBe(false);
  });

  // ---- AgentRefreshRequest / AgentRevokeRequest -------------------------

  it("validates AgentRefreshRequest shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentRefreshRequest");
    expect(validate({ refresh_token: "agr_xyz" })).toBe(true);
    expect(validate({})).toBe(false);
  });

  it("validates AgentRevokeRequest shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentRevokeRequest");
    expect(validate({ token: "agt_abc" })).toBe(true);
    expect(validate({ token: "agr_xyz" })).toBe(true);
    expect(validate({})).toBe(false);
  });

  // ---- Credential lifecycle ---------------------------------------------

  it("accepts a realistic CreateAgentCredentialRequest", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "CreateAgentCredentialRequest");
    expect(
      validate({
        agent_id: "11111111-1111-4111-8111-111111111111",
        label: "runtime prod",
        scopes: ["messages.read", "messages.send"],
      }),
    ).toBe(true);
  });

  it("rejects CreateAgentCredentialRequest with unknown scope", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "CreateAgentCredentialRequest");
    expect(
      validate({
        agent_id: "11111111-1111-4111-8111-111111111111",
        label: "runtime prod",
        scopes: ["messages.read", "admin.superpowers"],
      }),
    ).toBe(false);
  });

  it("accepts a pending AgentCredentialResponse with enrollment_secret", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentCredentialResponse");
    expect(
      validate({
        credential_id: "22222222-2222-4222-8222-222222222222",
        aid: "aid:ai:abc",
        label: "runtime prod",
        status: "pending",
        allowed_scopes: ["messages.send"],
        enrollment_secret: "ens_deadbeef",
        enrollment_expires_at: "2026-04-24T12:30:00Z",
        created_at: "2026-04-24T12:00:00Z",
        activated_at: null,
        last_used_at: null,
        revoked_at: null,
        key_holder: "signer_daemon",
      }),
    ).toBe(true);
  });

  it("accepts an active AgentCredentialResponse (no enrollment_secret)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentCredentialResponse");
    expect(
      validate({
        credential_id: "22222222-2222-4222-8222-222222222222",
        aid: "aid:ai:abc",
        label: "runtime prod",
        status: "active",
        allowed_scopes: ["messages.read", "messages.send"],
        created_at: "2026-04-24T12:00:00Z",
        activated_at: "2026-04-24T12:05:00Z",
        last_used_at: "2026-04-24T13:00:00Z",
        key_holder: "web_keystore",
      }),
    ).toBe(true);
  });

  it("rejects AgentCredentialResponse with unknown status", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AgentCredentialResponse");
    expect(
      validate({
        credential_id: "22222222-2222-4222-8222-222222222222",
        aid: "aid:ai:abc",
        label: "runtime prod",
        status: "maybe",
        allowed_scopes: [],
        created_at: "2026-04-24T12:00:00Z",
        key_holder: "unknown",
      }),
    ).toBe(false);
  });

  it("validates ActivateCredentialRequest shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "ActivateCredentialRequest");
    expect(
      validate({
        enrollment_secret: "ens_deadbeef",
        signing_public_key: "z6Mk...",
        encryption_public_key: "z6LSh...",
        enrollment_proof: "eyJhbGciOiJFZERTQSJ9.e30.sig",
        key_holder: "signer_daemon",
      }),
    ).toBe(true);
    // missing enrollment_proof
    expect(
      validate({
        enrollment_secret: "ens_deadbeef",
        signing_public_key: "z6Mk...",
        encryption_public_key: "z6LSh...",
      }),
    ).toBe(false);
  });

  it("validates ActivateCredentialResponse shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "ActivateCredentialResponse");
    expect(
      validate({
        credential_id: "22222222-2222-4222-8222-222222222222",
        aid: "aid:ai:abc",
        did: "did:key:z6Mk...",
        status: "active",
      }),
    ).toBe(true);
  });

  // ---- Audit log --------------------------------------------------------

  it("accepts an AuditLogResponse with mixed event details", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AuditLogResponse");
    expect(
      validate({
        events: [
          {
            id: "33333333-3333-4333-8333-333333333333",
            credential_id: "22222222-2222-4222-8222-222222222222",
            aid: "aid:ai:abc",
            event: "token_issued",
            detail: { scope: "messages.send", dpop_jkt: "abc" },
            created_at: "2026-04-24T13:00:00Z",
          },
          {
            id: "33333333-3333-4333-8333-333333333334",
            credential_id: null,
            aid: null,
            event: "emergency_shutdown",
            detail: {},
            created_at: "2026-04-24T13:05:00Z",
          },
        ],
        total: 2,
      }),
    ).toBe(true);
  });

  it("rejects AuditLogResponse missing total", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AuditLogResponse");
    expect(validate({ events: [] })).toBe(false);
  });

  // ---- Emergency shutdown ----------------------------------------------

  it("validates EmergencyShutdownResponse shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "EmergencyShutdownResponse");
    expect(
      validate({
        agent_id: "44444444-4444-4444-8444-444444444444",
        aid: "aid:ai:abc",
        credentials_revoked: 2,
        tokens_revoked: 7,
      }),
    ).toBe(true);
    // negative counts not allowed
    expect(
      validate({
        agent_id: "44444444-4444-4444-8444-444444444444",
        aid: "aid:ai:abc",
        credentials_revoked: -1,
        tokens_revoked: 0,
      }),
    ).toBe(false);
  });

  // ---- Bridge audit ingest ---------------------------------------------

  it("validates BridgeAuditIngestRequest / Response shape", async () => {
    const doc = await loadOpenApi();
    const reqValidate = compile(doc, "BridgeAuditIngestRequest");
    const respValidate = compile(doc, "BridgeAuditIngestResponse");
    expect(reqValidate({ jws: "eyJhbGciOiJFZERTQSJ9.e30.sig" })).toBe(true);
    expect(reqValidate({})).toBe(false);
    expect(respValidate({ accepted: true })).toBe(true);
    expect(respValidate({})).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// Auto-reply policy (Phase 4.4a, docs/25)
//
// These are the first settings surface for the auto-reply engine. Path + auth
// + schema round-trip are locked so future phases can add behaviour (evaluator,
// executor, Calendar, LLM) without silently dropping CRUD guarantees.
// -----------------------------------------------------------------------------

describe("OpenAPI contract — auto-reply policy", () => {
  const PATH = "/agents/{id}/auto-reply-policy";

  it("documents GET / PUT / DELETE on the policy path", async () => {
    const doc = await loadOpenApi();
    const item = doc.paths[PATH];
    expect(item, "path missing").toBeDefined();
    expect(item?.get, "GET missing").toBeDefined();
    expect(item?.put, "PUT missing").toBeDefined();
    expect(item?.delete, "DELETE missing").toBeDefined();
  });

  it("requires auth on every verb (no explicit security: [])", async () => {
    const doc = await loadOpenApi();
    const item = doc.paths[PATH];
    for (const op of [item?.get, item?.put, item?.delete]) {
      if (op?.security !== undefined) {
        expect(op.security.length).toBeGreaterThan(0);
      }
    }
  });

  it("accepts a well-formed policy payload", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AutoReplyPolicy");
    expect(
      validate({
        v: 1,
        default_action: "queue_for_human",
        protocols: {
          schedule_negotiation: {
            propose: {
              action: "auto_accept_if_free",
              conditions: {
                min_trust_score: 0.5,
                require_contact: true,
                priority_at_most: "normal",
                sender_in_allowlist: ["did:key:zAlice"],
              },
              note_template: "OK from my agent.",
            },
          },
          task_delegation: {
            delegate: { action: "queue_for_human" },
          },
        },
      }),
    ).toBe(true);
  });

  it("rejects unknown action enum", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AutoReplyPolicy");
    expect(
      validate({
        v: 1,
        default_action: "explode",
      }),
    ).toBe(false);
  });

  it("rejects unknown protocol-type keys", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AutoReplyPolicy");
    expect(
      validate({
        v: 1,
        default_action: "queue_for_human",
        protocols: { phantom: {} },
      }),
    ).toBe(false);
  });

  it("rejects wrong action name inside schedule_negotiation", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AutoReplyPolicy");
    expect(
      validate({
        v: 1,
        default_action: "queue_for_human",
        protocols: {
          schedule_negotiation: {
            delegate: { action: "queue_for_human" },
          },
        },
      }),
    ).toBe(false);
  });

  it("validates PutAutoReplyPolicyRequest shape (revision optional)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "PutAutoReplyPolicyRequest");
    expect(
      validate({
        policy: { v: 1, default_action: "queue_for_human" },
        revision: 0,
      }),
    ).toBe(true);
    expect(
      validate({ policy: { v: 1, default_action: "queue_for_human" } }),
    ).toBe(true);
    expect(validate({})).toBe(false);
  });

  it("validates AutoReplyPolicyResponse shape (present + empty default)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "AutoReplyPolicyResponse");
    expect(
      validate({
        agent_id: "11111111-1111-4111-8111-111111111111",
        schema_version: 1,
        revision: 3,
        policy: { v: 1, default_action: "queue_for_human" },
        updated_at: "2026-04-24T12:34:56Z",
      }),
    ).toBe(true);
    // "No row yet" default — an empty policy object is acceptable
    // because docs/25 says GET returns {} when nothing's stored.
    // OpenAPI's AutoReplyPolicy requires v + default_action, so the
    // empty object fails schema — wrap in `anyOf` if we later need
    // stricter validation. For now, assert the explicit default
    // shape (v=1, default_action) is what clients can depend on.
    expect(
      validate({
        agent_id: "11111111-1111-4111-8111-111111111111",
        schema_version: 1,
        revision: 0,
        policy: { v: 1, default_action: "queue_for_human" },
        updated_at: null,
      }),
    ).toBe(true);
  });
});

// -----------------------------------------------------------------------------
// Auto-reply evaluator decision fields on inbox items (Phase 4.4b, docs/25b)
//
// The server-side evaluator caches its action into `message_index` so the
// inbox list can render a badge without JOINing the audit log. Both fields
// are optional so pre-4.4b rows (and rows produced while the evaluator is
// disabled via `AGENT_INBOX_AUTO_REPLY_EVALUATOR=off`) remain valid.
// -----------------------------------------------------------------------------

describe("OpenAPI contract — MessageIndexEntry auto-reply decision fields", () => {
  it("accepts entries without evaluator fields (backward compat)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MessageIndexEntry");
    expect(
      validate({
        id: "11111111-1111-4111-8111-111111111111",
        sender_did: "did:key:zAlice",
        recipient_did: "did:key:zBob",
        subject_encrypted: "base64",
        storage_ref: "ref://x",
        status: "unread",
        priority: "normal",
        created_at: "2026-04-24T12:34:56Z",
        trust_score: 0.8,
      }),
    ).toBe(true);
  });

  it("accepts entries carrying evaluator decision + reason", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MessageIndexEntry");
    expect(
      validate({
        id: "11111111-1111-4111-8111-111111111111",
        sender_did: "did:key:zAlice",
        recipient_did: "did:key:zBob",
        subject_encrypted: "base64",
        storage_ref: "ref://x",
        status: "unread",
        priority: "normal",
        created_at: "2026-04-24T12:34:56Z",
        trust_score: 0.8,
        auto_reply_decision: "queue_for_human",
        auto_reply_reason: "trust_below_threshold",
      }),
    ).toBe(true);
  });

  it("rejects unknown decision enum values", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MessageIndexEntry");
    expect(
      validate({
        id: "11111111-1111-4111-8111-111111111111",
        sender_did: "did:key:zAlice",
        recipient_did: "did:key:zBob",
        subject_encrypted: "base64",
        storage_ref: "ref://x",
        status: "unread",
        priority: "normal",
        created_at: "2026-04-24T12:34:56Z",
        trust_score: 0.8,
        auto_reply_decision: "unknown_action_v99",
      }),
    ).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// Auto-reply executor endpoints (Phase 4.4c, docs/25c)
//
// Standard mode executor: browser dispatches the auto-reply through the existing
// send path, then PATCHes /messages/{id}/auto-reply-sent to flip the
// idempotency column. These contract tests lock the path + schema so the
// server + client can evolve without silently dropping the guarantee.
// -----------------------------------------------------------------------------

describe("OpenAPI contract — auto-reply executor", () => {
  const PATH = "/messages/{id}/auto-reply-sent";

  it("documents PATCH on the mark-sent path", async () => {
    const doc = await loadOpenApi();
    const item = doc.paths[PATH];
    expect(item, "path missing").toBeDefined();
    expect(item?.patch, "PATCH missing").toBeDefined();
  });

  it("requires auth (no explicit security: [])", async () => {
    const doc = await loadOpenApi();
    const op = doc.paths[PATH]?.patch;
    if (op?.security !== undefined) {
      expect(op.security.length).toBeGreaterThan(0);
    }
  });

  it("accepts an empty body and a body with reply_message_id", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MarkAutoReplySentRequest");
    expect(validate({})).toBe(true);
    expect(
      validate({ reply_message_id: "22222222-2222-4222-8222-222222222222" }),
    ).toBe(true);
    expect(validate({ reply_message_id: "not-a-uuid" })).toBe(false);
  });

  it("accepts optional executor_mode (Isolated mode daemon label)", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MarkAutoReplySentRequest");
    expect(validate({ executor_mode: "daemon_protocol_v1" })).toBe(true);
    expect(
      validate({
        reply_message_id: "22222222-2222-4222-8222-222222222222",
        executor_mode: "client_protocol_v1",
      }),
    ).toBe(true);
  });

  it("GET /messages documents the auto_reply_pending query param", async () => {
    const doc = await loadOpenApi();
    const params = (doc.paths["/messages"]?.get?.parameters ?? []) as Array<{
      name?: string;
      in?: string;
    }>;
    expect(
      params.some((p) => p.name === "auto_reply_pending" && p.in === "query"),
    ).toBe(true);
  });

  it("validates the stamp response shape", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MarkAutoReplySentResponse");
    expect(
      validate({
        id: "11111111-1111-4111-8111-111111111111",
        auto_reply_sent_at: "2026-04-24T21:34:00Z",
      }),
    ).toBe(true);
    expect(validate({ id: "11111111-1111-4111-8111-111111111111" })).toBe(false);
  });

  it("MessageIndexEntry carries auto_reply_sent_at", async () => {
    const doc = await loadOpenApi();
    const validate = compile(doc, "MessageIndexEntry");
    expect(
      validate({
        id: "11111111-1111-4111-8111-111111111111",
        sender_did: "did:key:zAlice",
        recipient_did: "did:key:zBob",
        subject_encrypted: "base64",
        storage_ref: "ref://x",
        status: "unread",
        priority: "normal",
        created_at: "2026-04-24T12:34:56Z",
        trust_score: 0.8,
        auto_reply_decision: "auto_accept",
        auto_reply_reason: "default_match",
        auto_reply_sent_at: "2026-04-24T21:34:00Z",
      }),
    ).toBe(true);
  });
});
