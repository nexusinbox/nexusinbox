import { createHash } from "node:crypto";
import net from "node:net";

import {
  A2A_CONTENT_TYPE,
  A2A_CURRENT_VERSION,
  assertValidA2APayload,
  serializeA2APayload,
  type A2AMessagePayload,
  type A2AProtocolBlock,
} from "./a2a.js";

// Re-export the A2A surface so consumers can reach it from
// `@nexusinbox/core` without knowing about the `./a2a` sub-module.
// Keep type-only re-exports separate so `isolatedModules` stays happy
// in every downstream bundle.
export {
  A2A_CONTENT_TYPE,
  A2A_CURRENT_VERSION,
  A2AValidationError,
  assertValidA2APayload,
  assertValidScheduleNegotiationPayload,
  assertValidTaskDelegationPayload,
  isA2AContentType,
  isProposeExpired,
  isValidIso8601WithTimezone,
  parseA2APayload,
  SCHEDULE_MAX_CANDIDATES,
  SCHEDULE_MAX_CANDIDATE_DURATION_HOURS,
  serializeA2APayload,
  uuidv7,
} from "./a2a.js";
export type {
  A2AMessagePayload,
  A2AProtocolAction,
  A2AProtocolBlock,
  A2AProtocolType,
  Iso8601WithTimezone,
  ParsedMessageBody,
  ScheduleAcceptPayload,
  ScheduleCandidate,
  ScheduleCounterPayload,
  ScheduleDeclinePayload,
  ScheduleNegotiationPayload,
  ScheduleProposePayload,
  TaskAcceptPayload,
  TaskCompletePayload,
  TaskDeclinePayload,
  TaskDelegatePayload,
  TaskDelegationPayload,
  TaskPriority,
} from "./a2a.js";

/**
 * Local copy of the `AgentKeyHolder` string-literal union so that
 * `ActivateAgentCredentialInput.keyHolder` and
 * `AgentCredentialSummary.key_holder` can reference it without pulling
 * in `./visibility.ts`. That file is published as a separate subpath
 * export (`@nexusinbox/core/visibility`) specifically so the Next.js
 * browser bundle can consume it without dragging in this module's
 * `node:crypto` / `node:net` dependencies.
 *
 * The string-literal set here must stay in lockstep with
 * `AgentKeyHolder` in `./visibility.ts`. Any divergence will surface
 * at compile time — both are string-literal unions that serialise to
 * the same wire values, so no runtime drift is possible.
 */
type AgentKeyHolder = "web_keystore" | "signer_daemon" | "unknown";

export type RecipientResolution = {
  input?: string;
  aid: string;
  did: string;
  label?: string | null;
  signing_public_key?: string;
  encryption_public_key?: string;
  /**
   * Aggregate `key_holder` over the recipient agent's active
   * credentials, surfaced so compose flows can warn when a message
   * won't be readable on the recipient's web UI. Optional for
   * backwards compat — old API builds omit it. See
   * docs/21_message_visibility_ux_for_mcp_modes.md §4.4.
   */
  key_holder?: AgentKeyHolder;
};

export type MessageIndexEntry = {
  id: string;
  sender_did: string;
  sender_label?: string | null;
  recipient_did: string;
  recipient_label?: string | null;
  thread_id?: string | null;
  subject_encrypted: string;
  status: string;
  priority: string;
  ai_category?: string | null;
  created_at: string;
  trust_score: number;
  folder: string;
  starred: boolean;
};

export type MessageListResponse = {
  messages: MessageIndexEntry[];
  total: number;
  page: number;
  per_page: number;
};

export type MessageContentResponse = {
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  sender_did?: string;
  recipient_did?: string;
  subject_encrypted?: string;
  thread_id?: string | null;
};

export type SendMessageResponse = {
  message_id: string;
  status: string;
};

/**
 * Response shape for `POST /attachments/intents`. `upload_url` is an R2
 * presigned PUT URL; `required_headers` must be sent verbatim with the PUT
 * request or R2 will reject the upload.
 */
export type CreateAttachmentIntentResponse = {
  attachment_id: string;
  upload_url: string;
  upload_method: string;
  upload_expires_at: string;
  required_headers: Record<string, string>;
  max_ciphertext_size_bytes: number;
};

export type CompleteAttachmentResponse = {
  attachment_id: string;
  status: string;
};

/**
 * Reference included in the `attachments[]` array of `POST /messages`. The
 * `metadataEncrypted` / `metadataNonce` pair carries filename / MIME / size /
 * key-wrap info — the server treats it as an opaque blob.
 */
export type AttachmentRef = {
  attachmentId: string;
  metadataEncrypted: string;
  metadataNonce: string;
};

/**
 * Plaintext metadata — filled in before encryption. This is what the
 * recipient will see after decrypting `metadataEncrypted`.
 */
export type AttachmentMetadataPlain = {
  filename: string;
  mime: string;
  plaintext_size_bytes: number;
  cipher_algorithm: "aes-gcm-256";
  cipher_nonce: string;
  sha256_plaintext: string;
  attachment_key_wraps: Array<{
    recipient_did: string;
    wrapped_key: string;
  }>;
};

/**
 * Bundle returned from {@link NexusInboxApiClient.encryptAndUploadAttachment}.
 * Ready to embed in `attachments[]` of a `/messages` POST.
 */
export type UploadedAttachment = AttachmentRef & {
  ciphertext_size_bytes: number;
};

export type ActivateAgentCredentialResponse = {
  aid: string;
  did: string;
  credential_id: string;
  status: string;
};

/**
 * Per-credential / per-agent summary fields exposed by the Web API.
 * Kept alongside `ActivateAgentCredentialResponse` so callers can
 * unify the shape when listing credentials.
 */
export type AgentCredentialSummary = {
  credential_id: string;
  aid: string;
  label: string;
  status: string;
  allowed_scopes: string[];
  enrollment_secret?: string | null;
  enrollment_expires_at?: string | null;
  created_at: string;
  activated_at?: string | null;
  last_used_at?: string | null;
  revoked_at?: string | null;
  /**
   * Mirrors the server `key_holder` column (migration 0014). Reflects
   * where this credential's private-key material lives. See
   * `AgentKeyHolder` above + docs/21 §7.
   */
  key_holder: AgentKeyHolder;
};

export type AgentAuthTokenResponse = {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer" | "DPoP";
  expires_in: number;
  scope: string;
};

export type GatewayWhoAmI = {
  aid: string;
  did: string;
  agent_ref?: string | null;
};

export type SendEnvelope = {
  encrypted_content: string;
  encrypted_key: string;
  nonce: string;
  signature?: string;
  metadata: {
    subject_encrypted: string;
    thread_id?: string | null;
    content_type?: string;
    has_attachments?: boolean;
  };
};

export type SendTextMessageInput = {
  senderDid: string;
  recipientDid: string;
  recipientEncryptionPublicKey: string;
  senderSigningPrivateKey: CryptoKey;
  subject: string;
  body: string;
  priority?: "high" | "normal" | "low" | "background";
  threadId?: string;
};

export type DpopKeyPair = {
  privateKey: CryptoKey;
  publicJwk: Record<string, string>;
};

export type ActivateAgentCredentialInput = {
  baseUrl: string;
  credentialId: string;
  enrollmentSecret: string;
  signingKeyPair: CryptoKeyPair;
  encryptionKeyPair: CryptoKeyPair;
  fetchImpl?: typeof fetch;
  /**
   * Optional — tells the server where the private keys will live so
   * the Web UI can later show accurate Standard / Daemon-isolated
   * badges without probing every recipient's keystore. Defaults to
   * `"unknown"` on the server when omitted (treated as Standard mode for
   * display). See docs/21_message_visibility_ux_for_mcp_modes.md §7.
   */
  keyHolder?: AgentKeyHolder;
};

export type ExchangeAgentTokenInput = {
  baseUrl: string;
  aid: string;
  credentialId: string;
  signingPrivateKey: CryptoKey;
  scopes?: string[];
  audience?: string;
  dpop?: DpopKeyPair;
  fetchImpl?: typeof fetch;
};

type EncryptedPayload = {
  v: number;
  alg: "AES-GCM-256";
  kdf: "PBKDF2-SHA256";
  iter: number;
  salt: string;
  iv: string;
  ct: string;
};

const PBKDF2_ITERATIONS = 120_000;

function ensureCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API is required");
  }
  return globalThis.crypto;
}

function encoder(): TextEncoder {
  return new TextEncoder();
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function toBase64UrlJson(value: unknown): string {
  return toBase64Url(encoder().encode(JSON.stringify(value)));
}

function fromBase64Url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  ensureCrypto().getRandomValues(out);
  return out;
}

async function deriveAesKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const crypto = ensureCrypto();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(encoder().encode(passphrase)),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: asArrayBuffer(salt),
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptText(plainText: string, passphrase: string): Promise<EncryptedPayload> {
  const crypto = ensureCrypto();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: asArrayBuffer(iv),
    },
    key,
    asArrayBuffer(encoder().encode(plainText)),
  );

  return {
    v: 1,
    alg: "AES-GCM-256",
    kdf: "PBKDF2-SHA256",
    iter: PBKDF2_ITERATIONS,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ct: toBase64Url(new Uint8Array(ciphertext)),
  };
}

function serializeEncryptedPayload(payload: EncryptedPayload): string {
  return `enc:v${payload.v}:${payload.kdf}:${payload.alg}:${payload.iter}:${payload.salt}:${payload.iv}:${payload.ct}`;
}

function sha256Base64Url(text: string): string {
  const digest = createHash("sha256").update(text).digest();
  return toBase64Url(new Uint8Array(digest));
}

export function generateContentKey(): string {
  return toBase64Url(randomBytes(32));
}

// Visibility helpers (AgentKeyHolder, MessageVisibilityState,
// deriveMessageState) live in `./visibility.ts` and are published via
// the `@nexusinbox/core/visibility` subpath — importing from there
// avoids pulling this file's node:crypto / node:net dependencies into
// the Next.js browser bundle. Node callers (MCP runtime, tests) can
// import from the same subpath too; there's intentionally no
// re-export from the main entry so the module graphs stay clean.

export function isValidX25519PublicKeyB64Url(publicKeyB64Url: string): boolean {
  try {
    return fromBase64Url(publicKeyB64Url).byteLength === 32;
  } catch {
    return false;
  }
}

export function isValidEd25519PublicKeyB64Url(publicKeyB64Url: string): boolean {
  try {
    return fromBase64Url(publicKeyB64Url).byteLength === 32;
  } catch {
    return false;
  }
}

async function deriveWrapKey(sharedSecret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const crypto = ensureCrypto();
  const hkdfKey = await crypto.subtle.importKey("raw", asArrayBuffer(sharedSecret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asArrayBuffer(salt),
      info: asArrayBuffer(encoder().encode("nexusinbox/x25519-wrap/v1")),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function wrapContentKeyForRecipient(
  contentKey: string,
  recipientPublicKeyB64Url: string,
): Promise<string> {
  if (!isValidX25519PublicKeyB64Url(recipientPublicKeyB64Url)) {
    throw new Error("invalid x25519 public key format");
  }

  const crypto = ensureCrypto();
  const recipientPublicKey = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(fromBase64Url(recipientPublicKeyB64Url)),
    { name: "X25519" },
    false,
    [],
  );
  const ephemeral = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: recipientPublicKey },
    ephemeral.privateKey,
    256,
  );
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const wrapKey = await deriveWrapKey(new Uint8Array(sharedBits), salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: asArrayBuffer(iv) },
    wrapKey,
    asArrayBuffer(encoder().encode(contentKey)),
  );
  const ephemeralRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  return `x25519v1:${toBase64Url(ephemeralRaw)}:${toBase64Url(salt)}:${toBase64Url(iv)}:${toBase64Url(new Uint8Array(ciphertext))}`;
}

export async function signEnvelopePayload(params: {
  signingPrivateKey: CryptoKey;
  senderDid: string;
  recipientDid: string;
  subjectEncrypted: string;
  encryptedContent: string;
  encryptedKey: string;
  nonce: string;
}): Promise<string> {
  const crypto = ensureCrypto();
  const payload = [
    params.senderDid,
    params.recipientDid,
    params.subjectEncrypted,
    params.encryptedContent,
    params.encryptedKey,
    params.nonce,
  ].join("\n");
  const signature = await crypto.subtle.sign(
    "Ed25519",
    params.signingPrivateKey,
    asArrayBuffer(encoder().encode(payload)),
  );
  return toBase64Url(new Uint8Array(signature));
}

export async function buildEncryptedTextEnvelope(input: SendTextMessageInput): Promise<SendEnvelope> {
  const contentKey = generateContentKey();
  const encryptedSubject = await encryptText(input.subject, contentKey);
  const encryptedBody = await encryptText(input.body, contentKey);
  const subjectEncrypted = serializeEncryptedPayload(encryptedSubject);
  const encryptedContent = serializeEncryptedPayload(encryptedBody);
  const encryptedKey = await wrapContentKeyForRecipient(contentKey, input.recipientEncryptionPublicKey);
  const signature = await signEnvelopePayload({
    signingPrivateKey: input.senderSigningPrivateKey,
    senderDid: input.senderDid,
    recipientDid: input.recipientDid,
    subjectEncrypted,
    encryptedContent,
    encryptedKey,
    nonce: encryptedBody.iv,
  });

  return {
    encrypted_content: encryptedContent,
    encrypted_key: encryptedKey,
    nonce: encryptedBody.iv,
    signature,
    metadata: {
      subject_encrypted: subjectEncrypted,
      thread_id: input.threadId,
      content_type: "text/plain",
      has_attachments: false,
    },
  };
}

// ---------------------------------------------------------------------------
// A2A envelope builder
// ---------------------------------------------------------------------------

export type SendA2AMessageInput = Omit<SendTextMessageInput, "body"> & {
  /**
   * Human-readable summary, shown to legacy clients that don't know
   * how to render the structured protocol block. Empty string is
   * allowed but strongly discouraged — pick a short one-line
   * summary so notification previews and legacy renderers degrade
   * gracefully. See docs/24 §6 Compatibility Matrix.
   */
  body: string;
  /**
   * Optional structured protocol payload. When present the envelope's
   * `metadata.content_type` is set to the A2A MIME so receivers can
   * dispatch on it. When absent this function is equivalent to
   * `buildEncryptedTextEnvelope` except that the body is serialised
   * as an A2A v=1 JSON — which is a legitimate but unusual shape;
   * most plain-text callers should keep using
   * `buildEncryptedTextEnvelope`.
   */
  protocol?: A2AProtocolBlock;
};

/**
 * Build an E2E envelope whose decrypted body is an A2A v=1 JSON
 * document. Thin wrapper around {@link buildEncryptedTextEnvelope}
 * — the signature lives on ciphertext so the protocol block is
 * inside the encryption boundary and the signature verifier has
 * nothing extra to check.
 *
 * Validates the protocol payload before serialisation so invalid
 * input (bad timestamps, candidate count limits, etc.) fails
 * locally with a clear error instead of landing in the recipient's
 * inbox as an unreadable A2A message.
 */
export async function buildA2AEnvelope(input: SendA2AMessageInput): Promise<SendEnvelope> {
  if (input.protocol) {
    // Dispatch on protocol.type so each A2A type's validator runs
    // without cross-contamination. See packages/core/src/a2a.ts
    // for the per-type rules and assertValidA2APayload's exhaustive
    // switch.
    assertValidA2APayload(input.protocol);
  }
  const a2aPayload: A2AMessagePayload = {
    v: A2A_CURRENT_VERSION,
    body: input.body,
    ...(input.protocol ? { protocol: input.protocol } : {}),
  };
  const serialised = serializeA2APayload(a2aPayload);

  const contentKey = generateContentKey();
  const encryptedSubject = await encryptText(input.subject, contentKey);
  const encryptedBody = await encryptText(serialised, contentKey);
  const subjectEncrypted = serializeEncryptedPayload(encryptedSubject);
  const encryptedContent = serializeEncryptedPayload(encryptedBody);
  const encryptedKey = await wrapContentKeyForRecipient(
    contentKey,
    input.recipientEncryptionPublicKey,
  );
  const signature = await signEnvelopePayload({
    signingPrivateKey: input.senderSigningPrivateKey,
    senderDid: input.senderDid,
    recipientDid: input.recipientDid,
    subjectEncrypted,
    encryptedContent,
    encryptedKey,
    nonce: encryptedBody.iv,
  });

  return {
    encrypted_content: encryptedContent,
    encrypted_key: encryptedKey,
    nonce: encryptedBody.iv,
    signature,
    metadata: {
      subject_encrypted: subjectEncrypted,
      thread_id: input.threadId,
      content_type: input.protocol ? A2A_CONTENT_TYPE : "text/plain",
      has_attachments: false,
    },
  };
}

export async function createEd25519KeyPair(): Promise<CryptoKeyPair> {
  return (await ensureCrypto().subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
}

export async function createX25519KeyPair(): Promise<CryptoKeyPair> {
  return (await ensureCrypto().subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
}

export async function exportRawPublicKeyBase64Url(publicKey: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await ensureCrypto().subtle.exportKey("raw", publicKey));
  return toBase64Url(raw);
}

export async function deriveDidKeyFromPublicKey(publicKey: CryptoKey): Promise<string> {
  const raw = new Uint8Array(await ensureCrypto().subtle.exportKey("raw", publicKey));
  const multicodec = new Uint8Array(2 + raw.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(raw, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

function base58Encode(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  if (bytes.length === 0) return "";

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const value = digits[i] * 256 + carry;
      digits[i] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;

  let output = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    output += alphabet[digits[i]];
  }
  return output;
}

async function signCompactJws(privateKey: CryptoKey, header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string> {
  const signingInput = `${toBase64UrlJson(header)}.${toBase64UrlJson(payload)}`;
  const signature = await ensureCrypto().subtle.sign("Ed25519", privateKey, asArrayBuffer(encoder().encode(signingInput)));
  return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
}

export async function buildEnrollmentProof(params: {
  credentialId: string;
  signingPrivateKey: CryptoKey;
  now?: number;
}): Promise<string> {
  return signCompactJws(
    params.signingPrivateKey,
    { alg: "EdDSA", typ: "JWT" },
    {
      credential_id: params.credentialId,
      iat: params.now ?? Math.floor(Date.now() / 1000),
    },
  );
}

export async function buildAgentAssertion(params: {
  aid: string;
  credentialId: string;
  signingPrivateKey: CryptoKey;
  audience: string;
  scopes?: string[];
  now?: number;
  expiresInSeconds?: number;
}): Promise<string> {
  const now = params.now ?? Math.floor(Date.now() / 1000);
  return signCompactJws(
    params.signingPrivateKey,
    { alg: "EdDSA", typ: "JWT" },
    {
      iss: params.aid,
      sub: params.credentialId,
      aud: params.audience,
      jti: globalThis.crypto.randomUUID(),
      iat: now,
      exp: now + (params.expiresInSeconds ?? 60),
      scope: (params.scopes ?? ["messages.read", "messages.send"]).join(" "),
    },
  );
}

export async function activateAgentCredential(
  input: ActivateAgentCredentialInput,
): Promise<ActivateAgentCredentialResponse> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const signingPublicKey = await exportRawPublicKeyBase64Url(input.signingKeyPair.publicKey);
  const encryptionPublicKey = await exportRawPublicKeyBase64Url(input.encryptionKeyPair.publicKey);
  const enrollmentProof = await buildEnrollmentProof({
    credentialId: input.credentialId,
    signingPrivateKey: input.signingKeyPair.privateKey,
  });

  const response = await fetchImpl(
    `${input.baseUrl.replace(/\/+$/, "")}/agent-credentials/${input.credentialId}/activate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        enrollment_secret: input.enrollmentSecret,
        signing_public_key: signingPublicKey,
        encryption_public_key: encryptionPublicKey,
        enrollment_proof: enrollmentProof,
        // Only include when the caller supplied a value, so the
        // server's default ('unknown') keeps applying for older
        // call sites that haven't been updated yet. Unknown strings
        // are clamped server-side by normalise_key_holder.
        ...(input.keyHolder ? { key_holder: input.keyHolder } : {}),
      }),
    },
  );
  return parseJsonResponse<ActivateAgentCredentialResponse>(response);
}

export async function exchangeAgentToken(
  input: ExchangeAgentTokenInput,
): Promise<AgentAuthTokenResponse & { dpop: DpopKeyPair }> {
  const fetchImpl = input.fetchImpl ?? fetch;
  const dpop = input.dpop ?? (await createDpopKeyPair());
  const baseUrl = input.baseUrl.replace(/\/+$/, "");
  const assertion = await buildAgentAssertion({
    aid: input.aid,
    credentialId: input.credentialId,
    signingPrivateKey: input.signingPrivateKey,
    audience: input.audience ?? `${baseUrl}/agent-auth/token`,
    scopes: input.scopes,
  });

  const response = await fetchImpl(`${baseUrl}/agent-auth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      assertion,
      dpop_jwk: dpop.publicJwk,
    }),
  });
  const tokens = await parseJsonResponse<AgentAuthTokenResponse>(response);
  return { ...tokens, dpop };
}

export async function createAuthenticatedApiClient(input: ExchangeAgentTokenInput): Promise<{
  client: NexusInboxApiClient;
  tokens: AgentAuthTokenResponse;
  dpop: DpopKeyPair;
}> {
  const { dpop, ...tokens } = await exchangeAgentToken(input);
  return {
    client: new NexusInboxApiClient({
      baseUrl: input.baseUrl,
      accessToken: tokens.access_token,
      dpop,
      fetchImpl: input.fetchImpl,
    }),
    tokens,
    dpop,
  };
}

export async function createDpopKeyPair(): Promise<DpopKeyPair> {
  const pair = (await createEd25519KeyPair()) as CryptoKeyPair;
  const jwk = (await ensureCrypto().subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return {
    privateKey: pair.privateKey,
    publicJwk: {
      kty: String(jwk.kty),
      crv: String(jwk.crv),
      x: String(jwk.x),
    },
  };
}

async function buildDpopProof(params: {
  privateKey: CryptoKey;
  publicJwk: Record<string, string>;
  method: string;
  url: string;
  accessToken: string;
}): Promise<string> {
  const header = {
    typ: "dpop+jwt",
    alg: "EdDSA",
    jwk: params.publicJwk,
  };
  const parsed = new URL(params.url);
  const payload = {
    htm: params.method.toUpperCase(),
    htu: parsed.pathname,
    iat: Math.floor(Date.now() / 1000),
    jti: globalThis.crypto.randomUUID(),
    ath: sha256Base64Url(params.accessToken),
  };
  const signingInput = `${toBase64Url(encoder().encode(JSON.stringify(header)))}.${toBase64Url(
    encoder().encode(JSON.stringify(payload)),
  )}`;
  const signature = await ensureCrypto().subtle.sign(
    "Ed25519",
    params.privateKey,
    asArrayBuffer(encoder().encode(signingInput)),
  );
  return `${signingInput}.${toBase64Url(new Uint8Array(signature))}`;
}

async function parseJsonResponse<T>(response: Response): Promise<T> {
  const text = await response.text();
  const data = text ? (JSON.parse(text) as T) : ({} as T);
  if (!response.ok) {
    throw new Error(`API returned ${response.status}: ${text}`);
  }
  return data;
}

/**
 * Callback returning a fresh access token + DPoP keypair when the
 * current pair expires. The client invokes this once per request that
 * returns 401 and retries with the refreshed credentials. Long-running
 * processes (Signer Daemon, MCP server) wire this to a JWS-Assertion
 * re-issuance closure so they don't have to track token TTLs themselves.
 */
export type RefreshCredentials = () => Promise<{
  accessToken: string;
  dpop: DpopKeyPair;
}>;

export class NexusInboxApiClient {
  private readonly baseUrl: string;
  private accessToken: string;
  private dpop: DpopKeyPair;
  private readonly fetchImpl: typeof fetch;
  private readonly onUnauthorized?: RefreshCredentials;

  constructor(options: {
    baseUrl: string;
    accessToken: string;
    dpop: DpopKeyPair;
    fetchImpl?: typeof fetch;
    /**
     * Optional refresh callback. When set, requests that return 401 are
     * retried once after invoking this callback to obtain a fresh
     * access token + DPoP keypair. Without it, 401 surfaces directly to
     * the caller (legacy behavior).
     */
    onUnauthorized?: RefreshCredentials;
  }) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.accessToken = options.accessToken;
    this.dpop = options.dpop;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.onUnauthorized = options.onUnauthorized;
  }

  private async dispatch(method: string, url: string, body?: unknown): Promise<Response> {
    const dpop = await buildDpopProof({
      privateKey: this.dpop.privateKey,
      publicJwk: this.dpop.publicJwk,
      method,
      url,
      accessToken: this.accessToken,
    });
    return this.fetchImpl(url, {
      method,
      headers: {
        Authorization: `DPoP ${this.accessToken}`,
        DPoP: dpop,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    let response = await this.dispatch(method, url, body);
    // 401 → invoke refresh callback (if wired) and retry once. Bounded to
    // a single retry so a persistently-failing token doesn't loop.
    if (response.status === 401 && this.onUnauthorized) {
      const refreshed = await this.onUnauthorized();
      this.accessToken = refreshed.accessToken;
      this.dpop = refreshed.dpop;
      response = await this.dispatch(method, url, body);
    }
    return parseJsonResponse<T>(response);
  }

  resolveRecipient(identifier: string): Promise<RecipientResolution> {
    return this.request("GET", `/recipients/resolve?identifier=${encodeURIComponent(identifier)}`);
  }

  listMessages(params: { agentDid: string; folder?: string; status?: string }): Promise<MessageListResponse> {
    const query = new URLSearchParams({
      agent_did: params.agentDid,
      folder: params.folder ?? "inbox",
      status: params.status ?? "all",
    });
    return this.request("GET", `/messages?${query.toString()}`);
  }

  readMessage(messageId: string): Promise<MessageContentResponse> {
    return this.request("GET", `/messages/${messageId}/content`);
  }

  sendMessage(params: {
    senderDid: string;
    recipientDid: string;
    envelope: SendEnvelope;
    priority?: "high" | "normal" | "low" | "background";
    attachments?: AttachmentRef[];
  }): Promise<SendMessageResponse> {
    const body: Record<string, unknown> = {
      sender_did: params.senderDid,
      recipient_did: params.recipientDid,
      envelope: params.envelope,
      priority: params.priority ?? "normal",
    };
    if (params.attachments && params.attachments.length > 0) {
      body.attachments = params.attachments.map((ref) => ({
        attachment_id: ref.attachmentId,
        metadata_encrypted: ref.metadataEncrypted,
        metadata_nonce: ref.metadataNonce,
      }));
    }
    return this.request("POST", "/messages", body);
  }

  async sendTextMessage(
    input: SendTextMessageInput & { attachments?: AttachmentRef[] },
  ): Promise<SendMessageResponse> {
    const envelope = await buildEncryptedTextEnvelope(input);
    if (input.attachments && input.attachments.length > 0) {
      envelope.metadata.has_attachments = true;
    }
    return this.sendMessage({
      senderDid: input.senderDid,
      recipientDid: input.recipientDid,
      envelope,
      priority: input.priority,
      attachments: input.attachments,
    });
  }

  /**
   * Step 1 of the attachment flow: reserve an attachment_id and obtain an R2
   * presigned PUT URL. See docs/17_attachment_upload_r2_spec.md.
   */
  createAttachmentIntent(params: {
    senderDid?: string;
    draftId?: string;
    ciphertextSizeBytes: number;
  }): Promise<CreateAttachmentIntentResponse> {
    return this.request("POST", "/attachments/intents", {
      sender_did: params.senderDid,
      draft_id: params.draftId,
      ciphertext_size_bytes: params.ciphertextSizeBytes,
    });
  }

  /**
   * Step 2: PUT the encrypted bytes to R2 using the `upload_url` + exact
   * `required_headers` from the intent. R2 enforces the headers; any
   * mismatch fails the upload.
   */
  async uploadAttachmentCiphertext(params: {
    intent: CreateAttachmentIntentResponse;
    ciphertext: Uint8Array;
  }): Promise<void> {
    const response = await this.fetchImpl(params.intent.upload_url, {
      method: params.intent.upload_method,
      headers: params.intent.required_headers,
      body: asArrayBuffer(params.ciphertext),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(
        `attachment ciphertext upload failed: ${response.status} ${text}`,
      );
    }
  }

  /**
   * Step 3: confirm the upload. The server validates the reported size
   * matches the R2 object (via HEAD) before flipping the row to `uploaded`.
   */
  completeAttachment(params: {
    attachmentId: string;
    ciphertextSizeBytes: number;
  }): Promise<CompleteAttachmentResponse> {
    return this.request("POST", `/attachments/${params.attachmentId}/complete`, {
      ciphertext_size_bytes: params.ciphertextSizeBytes,
    });
  }

  /**
   * High-level helper: encrypts the plaintext with a fresh AES-GCM content key,
   * wraps the key for the supplied recipients (plus the sender for self-view),
   * uploads the ciphertext to R2, completes the intent, and returns the
   * AttachmentRef ready to embed in `sendMessage({ attachments })`.
   *
   * The cipher nonce prepends the ciphertext so the recipient can split it
   * off on decrypt — matching the in-browser implementation.
   */
  async encryptAndUploadAttachment(params: {
    plaintext: Uint8Array;
    filename: string;
    mimeType: string;
    senderDid?: string;
    draftId?: string;
    /** did + encryption_public_key pairs for each recipient + the sender */
    keyWrapTargets: Array<{ did: string; encryptionPublicKeyB64Url: string }>;
  }): Promise<UploadedAttachment> {
    const crypto = ensureCrypto();
    const contentKeyBytes = randomBytes(32);
    const cipherNonce = randomBytes(12);
    const contentKeyB64 = toBase64Url(contentKeyBytes);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      asArrayBuffer(contentKeyBytes),
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: asArrayBuffer(cipherNonce) },
        cryptoKey,
        asArrayBuffer(params.plaintext),
      ),
    );

    // Prepend nonce to ciphertext so the stored blob is self-contained.
    const blob = new Uint8Array(cipherNonce.length + ciphertext.length);
    blob.set(cipherNonce, 0);
    blob.set(ciphertext, cipherNonce.length);

    // Wrap the content key for each intended reader.
    const wraps = await Promise.all(
      params.keyWrapTargets.map(async (target) => ({
        recipient_did: target.did,
        wrapped_key: await wrapContentKeyForRecipient(
          contentKeyB64,
          target.encryptionPublicKeyB64Url,
        ),
      })),
    );

    const sha = new Uint8Array(
      await crypto.subtle.digest("SHA-256", asArrayBuffer(params.plaintext)),
    );
    const metadata: AttachmentMetadataPlain = {
      filename: params.filename,
      mime: params.mimeType,
      plaintext_size_bytes: params.plaintext.byteLength,
      cipher_algorithm: "aes-gcm-256",
      cipher_nonce: toBase64Url(cipherNonce),
      sha256_plaintext: toBase64Url(sha),
      attachment_key_wraps: wraps,
    };

    // Encrypt metadata with the same content key but a fresh nonce so the
    // server's `metadata_nonce` column is meaningful.
    const metaNonce = randomBytes(12);
    const metaCryptoKey = await crypto.subtle.importKey(
      "raw",
      asArrayBuffer(contentKeyBytes),
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    const metaCiphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: asArrayBuffer(metaNonce) },
        metaCryptoKey,
        asArrayBuffer(encoder().encode(JSON.stringify(metadata))),
      ),
    );

    const intent = await this.createAttachmentIntent({
      senderDid: params.senderDid,
      draftId: params.draftId,
      ciphertextSizeBytes: blob.byteLength,
    });
    await this.uploadAttachmentCiphertext({ intent, ciphertext: blob });
    await this.completeAttachment({
      attachmentId: intent.attachment_id,
      ciphertextSizeBytes: blob.byteLength,
    });

    return {
      attachmentId: intent.attachment_id,
      metadataEncrypted: toBase64Url(metaCiphertext),
      metadataNonce: toBase64Url(metaNonce),
      ciphertext_size_bytes: blob.byteLength,
    };
  }
}

type GatewayRpcEnvelope = Omit<SendEnvelope, "signature"> & { signature?: string };

type GatewayRpcResponse<T> = {
  id: number;
  result?: T;
  error?: { code: number; message: string };
};

export class NexusInboxGatewayClient {
  private readonly socketPath: string;
  private readonly rpcTransport?: (method: string, params: Record<string, unknown>) => Promise<unknown>;

  constructor(options?: {
    socketPath?: string;
    rpcTransport?: (method: string, params: Record<string, unknown>) => Promise<unknown>;
  }) {
    this.socketPath = options?.socketPath ?? "/tmp/nexusinbox-gateway.sock";
    this.rpcTransport = options?.rpcTransport;
  }

  call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    if (this.rpcTransport) {
      return this.rpcTransport(method, params).then((result) => result as T);
    }
    return new Promise((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      let buffer = "";

      socket.on("connect", () => {
        socket.write(`${JSON.stringify({ id: 1, method, params })}\n`);
      });

      socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        const newline = buffer.indexOf("\n");
        if (newline === -1) return;

        const line = buffer.slice(0, newline).trim();
        socket.end();
        try {
          const response = JSON.parse(line) as GatewayRpcResponse<T>;
          if (response.error) {
            reject(new Error(response.error.message));
            return;
          }
          resolve(response.result as T);
        } catch (error) {
          reject(error);
        }
      });

      socket.on("error", reject);
    });
  }

  whoami(): Promise<GatewayWhoAmI> {
    return this.call("whoami");
  }

  resolveRecipient(identifier: string): Promise<RecipientResolution> {
    return this.call("resolve_recipient", { identifier });
  }

  listInbox(params?: { folder?: string; status?: string }): Promise<MessageListResponse> {
    return this.call("list_inbox", {
      folder: params?.folder ?? "inbox",
      status: params?.status ?? "all",
    });
  }

  readMessage(messageId: string): Promise<MessageContentResponse> {
    return this.call("read_message", { message_id: messageId });
  }

  sendMessage(params: { recipientDid: string; envelope: GatewayRpcEnvelope }): Promise<SendMessageResponse> {
    return this.call("send_message", {
      recipient_did: params.recipientDid,
      envelope: params.envelope,
    });
  }

  /**
   * Phase 2.5 — ask the daemon (via the Gateway) to unwrap a
   * `x25519v1:...` wrapped content key so Isolated mode callers can decrypt
   * the body with a local `decryptText`. The daemon keeps the X25519
   * private half; the Gateway only sees the (encrypted_key in →
   * content_key out) mapping.
   *
   * Returns the JWK-ish content_key string (as produced by the
   * web-side `wrapContentKeyForRecipient`).
   */
  unwrapContentKey(encryptedKey: string): Promise<string> {
    return this.call<{ content_key: string }>("unwrap_content_key", {
      encrypted_key: encryptedKey,
    }).then((result) => result.content_key);
  }
}
