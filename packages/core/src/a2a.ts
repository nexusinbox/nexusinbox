// Agent-to-Agent (A2A) Protocol v1 — type definitions, payload
// serialisation, and client-side validation.
//
// Design lives in docs/24_a2a_protocol_design.md. The short version:
//
//   Inside the existing E2E envelope, `encrypted_content` carries a
//   JSON document of shape `{ v: 1, body, protocol? }`. The server
//   never sees past the ciphertext, so extending the protocol is a
//   zero-migration client-side change. `envelope.metadata.content_type`
//   is set to `application/vnd.nexusinbox.a2a+json; v=1` so receivers
//   know to parse instead of treating the body as text/plain.
//
// Versioning: additive fields stay on v=1; only breaking changes bump
// v. See docs/24 §9 Versioning Policy.

export const A2A_CONTENT_TYPE = "application/vnd.nexusinbox.a2a+json; v=1";
export const A2A_CURRENT_VERSION = 1;
export const SCHEDULE_MAX_CANDIDATES = 20;
export const SCHEDULE_MAX_CANDIDATE_DURATION_HOURS = 24;

// --- Timestamps ------------------------------------------------------------

/**
 * Regex for ISO 8601 date-time with an explicit timezone — either `Z`
 * (UTC) or `±HH:MM` offset. Plain naive strings like
 * `"2026-06-01T15:00:00"` are rejected because they lose the
 * sender's intent about timezone.
 */
const ISO8601_WITH_TZ =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export function isValidIso8601WithTimezone(value: string): boolean {
  if (typeof value !== "string") return false;
  if (!ISO8601_WITH_TZ.test(value)) return false;
  const ms = Date.parse(value);
  return Number.isFinite(ms);
}

// --- UUIDv7 generator ------------------------------------------------------

/**
 * UUIDv7 (time-ordered UUID). We prefer v7 over v4 so protocol IDs
 * sort naturally by creation time — useful for debugging and for
 * correlation between propose / accept exchanges. Spec:
 * https://datatracker.ietf.org/doc/rfc9562/ §5.7
 */
export function uuidv7(): string {
  const ms = BigInt(Date.now());
  const bytes = new Uint8Array(16);
  // 48 bits of unix_ts_ms
  bytes[0] = Number((ms >> 40n) & 0xffn);
  bytes[1] = Number((ms >> 32n) & 0xffn);
  bytes[2] = Number((ms >> 24n) & 0xffn);
  bytes[3] = Number((ms >> 16n) & 0xffn);
  bytes[4] = Number((ms >> 8n) & 0xffn);
  bytes[5] = Number(ms & 0xffn);
  // 74 bits of randomness in bytes 6..15, with version/variant bits overlaid.
  const rand = new Uint8Array(10);
  ensureCryptoRandom(rand);
  bytes.set(rand, 6);
  // Version = 0111 in the high nibble of byte 6
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  // Variant = 10xx in the high bits of byte 8
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function ensureCryptoRandom(into: Uint8Array) {
  const g = globalThis as { crypto?: Crypto };
  if (g.crypto && typeof g.crypto.getRandomValues === "function") {
    g.crypto.getRandomValues(into);
    return;
  }
  throw new Error("crypto.getRandomValues is not available in this environment");
}

// --- schedule_negotiation payloads -----------------------------------------

/**
 * Wall-clock time with an explicit timezone offset. See
 * {@link isValidIso8601WithTimezone} for the accepted shape.
 */
export type Iso8601WithTimezone = string;

export interface ScheduleCandidate {
  start: Iso8601WithTimezone;
  end: Iso8601WithTimezone;
}

export type ScheduleNegotiationPayload =
  | ScheduleProposePayload
  | ScheduleAcceptPayload
  | ScheduleDeclinePayload
  | ScheduleCounterPayload;

export interface ScheduleProposePayload {
  event_title: string;
  candidates: ScheduleCandidate[];
  required_participants: string[];
  response_deadline?: Iso8601WithTimezone;
}

export interface ScheduleAcceptPayload {
  /**
   * Echo back the chosen candidate's `start`/`end`. This is NOT a
   * replay defence (Ed25519 signature + `protocol.id` uniqueness
   * handle that). It is a context binding: it tells the proposer
   * exactly which candidate the acceptance refers to, even if the
   * proposer edited their list between messages, and keeps
   * UI idempotency logic simple. See docs/24 §7.1.
   */
  selected_candidate: ScheduleCandidate;
}

export interface ScheduleDeclinePayload {
  reason?: string;
}

export interface ScheduleCounterPayload {
  candidates: ScheduleCandidate[];
  reason?: string;
}

// --- task_delegation payloads ---------------------------------------------

/**
 * `task_delegation` lets one agent hand off a piece of work to
 * another. The state machine is much flatter than
 * schedule_negotiation — there's no timezone negotiation, just a
 * linear delegate → accept/decline → (optionally) complete chain.
 */

export type TaskPriority = "high" | "normal" | "low";

export interface TaskDelegatePayload {
  title: string;
  description?: string;
  /**
   * ISO 8601 with an explicit timezone offset (Z or ±HH:MM), same
   * rules as schedule_negotiation timestamps.
   */
  due_date?: Iso8601WithTimezone;
  priority?: TaskPriority;
}

export interface TaskAcceptPayload {
  note?: string;
}

export interface TaskDeclinePayload {
  reason?: string;
}

export interface TaskCompletePayload {
  /**
   * Short human-readable completion summary or a pointer to a
   * larger artifact the delegator can follow up on (URL, doc
   * reference, etc.). Intentionally plain text so the delegator
   * can inspect it without needing to parse a structured schema.
   */
  result?: string;
}

export type TaskDelegationPayload =
  | TaskDelegatePayload
  | TaskAcceptPayload
  | TaskDeclinePayload
  | TaskCompletePayload;

// --- Protocol block + top-level payload ------------------------------------

export type A2AProtocolType = "schedule_negotiation" | "task_delegation";
export type A2AProtocolAction =
  // schedule_negotiation actions
  | "propose"
  | "accept"
  | "decline"
  | "counter"
  // task_delegation actions — "accept" / "decline" overlap with
  // schedule_negotiation by design (same UI affordance, same
  // response semantics), so they stay as shared tokens.
  | "delegate"
  | "complete";

/**
 * The `protocol` field inside the decrypted envelope body. `id`
 * uniquely identifies this exchange; `reply_to` links back to the
 * `id` of an earlier message in the same protocol conversation
 * (independent of the envelope-level `thread_id`, which is the
 * inbox UI's grouping).
 */
export interface A2AProtocolBlock {
  id: string;
  type: A2AProtocolType;
  action: A2AProtocolAction;
  reply_to: string | null;
  payload: ScheduleNegotiationPayload | TaskDelegationPayload;
}

export interface A2AMessagePayload {
  v: 1;
  body: string;
  protocol?: A2AProtocolBlock;
}

/**
 * Result of parsing a decrypted message body in the context of a
 * content_type. `protocol` is present only when we recognised an
 * A2A payload; `parse_error` is set when the content_type claimed
 * A2A but the body didn't parse (a client bug on the sender side).
 */
export interface ParsedMessageBody {
  body: string;
  protocol: A2AProtocolBlock | null;
  parse_error?: true;
}

// --- Public parsing API ----------------------------------------------------

/**
 * Parse a decrypted message body, using the envelope's content_type
 * as the dispatcher. The caller is expected to have already
 * decrypted the ciphertext into `raw`; this function only handles
 * the JSON-vs-legacy-text shape.
 *
 * Contract:
 * - `contentType` starting with `application/vnd.nexusinbox.a2a+json`
 *   → try JSON.parse; on success return the typed payload, on
 *   failure return the raw string with `parse_error: true`.
 * - Any other content type (including `text/plain`, markdown, or
 *   undefined) → treat as legacy text; do NOT try JSON.parse because
 *   plain text that happens to start with `{` would give a false
 *   positive.
 */
export function parseA2APayload(
  raw: string,
  contentType?: string | null,
): ParsedMessageBody {
  if (!isA2AContentType(contentType)) {
    return { body: raw, protocol: null };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { body: raw, protocol: null, parse_error: true };
  }
  if (!isA2AMessagePayload(parsed)) {
    return { body: raw, protocol: null, parse_error: true };
  }
  const protocolBlock =
    parsed.protocol && isA2AProtocolBlock(parsed.protocol)
      ? parsed.protocol
      : null;
  return {
    body: typeof parsed.body === "string" ? parsed.body : "",
    protocol: protocolBlock,
  };
}

export function isA2AContentType(contentType: string | null | undefined): boolean {
  if (!contentType) return false;
  return contentType
    .toLowerCase()
    .startsWith("application/vnd.nexusinbox.a2a+json");
}

// --- Serialisation ---------------------------------------------------------

/**
 * Build the JSON string that goes inside `encrypted_content` for an
 * A2A message. When `protocol` is omitted the caller is just sending
 * a plain text message with the A2A envelope shape — legal but
 * unusual; most plain text callers should keep using the classic
 * `buildEncryptedTextEnvelope` path instead.
 */
export function serializeA2APayload(payload: A2AMessagePayload): string {
  return JSON.stringify(payload);
}

// --- Validation ------------------------------------------------------------

export class A2AValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "A2AValidationError";
  }
}

export function assertValidScheduleNegotiationPayload(
  action: A2AProtocolAction,
  payload: ScheduleNegotiationPayload,
): void {
  switch (action) {
    case "propose":
      assertValidProposePayload(payload as ScheduleProposePayload);
      return;
    case "accept":
      assertValidScheduleAcceptPayload(payload as ScheduleAcceptPayload);
      return;
    case "decline":
      assertValidReasonOnlyPayload(
        payload as ScheduleDeclinePayload,
        "schedule decline",
      );
      return;
    case "counter":
      assertValidCounterPayload(payload as ScheduleCounterPayload);
      return;
    case "delegate":
    case "complete":
      throw new A2AValidationError(
        `action "${action}" is not valid for schedule_negotiation`,
      );
    default: {
      // Exhaustiveness guard for future actions.
      const exhaustive: never = action;
      throw new A2AValidationError(`unknown action: ${String(exhaustive)}`);
    }
  }
}

/**
 * Validate a `task_delegation` payload for a given action. Mirrors
 * the shape of `assertValidScheduleNegotiationPayload` — the
 * dispatcher in a2a validation stays per-type so each type's rule
 * set is isolated and future types don't cross-contaminate.
 */
export function assertValidTaskDelegationPayload(
  action: A2AProtocolAction,
  payload: TaskDelegationPayload,
): void {
  switch (action) {
    case "delegate":
      assertValidDelegatePayload(payload as TaskDelegatePayload);
      return;
    case "accept":
      assertValidTaskAcceptPayload(payload as TaskAcceptPayload);
      return;
    case "decline":
      assertValidReasonOnlyPayload(
        payload as TaskDeclinePayload,
        "task decline",
      );
      return;
    case "complete":
      assertValidCompletePayload(payload as TaskCompletePayload);
      return;
    case "propose":
    case "counter":
      throw new A2AValidationError(
        `action "${action}" is not valid for task_delegation`,
      );
    default: {
      const exhaustive: never = action;
      throw new A2AValidationError(`unknown action: ${String(exhaustive)}`);
    }
  }
}

/**
 * Dispatcher that picks the right per-type validator. Used by
 * `buildA2AEnvelope` so callers don't have to switch on type
 * themselves.
 */
export function assertValidA2APayload(block: A2AProtocolBlock): void {
  switch (block.type) {
    case "schedule_negotiation":
      assertValidScheduleNegotiationPayload(
        block.action,
        block.payload as ScheduleNegotiationPayload,
      );
      return;
    case "task_delegation":
      assertValidTaskDelegationPayload(
        block.action,
        block.payload as TaskDelegationPayload,
      );
      return;
    default: {
      const exhaustive: never = block.type;
      throw new A2AValidationError(`unknown protocol type: ${String(exhaustive)}`);
    }
  }
}

function assertValidCandidate(c: ScheduleCandidate, idx: number): void {
  if (!isValidIso8601WithTimezone(c.start)) {
    throw new A2AValidationError(
      `candidate[${idx}].start must be ISO 8601 with timezone (Z or ±HH:MM)`,
    );
  }
  if (!isValidIso8601WithTimezone(c.end)) {
    throw new A2AValidationError(
      `candidate[${idx}].end must be ISO 8601 with timezone (Z or ±HH:MM)`,
    );
  }
  const startMs = Date.parse(c.start);
  const endMs = Date.parse(c.end);
  if (!(startMs < endMs)) {
    throw new A2AValidationError(
      `candidate[${idx}].end must be strictly after start`,
    );
  }
  const maxDurationMs = SCHEDULE_MAX_CANDIDATE_DURATION_HOURS * 3600 * 1000;
  if (endMs - startMs > maxDurationMs) {
    throw new A2AValidationError(
      `candidate[${idx}] exceeds ${SCHEDULE_MAX_CANDIDATE_DURATION_HOURS}h duration limit`,
    );
  }
}

function assertValidCandidateList(
  candidates: ScheduleCandidate[] | undefined,
  label: string,
): void {
  if (!Array.isArray(candidates)) {
    throw new A2AValidationError(`${label} must be an array`);
  }
  if (candidates.length < 1) {
    throw new A2AValidationError(`${label} must contain at least one candidate`);
  }
  if (candidates.length > SCHEDULE_MAX_CANDIDATES) {
    throw new A2AValidationError(
      `${label} may contain at most ${SCHEDULE_MAX_CANDIDATES} candidates`,
    );
  }
  candidates.forEach((c, i) => assertValidCandidate(c, i));
}

function assertValidProposePayload(p: ScheduleProposePayload): void {
  if (typeof p.event_title !== "string" || p.event_title.trim().length === 0) {
    throw new A2AValidationError("propose.event_title is required");
  }
  assertValidCandidateList(p.candidates, "propose.candidates");
  if (!Array.isArray(p.required_participants)) {
    throw new A2AValidationError("propose.required_participants must be an array");
  }
  if (p.response_deadline !== undefined && !isValidIso8601WithTimezone(p.response_deadline)) {
    throw new A2AValidationError(
      "propose.response_deadline must be ISO 8601 with timezone when present",
    );
  }
}

function assertValidScheduleAcceptPayload(p: ScheduleAcceptPayload): void {
  if (!p || typeof p !== "object" || !p.selected_candidate) {
    throw new A2AValidationError("accept.selected_candidate is required");
  }
  assertValidCandidate(p.selected_candidate, 0);
}

function assertValidReasonOnlyPayload(
  p: { reason?: string } | undefined,
  label: string,
): void {
  if (p && p.reason !== undefined && typeof p.reason !== "string") {
    throw new A2AValidationError(`${label}.reason must be a string when present`);
  }
}

function assertValidCounterPayload(p: ScheduleCounterPayload): void {
  assertValidCandidateList(p.candidates, "counter.candidates");
  if (p.reason !== undefined && typeof p.reason !== "string") {
    throw new A2AValidationError("counter.reason must be a string when present");
  }
}

// --- task_delegation validators -------------------------------------------

const MAX_TASK_TITLE_LEN = 200;
const MAX_TASK_DESCRIPTION_LEN = 4000;
const MAX_TASK_RESULT_LEN = 4000;
const MAX_TASK_NOTE_LEN = 2000;
const VALID_TASK_PRIORITIES: readonly TaskPriority[] = ["high", "normal", "low"];

function assertValidDelegatePayload(p: TaskDelegatePayload): void {
  if (typeof p.title !== "string" || p.title.trim().length === 0) {
    throw new A2AValidationError("delegate.title is required");
  }
  if (p.title.length > MAX_TASK_TITLE_LEN) {
    throw new A2AValidationError(
      `delegate.title must be ≤ ${MAX_TASK_TITLE_LEN} characters`,
    );
  }
  if (p.description !== undefined) {
    if (typeof p.description !== "string") {
      throw new A2AValidationError("delegate.description must be a string when present");
    }
    if (p.description.length > MAX_TASK_DESCRIPTION_LEN) {
      throw new A2AValidationError(
        `delegate.description must be ≤ ${MAX_TASK_DESCRIPTION_LEN} characters`,
      );
    }
  }
  if (p.due_date !== undefined && !isValidIso8601WithTimezone(p.due_date)) {
    throw new A2AValidationError(
      "delegate.due_date must be ISO 8601 with timezone when present",
    );
  }
  if (p.priority !== undefined && !VALID_TASK_PRIORITIES.includes(p.priority)) {
    throw new A2AValidationError(
      `delegate.priority must be one of ${VALID_TASK_PRIORITIES.join(", ")}`,
    );
  }
}

function assertValidTaskAcceptPayload(p: TaskAcceptPayload): void {
  if (p && p.note !== undefined) {
    if (typeof p.note !== "string") {
      throw new A2AValidationError("accept.note must be a string when present");
    }
    if (p.note.length > MAX_TASK_NOTE_LEN) {
      throw new A2AValidationError(
        `accept.note must be ≤ ${MAX_TASK_NOTE_LEN} characters`,
      );
    }
  }
}

function assertValidCompletePayload(p: TaskCompletePayload): void {
  if (p && p.result !== undefined) {
    if (typeof p.result !== "string") {
      throw new A2AValidationError("complete.result must be a string when present");
    }
    if (p.result.length > MAX_TASK_RESULT_LEN) {
      throw new A2AValidationError(
        `complete.result must be ≤ ${MAX_TASK_RESULT_LEN} characters`,
      );
    }
  }
}

// --- UX helpers ------------------------------------------------------------

/**
 * True when a schedule_negotiation `propose` payload's
 * `response_deadline` has passed. Client-side clock only; server
 * doesn't enforce this. Used by the card to decide whether to
 * show Accept/Decline buttons.
 */
export function isProposeExpired(
  payload: ScheduleProposePayload,
  now: Date = new Date(),
): boolean {
  if (!payload.response_deadline) return false;
  const deadlineMs = Date.parse(payload.response_deadline);
  if (!Number.isFinite(deadlineMs)) return false;
  return now.getTime() > deadlineMs;
}

// --- Type guards (runtime checks for untrusted input) ----------------------

function isA2AMessagePayload(v: unknown): v is A2AMessagePayload {
  if (!v || typeof v !== "object") return false;
  const obj = v as Record<string, unknown>;
  if (obj.v !== A2A_CURRENT_VERSION) return false;
  // body may be empty string but must be a string
  if (typeof obj.body !== "string") return false;
  if (obj.protocol !== undefined && !isA2AProtocolBlock(obj.protocol)) return false;
  return true;
}

function isA2AProtocolBlock(v: unknown): v is A2AProtocolBlock {
  if (!v || typeof v !== "object") return false;
  const obj = v as Record<string, unknown>;
  if (typeof obj.id !== "string" || obj.id.length === 0) return false;
  if (obj.type !== "schedule_negotiation" && obj.type !== "task_delegation") {
    return false;
  }
  if (!isKnownAction(obj.action)) return false;
  if (!isActionValidForType(obj.type, obj.action)) return false;
  if (obj.reply_to !== null && typeof obj.reply_to !== "string") return false;
  if (!obj.payload || typeof obj.payload !== "object") return false;
  return true;
}

function isKnownAction(v: unknown): v is A2AProtocolAction {
  return (
    v === "propose" ||
    v === "accept" ||
    v === "decline" ||
    v === "counter" ||
    v === "delegate" ||
    v === "complete"
  );
}

function isActionValidForType(
  type: A2AProtocolType,
  action: A2AProtocolAction,
): boolean {
  if (type === "schedule_negotiation") {
    return (
      action === "propose" ||
      action === "accept" ||
      action === "decline" ||
      action === "counter"
    );
  }
  // task_delegation
  return (
    action === "delegate" ||
    action === "accept" ||
    action === "decline" ||
    action === "complete"
  );
}
