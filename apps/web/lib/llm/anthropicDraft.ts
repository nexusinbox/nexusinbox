// Phase 4.5 (docs/25f) — Anthropic draft generation helper.
//
// Pure-ish async function. The only side effect is the HTTP POST to
// api.anthropic.com, and even that goes through an injectable fetcher
// so tests can swap it for an in-memory mock.
//
// Key invariants from docs/25f §3:
//   - Calls api.anthropic.com directly from the browser (never our
//     backend). The `anthropic-dangerous-direct-browser-access`
//     header is what unlocks CORS there.
//   - API key travels in a header, never in a URL / query string
//     / our server's logs.
//   - Draft is always returned as plain text for the user to read
//     + edit before sending; this module does no auto-send.

import type { A2AProtocolBlock } from "@nexusinbox/core/a2a";

const ANTHROPIC_URL = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MAX_TOKENS = 512;

const BASE_SYSTEM_PROMPT = `You are drafting a reply to an incoming message on the user's behalf.
The reply will be shown to the user for review and editing before sending.

- Be concise.
- Match the tone of the incoming message.
- Do not commit to specific actions (dates, payments, tasks) unless the incoming message clearly requested them.
- If the message is ambiguous, err on the side of asking a clarifying question.
- Write in the same language as the incoming message.
- Output only the reply text itself — no preamble, no explanation, no markdown code fences.`;

/** Phase 4.6 — fixed tone enum. UI translates these into labels. */
export type DraftTone = "formal" | "casual" | "brief" | "detailed";

const TONE_PROMPT_FRAGMENTS: Record<DraftTone, string> = {
  formal: "Use a formal, professional register. Avoid contractions and casual expressions.",
  casual: "Use a casual, friendly tone. Contractions and informal phrasing are fine.",
  brief: "Be very concise — aim for two sentences or fewer.",
  detailed:
    "Be thorough — cover all relevant points with explicit reasoning, even if the reply runs longer.",
};

export function buildSystemPrompt(tone?: DraftTone): string {
  if (!tone) return BASE_SYSTEM_PROMPT;
  return `${BASE_SYSTEM_PROMPT}\n- ${TONE_PROMPT_FRAGMENTS[tone]}`;
}

export type GenerateReplyDraftInput = {
  incomingBody: string;
  incomingSubject?: string;
  protocolBlock?: A2AProtocolBlock | null;
  apiKey: string;
  model: string;
  /** Phase 4.6 (docs/25f §6). Omitted = default (matches incoming tone). */
  tone?: DraftTone;
  fetcher?: typeof fetch;
  maxTokens?: number;
};

export class AnthropicDraftError extends Error {
  code: "auth" | "rate_limit" | "api_error" | "network" | "empty_response";
  status?: number;

  constructor(
    code: AnthropicDraftError["code"],
    message: string,
    status?: number,
  ) {
    super(message);
    this.name = "AnthropicDraftError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Produce a plain-text reply draft for the given incoming message.
 * Throws {@link AnthropicDraftError} on any failure so the compose
 * UI can map error codes to localised messages.
 */
export async function generateReplyDraft(
  input: GenerateReplyDraftInput,
): Promise<string> {
  const fetcher = input.fetcher ?? fetch;
  const userMessage = buildUserMessage(input);

  let resp: Response;
  try {
    resp = await fetcher(ANTHROPIC_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": input.apiKey,
        "anthropic-version": ANTHROPIC_VERSION,
        // Anthropic requires this explicit opt-in to allow the API
        // key to travel directly from a browser. We ship it because
        // the alternative — routing through our server — would
        // violate the E2E encryption invariant the rest of this
        // codebase protects (docs/04 §2).
        "anthropic-dangerous-direct-browser-access": "true",
      },
      body: JSON.stringify({
        model: input.model,
        max_tokens: input.maxTokens ?? DEFAULT_MAX_TOKENS,
        system: buildSystemPrompt(input.tone),
        messages: [{ role: "user", content: userMessage }],
      }),
    });
  } catch (error) {
    throw new AnthropicDraftError(
      "network",
      error instanceof Error ? error.message : "network error",
    );
  }

  if (!resp.ok) {
    if (resp.status === 401 || resp.status === 403) {
      throw new AnthropicDraftError(
        "auth",
        "Anthropic rejected the API key",
        resp.status,
      );
    }
    if (resp.status === 429) {
      throw new AnthropicDraftError(
        "rate_limit",
        "Anthropic rate limit exceeded",
        resp.status,
      );
    }
    throw new AnthropicDraftError(
      "api_error",
      `Anthropic API returned ${resp.status}`,
      resp.status,
    );
  }

  let body: unknown;
  try {
    body = await resp.json();
  } catch {
    throw new AnthropicDraftError("api_error", "response was not JSON");
  }

  const text = extractTextFromAnthropicResponse(body);
  if (!text) {
    throw new AnthropicDraftError("empty_response", "no text in response");
  }
  return text.trim();
}

function buildUserMessage(input: GenerateReplyDraftInput): string {
  const parts: string[] = [];
  if (input.incomingSubject) {
    parts.push(`Incoming subject: ${input.incomingSubject}`);
  }

  if (input.protocolBlock) {
    parts.push(renderProtocolContext(input.protocolBlock));
  } else {
    parts.push(`Incoming body:\n${input.incomingBody}`);
  }

  parts.push(
    "Please draft a short reply the user can review and edit before sending.",
  );
  return parts.join("\n\n");
}

function renderProtocolContext(block: A2AProtocolBlock): string {
  if (block.type === "schedule_negotiation" && block.action === "propose") {
    const payload = block.payload as
      | { event_title?: string; candidates?: Array<{ start: string; end: string }> }
      | undefined;
    const lines = ["The sender proposed a meeting via a structured protocol."];
    if (payload?.event_title) lines.push(`Event: ${payload.event_title}`);
    if (payload?.candidates && payload.candidates.length > 0) {
      lines.push("Proposed time slots:");
      for (const c of payload.candidates) {
        lines.push(`  - ${c.start} → ${c.end}`);
      }
    }
    lines.push(
      "Draft a short acceptance or polite decline. Reference the slot(s) explicitly if accepting.",
    );
    return lines.join("\n");
  }

  if (block.type === "task_delegation" && block.action === "delegate") {
    const payload = block.payload as
      | { title?: string; description?: string; due_date?: string; priority?: string }
      | undefined;
    const lines = ["The sender delegated a task via a structured protocol."];
    if (payload?.title) lines.push(`Task: ${payload.title}`);
    if (payload?.description) lines.push(`Description: ${payload.description}`);
    if (payload?.due_date) lines.push(`Due: ${payload.due_date}`);
    if (payload?.priority) lines.push(`Priority: ${payload.priority}`);
    lines.push(
      "Draft a short acceptance or polite decline with a brief reason.",
    );
    return lines.join("\n");
  }

  // Unknown / unsupported protocol action — fall back to treating
  // the raw body as plain text so we still produce something useful.
  return "The sender used a structured protocol we don't have a specific template for; draft a short generic acknowledgement.";
}

function extractTextFromAnthropicResponse(body: unknown): string | null {
  if (!body || typeof body !== "object") return null;
  const content = (body as { content?: unknown }).content;
  if (!Array.isArray(content)) return null;
  const chunks: string[] = [];
  for (const item of content) {
    if (
      item &&
      typeof item === "object" &&
      (item as { type?: unknown }).type === "text"
    ) {
      const text = (item as { text?: unknown }).text;
      if (typeof text === "string") chunks.push(text);
    }
  }
  return chunks.join("").trim() || null;
}
