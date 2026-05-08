/**
 * Client-side audit logger for Phase 1B write tools.
 *
 * Writes one JSON object per line to stderr (line-delimited JSON).
 * Stdout is reserved for the MCP protocol, so emitting structured
 * audit entries there would corrupt the transport; stderr is the
 * conventional "sideband" channel that Claude Desktop / Cursor leave
 * alone and that operators can redirect with a shell pipe.
 *
 * The schema mirrors docs/20_mcp_skill_strategy.md §11.3 so `grep`
 * / `jq` workflows work the same whether the event came from the
 * server-side `agent_audit_log` table or from this client.
 *
 * Server-side `record_audit_event` already covers the authoritative
 * audit trail (agent_message_sent, attachment_attached_to_message,
 * etc.) — this stream is the *intent* layer: what the LLM proposed,
 * what the human confirmed, which provider drove the call. The two
 * combined give full draft → send traceability without storing any
 * plaintext.
 */

import { createHash } from "node:crypto";

export type AuditSource = "mcp-server";

export type AuditEntry = {
  /** ISO-8601, UTC, millisecond precision. */
  timestamp: string;
  source: AuditSource;
  tool_name: string;
  aid: string;
  did?: string;
  credential_id: string;
  mode: "draft" | "send" | "read";
  confirmed_by_user?: boolean;
  provider_hint?: string;
  /** SHA-256 hex of the draft body text. plaintext itself is never logged. */
  draft_body_hash?: string;
  /** Target message or new message id (send result). */
  message_id?: string;
  recipient_aid?: string;
  recipient_did?: string;
  thread_id?: string | null;
  /** Non-sensitive failure reason, if the tool throws. */
  error?: string;
};

export type AuditSink = (entry: AuditEntry) => void;

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Default sink: one JSON line to stderr, best-effort.
 * Errors in the sink itself are swallowed — audit must never mask a
 * genuine tool-level error.
 */
export const defaultAuditSink: AuditSink = (entry) => {
  try {
    process.stderr.write(`${JSON.stringify(entry)}\n`);
  } catch {
    // ignore — stderr being unwritable is rare enough that crashing
    // the server for a logging failure is the wrong trade-off.
  }
};

/**
 * Build a new audit-entry factory bound to a specific credential. The
 * runtime passes one of these into every tool handler so they don't
 * have to re-thread aid / did / credential_id on every emit.
 */
export function createAuditor(args: {
  aid: string;
  did: string;
  credential_id: string;
  sink?: AuditSink;
}) {
  const sink = args.sink ?? defaultAuditSink;
  return function emit(partial: Omit<AuditEntry, "timestamp" | "source" | "aid" | "did" | "credential_id">): void {
    sink({
      timestamp: new Date().toISOString(),
      source: "mcp-server",
      aid: args.aid,
      did: args.did,
      credential_id: args.credential_id,
      ...partial,
    });
  };
}

export type Auditor = ReturnType<typeof createAuditor>;
