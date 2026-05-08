"use client";

import Link from "next/link";
import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { AppShell } from "../../_components/AppShell";
import { RefreshIconButton } from "../../_components/RefreshIconButton";
import { AutoReplyPolicyPanel } from "../../_components/AutoReplyPolicyPanel";
import {
  useAgentCredentialsQuery,
  useAgentsQuery,
  useAuditLogQuery,
  useCreateAgentCredentialMutation,
  useDeleteAgentMutation,
  useEmergencyShutdownMutation,
  usePurgeAgentCredentialMutation,
  useRevokeAgentCredentialMutation,
  useUpdateAgentMutation,
} from "../../../lib/api/hooks";
import { useTwoColumnResize } from "../../../lib/ui/useTwoColumnResize";
import { useTranslation } from "../../../lib/i18n";
import type { AgentCredential } from "../../../lib/api/types";
import {
  deriveAgentMode,
  type AgentMode,
} from "../../../lib/agents/derive-mode";
import {
  BridgeClient,
  type BridgePairedSession,
  type BridgeRatePolicy,
} from "../../../lib/bridge/client";
import {
  BridgeSecureStorageUnavailableError,
  clearBridgeSessionNonce,
  clearBridgeToken,
  generateBridgeSessionNonce,
  loadBridgeSessionNonce,
  loadBridgeToken,
  saveBridgeSessionNonce,
  saveBridgeToken,
} from "../../../lib/bridge/token-store";
import { secureLoadKey } from "../../../lib/crypto/keystore";

type Banner = { tone: "info" | "error" | "success"; text: string } | null;
type CreatedCredentialNotice = {
  credentialId: string;
  enrollmentSecret: string;
  aid: string;
};

// Renders the Standard / Daemon-isolated pill next to a credential's
// label in the settings list. Reads `key_holder` straight from the
// API (migration 0014); pre-migration rows arrive as `"unknown"` and
// surface as a muted "Standard" variant so legacy credentials don't
// suddenly look abnormal. See docs/21 §4.5.
function CredentialModeBadge({
  keyHolder,
}: {
  keyHolder: "web_keystore" | "signer_daemon" | "unknown";
}) {
  const { t } = useTranslation();
  const isDaemon = keyHolder === "signer_daemon";
  const isUnknown = keyHolder === "unknown";
  const label = isDaemon
    ? t("agents.credModeDaemonIsolated")
    : isUnknown
      ? t("agents.credModeUnknown")
      : t("agents.credModeStandard");
  const tooltip = isDaemon
    ? t("agents.credModeDaemonIsolatedTooltip")
    : isUnknown
      ? t("agents.credModeUnknownTooltip")
      : t("agents.credModeStandardTooltip");
  // Colour choices picked for both light and dark backgrounds — the
  // pre-fix version used ~6% white which disappeared entirely on the
  // light-mode inbox. Stronger tint + explicit border gives a visible
  // shape either way without needing a theme-aware conditional.
  const daemonStyle: CSSProperties = {
    background: "rgba(66, 133, 244, 0.14)",
    color: "#1a73e8",
    border: "1px solid rgba(66, 133, 244, 0.28)",
  };
  const unknownStyle: CSSProperties = {
    background: "rgba(128, 128, 128, 0.14)",
    color: "#5f6368",
    border: "1px solid rgba(128, 128, 128, 0.28)",
  };
  const standardStyle: CSSProperties = {
    background: "rgba(52, 168, 83, 0.14)",
    color: "#188038",
    border: "1px solid rgba(52, 168, 83, 0.28)",
  };
  const style = isDaemon ? daemonStyle : isUnknown ? unknownStyle : standardStyle;
  return (
    <span
      title={tooltip}
      aria-label={`${label}: ${tooltip}`}
      style={{
        fontSize: 10,
        fontWeight: 500,
        padding: "1px 7px",
        borderRadius: 999,
        letterSpacing: 0.3,
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {label}
    </span>
  );
}

// Agent-level mode display (docs/21 §4.5). Both `<AgentModePanel>` and
// `<BridgeTokenPanel>` consume `deriveAgentMode` so the badge users see
// and the gate that decides whether the Bridge panel surfaces stay in
// lockstep. The helper lives in `lib/agents/derive-mode.ts` with its
// own tests covering the priority rules.

function AgentModePanel({
  aid,
  credentials,
}: {
  aid: string;
  credentials: AgentCredential[];
}) {
  const { t } = useTranslation();

  const mode = useMemo<AgentMode>(
    () => deriveAgentMode(aid, credentials),
    [aid, credentials],
  );

  const badgeStyle: CSSProperties =
    mode === "daemon_isolated"
      ? {
          background: "rgba(66, 133, 244, 0.14)",
          color: "#1a73e8",
          border: "1px solid rgba(66, 133, 244, 0.28)",
        }
      : mode === "standard"
        ? {
            background: "rgba(52, 168, 83, 0.14)",
            color: "#188038",
            border: "1px solid rgba(52, 168, 83, 0.28)",
          }
        : {
            background: "rgba(128, 128, 128, 0.14)",
            color: "#5f6368",
            border: "1px solid rgba(128, 128, 128, 0.28)",
          };

  const label =
    mode === "daemon_isolated"
      ? t("agents.modeDaemonIsolatedName")
      : mode === "standard"
        ? t("agents.modeStandardName")
        : t("agents.modeDefaultName");
  const desc =
    mode === "daemon_isolated"
      ? t("agents.modeDaemonIsolatedDesc")
      : mode === "standard"
        ? t("agents.modeStandardDesc")
        : t("agents.modeDefaultDesc");

  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <div className="row" style={{ alignItems: "center", gap: 10 }}>
        <p className="item-title" style={{ margin: 0 }}>
          {t("agents.modeLabel")}
        </p>
        <span
          style={{
            fontSize: 11,
            fontWeight: 500,
            padding: "2px 8px",
            borderRadius: 999,
            letterSpacing: 0.3,
            whiteSpace: "nowrap",
            ...badgeStyle,
          }}
        >
          {label}
        </span>
      </div>
      <p className="item-sub" style={{ marginTop: 6 }}>
        {desc}
      </p>
      <Link
        href="/help#help-modes"
        className="item-sub"
        style={{
          fontSize: 12,
          textDecoration: "underline",
          color: "var(--primary, #1a73e8)",
        }}
      >
        {t("agents.modeHelpLink")} →
      </Link>
    </div>
  );
}

/**
 * Per-agent "where are this agent's keys reachable from?" panel.
 *
 * Mode (Standard / Interactive / Default) tells you what the agent is
 * configured for; this panel tells you what the *current device* can
 * actually do with it. Three rows:
 *
 *   1. Browser keystore — does THIS browser hold either the
 *      signing or X25519 private key for the agent's current did?
 *      Answered locally by `secureLoadKey()` against IndexedDB.
 *   2. Signer Daemon (Bridge) — has this browser been paired with a
 *      Signer Daemon for this aid? `loadBridgeToken()` returns the
 *      stored bearer; we don't actively probe the daemon endpoint
 *      here (the Bridge panel below already handles live status),
 *      we just report whether the pairing handshake has happened
 *      so the user knows Bridged restore is available.
 *   3. AI runtime keystore — there's no server-side signal for
 *      whether a Claude Desktop / Code instance somewhere has
 *      `~/.nexusinbox/<credential>.json`. Render as an info row so
 *      the user understands the gap rather than guessing.
 *
 * Read-only display; never reveals key material — only presence.
 */
type WhereaboutsStatus = "checking" | "present" | "absent" | "info";

function WhereaboutsRow({
  icon,
  label,
  status,
  message,
}: {
  icon: string;
  label: string;
  status: WhereaboutsStatus;
  message: string;
}) {
  const indicator = (() => {
    if (status === "checking") return { color: "var(--text-muted)", text: "…" };
    if (status === "present") return { color: "#137333", text: "✓" };
    if (status === "absent") return { color: "var(--text-muted)", text: "—" };
    return { color: "var(--text-muted)", text: "◯" }; // info
  })();
  return (
    <div
      className="row"
      style={{
        alignItems: "flex-start",
        gap: 10,
        padding: "8px 0",
        borderTop: "1px solid var(--line)",
      }}
    >
      <span style={{ width: 22, fontSize: 16, lineHeight: 1.4 }} aria-hidden="true">
        {icon}
      </span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span style={{ fontWeight: 500, fontSize: 13 }}>{label}</span>
        <p className="item-sub" style={{ margin: "2px 0 0", fontSize: 12 }}>
          {message}
        </p>
      </span>
      <span
        style={{
          color: indicator.color,
          fontSize: 14,
          fontWeight: 600,
          minWidth: 16,
          textAlign: "right",
        }}
        aria-label={status}
      >
        {indicator.text}
      </span>
    </div>
  );
}

function AgentKeyWhereaboutsPanel({ aid, did }: { aid: string; did: string }) {
  const { t } = useTranslation();
  const [browserStatus, setBrowserStatus] = useState<WhereaboutsStatus>("checking");
  const [daemonStatus, setDaemonStatus] = useState<WhereaboutsStatus>("checking");

  useEffect(() => {
    let cancelled = false;
    setBrowserStatus("checking");
    setDaemonStatus("checking");

    // Browser keystore: presence of EITHER the signing or recipient
    // (X25519) key for the agent's current did is enough to consider
    // the browser to "have" the key set. Web UI activate stores both
    // under the same did, so this should rarely split, but using OR
    // keeps the row honest for any partial-import edge case.
    (async () => {
      try {
        const [sig, enc] = await Promise.all([
          secureLoadKey(`nexusinbox:signing-key:${did}`),
          secureLoadKey(`nexusinbox:recipient-key:${did}`),
        ]);
        if (!cancelled) setBrowserStatus(sig || enc ? "present" : "absent");
      } catch {
        if (!cancelled) setBrowserStatus("absent");
      }
    })();

    // Bridge pairing: token presence is the best signal we have
    // without paying for a live HTTP probe. The Bridge panel further
    // down on this page does the live probe and shows its result;
    // here we just answer "is this aid paired at all?".
    (async () => {
      try {
        const token = await loadBridgeToken(aid);
        if (!cancelled) setDaemonStatus(token ? "present" : "absent");
      } catch {
        if (!cancelled) setDaemonStatus("absent");
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [aid, did]);

  const truncatedDid = did.length > 24 ? `${did.slice(0, 16)}…${did.slice(-8)}` : did;

  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <p className="item-title">{t("agents.whereaboutsTitle")}</p>
      <p className="item-sub" style={{ marginTop: 4, fontSize: 12 }}>
        {t("agents.whereaboutsCaption", { did: truncatedDid })}
      </p>
      <div style={{ marginTop: 8 }}>
        <WhereaboutsRow
          icon="🌐"
          label={t("agents.whereaboutsBrowserLabel")}
          status={browserStatus}
          message={
            browserStatus === "checking"
              ? t("agents.whereaboutsBrowserChecking")
              : browserStatus === "present"
                ? t("agents.whereaboutsBrowserPresent")
                : t("agents.whereaboutsBrowserAbsent")
          }
        />
        <WhereaboutsRow
          icon="🛡️"
          label={t("agents.whereaboutsDaemonLabel")}
          status={daemonStatus}
          message={
            daemonStatus === "checking"
              ? t("agents.whereaboutsDaemonChecking")
              : daemonStatus === "present"
                ? t("agents.whereaboutsDaemonPaired")
                : t("agents.whereaboutsDaemonUnpaired")
          }
        />
        <WhereaboutsRow
          icon="🤖"
          label={t("agents.whereaboutsRuntimeLabel")}
          status="info"
          message={t("agents.whereaboutsRuntimeHint")}
        />
      </div>
    </div>
  );
}

/**
 * Per-agent auto-reply decision history (Phase A visibility).
 *
 * The evaluator runs as a policy preview even when the master switch
 * is OFF (we saw `decision: queue_for_human / reason: master_off`
 * during today's test send). So this panel is useful in either mode:
 *
 *   - Master OFF: shows what the policy WOULD HAVE done — a preview
 *     to validate rule wiring before flipping the switch.
 *   - Master ON: shows what the policy DID — actionable feedback for
 *     tuning thresholds.
 *
 * Implementation: read-only consumer of `useAuditLogQuery` filtered
 * to `event=auto_reply_evaluated` + `aid`. We aggregate counts
 * client-side because the server doesn't expose pre-aggregated
 * stats yet — fine at Phase A scale (limit=200, so ~6 months of
 * decisions for a typical agent receiving one inbound per day).
 *
 * Out of scope: dry-run preview, rule editor, executor controls.
 */
type AutoReplyDecisionDetail = {
  agent_id?: string;
  decision?: {
    action?: string;
    reason?: string | null;
    fallback_reason?: string | null;
    matched_rule_path?: string | null;
  };
  evaluator_mode?: string;
  message_id?: string;
  policy_revision?: number | null;
  sender_did?: string;
};

type AutoReplyStatBucket =
  | "auto_accept"
  | "auto_decline"
  | "queue_for_human"
  | "other";

function bucketForAction(action?: string): AutoReplyStatBucket {
  if (action === "auto_accept") return "auto_accept";
  if (action === "auto_decline") return "auto_decline";
  if (action === "queue_for_human") return "queue_for_human";
  return "other";
}

function StatCell({
  label,
  count,
  tone,
}: {
  label: string;
  count: number;
  tone: "neutral" | "ok" | "warn" | "muted";
}) {
  const color = (() => {
    if (tone === "ok") return "#137333";
    if (tone === "warn") return "#b45309";
    if (tone === "muted") return "var(--text-muted)";
    return "var(--text)";
  })();
  return (
    <div
      style={{
        flex: "1 1 0",
        minWidth: 0,
        padding: "8px 10px",
        borderRadius: 8,
        background: "var(--surface-alt)",
        border: "1px solid var(--line)",
      }}
    >
      <div style={{ fontSize: 18, fontWeight: 600, color, lineHeight: 1.2 }}>
        {count}
      </div>
      <div
        style={{
          fontSize: 11,
          color: "var(--text-muted)",
          marginTop: 2,
          textTransform: "lowercase",
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {label}
      </div>
    </div>
  );
}

function AutoReplyVisibilityPanel({ aid }: { aid: string }) {
  const { t } = useTranslation();
  const auditQuery = useAuditLogQuery({
    event: "auto_reply_evaluated",
    aid,
    limit: 200,
  });

  const { stats, latest, total } = useMemo(() => {
    const events = auditQuery.data?.events ?? [];
    const counts: Record<AutoReplyStatBucket, number> = {
      auto_accept: 0,
      auto_decline: 0,
      queue_for_human: 0,
      other: 0,
    };
    for (const ev of events) {
      const detail = ev.detail as AutoReplyDecisionDetail | undefined;
      counts[bucketForAction(detail?.decision?.action)] += 1;
    }
    return {
      stats: counts,
      latest: events.slice(0, 5),
      total: auditQuery.data?.total ?? 0,
    };
  }, [auditQuery.data]);

  // Truncate `did:key:z6Mk...XYZW` style addresses to keep the per-row
  // metadata legible without truncating the discriminating tail.
  const truncateDid = (did: string) =>
    did.length > 24 ? `${did.slice(0, 12)}…${did.slice(-6)}` : did;

  return (
    <div className="panel" style={{ marginTop: 10 }}>
      <p className="item-title">{t("agents.autoReplyVisibilityTitle")}</p>
      <p className="item-sub" style={{ marginTop: 4, fontSize: 12 }}>
        {t("agents.autoReplyVisibilityCaption")}
      </p>

      {auditQuery.isPending ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: 12 }}
        >
          {t("agents.autoReplyVisibilityLoading")}
        </p>
      ) : auditQuery.isError ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: 12, color: "#b00020" }}
        >
          {t("agents.autoReplyVisibilityError")}
        </p>
      ) : total === 0 ? (
        <p
          className="item-sub"
          style={{ marginTop: 10, fontSize: 12 }}
        >
          {t("agents.autoReplyVisibilityNoData")}
        </p>
      ) : (
        <>
          <div
            style={{
              marginTop: 10,
              display: "flex",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <StatCell
              label={t("agents.autoReplyStatTotal")}
              count={total}
              tone="neutral"
            />
            <StatCell
              label={t("agents.autoReplyStatAutoAccept")}
              count={stats.auto_accept}
              tone="ok"
            />
            <StatCell
              label={t("agents.autoReplyStatAutoDecline")}
              count={stats.auto_decline}
              tone="warn"
            />
            <StatCell
              label={t("agents.autoReplyStatQueueForHuman")}
              count={stats.queue_for_human}
              tone="muted"
            />
            {stats.other > 0 ? (
              <StatCell
                label={t("agents.autoReplyStatOther")}
                count={stats.other}
                tone="muted"
              />
            ) : null}
          </div>

          {latest.length > 0 ? (
            <div style={{ marginTop: 14 }}>
              <p className="item-sub" style={{ fontSize: 11, fontWeight: 600 }}>
                {t("agents.autoReplyVisibilityLatest", {
                  count: String(latest.length),
                })}
              </p>
              <ul
                style={{
                  margin: "6px 0 0",
                  padding: 0,
                  listStyle: "none",
                }}
              >
                {latest.map((ev) => {
                  const detail = ev.detail as
                    | AutoReplyDecisionDetail
                    | undefined;
                  const action = detail?.decision?.action ?? "other";
                  const reason = detail?.decision?.reason;
                  const sender = detail?.sender_did
                    ? truncateDid(detail.sender_did)
                    : "—";
                  const messageId = detail?.message_id;
                  return (
                    <li
                      key={ev.id}
                      style={{
                        padding: "8px 0",
                        borderTop: "1px solid var(--line)",
                        fontSize: 12,
                      }}
                    >
                      <div
                        style={{
                          display: "flex",
                          alignItems: "baseline",
                          gap: 8,
                          flexWrap: "wrap",
                        }}
                      >
                        <code
                          style={{
                            fontSize: 12,
                            fontWeight: 600,
                            padding: "1px 6px",
                            borderRadius: 4,
                            background:
                              action === "auto_accept"
                                ? "rgba(19, 115, 51, 0.12)"
                                : action === "auto_decline"
                                  ? "rgba(180, 83, 9, 0.12)"
                                  : "var(--surface-alt)",
                            color:
                              action === "auto_accept"
                                ? "#137333"
                                : action === "auto_decline"
                                  ? "#b45309"
                                  : "var(--text)",
                          }}
                        >
                          {action}
                        </code>
                        <span
                          className="item-sub"
                          style={{
                            margin: 0,
                            fontSize: 11,
                            color: "var(--text-muted)",
                          }}
                        >
                          {new Date(ev.created_at).toLocaleString()}
                        </span>
                      </div>
                      <p
                        className="item-sub"
                        style={{ margin: "4px 0 0", fontSize: 11 }}
                      >
                        {t("agents.autoReplyDecisionFrom", { sender })}
                        {reason
                          ? ` · ${t("agents.autoReplyDecisionReason", {
                              reason,
                            })}`
                          : ""}
                        {messageId
                          ? ` · ${t("agents.autoReplyDecisionMessage", {
                              messageId: messageId.slice(0, 8),
                            })}`
                          : ""}
                      </p>
                    </li>
                  );
                })}
              </ul>
            </div>
          ) : null}

          {total > latest.length ? (
            <p
              className="item-sub"
              style={{ marginTop: 10, fontSize: 11 }}
            >
              {t("agents.autoReplyShowingLatest", {
                limit: String(latest.length),
                total: String(total),
              })}
            </p>
          ) : null}

          <Link
            href={`/settings/audit?event=auto_reply_evaluated&aid=${encodeURIComponent(aid)}`}
            className="item-sub"
            style={{
              display: "inline-block",
              marginTop: 10,
              fontSize: 12,
              textDecoration: "underline",
              color: "var(--primary, #1a73e8)",
            }}
          >
            {t("agents.autoReplyVisibilityViewAll")}
          </Link>
        </>
      )}
    </div>
  );
}

/**
 * Per-agent Signer Daemon bridge pairing panel (docs/22 Phase 3a).
 * Stores the shared bearer token in localStorage keyed by aid, and
 * probes the daemon so the user can see whether the Web UI can reach
 * it before trying to restore an actual message. Phase 3b will swap
 * this manual paste flow for an interactive pairing-code handshake.
 */
/**
 * Compute sha256 hex of a UTF-8 string in the browser. Matches the
 * daemon's server-side hash so the Web UI can recognise its own
 * paired-session row in `GET /v1/status` without the bearer ever
 * leaving this browser.
 */
async function sha256HexBrowser(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const hash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer),
  );
  return Array.from(hash)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Best-effort guess at a friendly device label. Browser doesn't
 *  expose anything great so we synthesise from the first UA token,
 *  clamping to 64 chars so the daemon never needs to truncate. */
function guessDeviceLabel(): string {
  if (typeof navigator === "undefined") return "Paired browser";
  const ua = navigator.userAgent ?? "";
  // Match the browser name. Order matters — Edge masquerades as
  // Chrome, Chrome masquerades as Safari, etc.
  const browser = /Edg/.test(ua)
    ? "Edge"
    : /Firefox/.test(ua)
      ? "Firefox"
      : /Chrome/.test(ua)
        ? "Chrome"
        : /Safari/.test(ua)
          ? "Safari"
          : "Browser";
  const platform =
    /Mac/.test(ua) ? "Mac"
    : /Win/.test(ua) ? "Windows"
    : /Linux/.test(ua) ? "Linux"
    : /iPhone|iPad/.test(ua) ? "iOS"
    : /Android/.test(ua) ? "Android"
    : "this device";
  return `${browser} on ${platform}`.slice(0, 64);
}

function BridgeTokenPanel({
  aid,
  credentials,
}: {
  aid: string;
  credentials: AgentCredential[];
}) {
  const { t } = useTranslation();
  const [baseUrl, setBaseUrl] = useState("http://127.0.0.1:43417");
  const [storedTokenHash, setStoredTokenHash] = useState<string | null>(null);
  const [pairingCode, setPairingCode] = useState("");
  const [deviceLabel, setDeviceLabel] = useState(() => guessDeviceLabel());
  const [status, setStatus] = useState<
    | { kind: "idle" }
    | { kind: "pairing" }
    | { kind: "probing" }
    | { kind: "paired" }
    | { kind: "offline" }
    | { kind: "error"; message: string }
  >({ kind: "idle" });
  const [pairedSessions, setPairedSessions] = useState<BridgePairedSession[]>(
    [],
  );
  const [policy, setPolicy] = useState<BridgeRatePolicy | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [advancedToken, setAdvancedToken] = useState("");

  const mode = useMemo<AgentMode>(
    () => deriveAgentMode(aid, credentials),
    [aid, credentials],
  );

  // Load stored token and compute its hash so we can recognise our
  // own row in the paired_sessions list. The token itself stays in
  // localStorage; only the sha256 lives in component state.
  useEffect(() => {
    let cancelled = false;
    setStatus({ kind: "idle" });
    setPairedSessions([]);
    setPolicy(null);
    setPairingCode("");
    setAdvancedToken("");
    setStoredTokenHash(null);
    if (!aid) return;
    // 3c.5: loadBridgeToken is async now — AES-GCM unwrap via the
    // IndexedDB KEK. Thread through the existing cancellation
    // pattern so a fast aid flip doesn't stamp stale state.
    void (async () => {
      const existing = await loadBridgeToken(aid);
      if (cancelled || !existing) return;
      setBaseUrl(existing.base_url);
      const hash = await sha256HexBrowser(existing.token);
      if (!cancelled) setStoredTokenHash(hash);
    })();
    return () => {
      cancelled = true;
    };
  }, [aid]);

  // Auto-probe when a token is stored so the UI immediately reflects
  // "paired / offline" without the user hitting a button.
  useEffect(() => {
    if (!aid) return;
    let cancelled = false;
    void (async () => {
      const existing = await loadBridgeToken(aid);
      if (cancelled || !existing) return;
      const nonce = loadBridgeSessionNonce(aid);
      const result = await probe(existing.base_url, existing.token, nonce);
      if (cancelled) return;
      setPairedSessions(result.sessions);
      setPolicy(result.policy);
      setStatus(result.status);
    })();
    return () => {
      cancelled = true;
    };
    // Re-run whenever aid flips or a pair operation completes.
  }, [aid, storedTokenHash]);

  async function probe(
    base: string,
    token: string,
    nonce: string | null,
  ): Promise<{
    sessions: BridgePairedSession[];
    policy: BridgeRatePolicy | null;
    status:
      | { kind: "paired" }
      | { kind: "offline" }
      | { kind: "error"; message: string };
  }> {
    const client = new BridgeClient({
      baseUrl: base,
      token,
      sessionNonce: nonce,
    });
    const result = await client.detect();
    if (result.kind === "available") {
      return {
        sessions: result.paired_sessions,
        policy: result.policy,
        status: { kind: "paired" },
      };
    }
    if (result.kind === "offline") {
      return { sessions: [], policy: null, status: { kind: "offline" } };
    }
    return {
      sessions: [],
      policy: null,
      status: {
        kind: "error",
        message: t(`agents.bridgeStatus.${result.kind}`),
      },
    };
  }

  // Gate: only Daemon-isolated agents (or those with a leftover
  // token so the user can still revoke it) should see the panel.
  const isGated = mode !== "daemon_isolated" && storedTokenHash === null;
  if (isGated) return null;

  async function submitPair() {
    const code = pairingCode.trim().toUpperCase();
    if (!code) return;
    const resolvedBase = baseUrl.trim() || "http://127.0.0.1:43417";
    setStatus({ kind: "pairing" });
    // Generate the nonce up front so we have it whether the pair
    // call succeeds or fails. Save it only on success.
    const nonce = generateBridgeSessionNonce();
    const client = new BridgeClient({ baseUrl: resolvedBase, token: null });
    const result = await client.pair({
      pairingCode: code,
      deviceLabel: deviceLabel.trim() || undefined,
      sessionNonce: nonce,
    });
    if (result.kind !== "ok") {
      const messageKey =
        result.kind === "rejected"
          ? "agents.bridgePairRejected"
          : result.kind === "offline"
            ? "agents.bridgeStatus.offline"
            : result.kind === "forbidden_origin"
              ? "agents.bridgeStatus.forbidden_origin"
              : result.kind === "bad_request"
                ? "agents.bridgePairBadRequest"
                : "agents.bridgePairDaemonError";
      setStatus({ kind: "error", message: t(messageKey) });
      return;
    }
    // 3c.5: saveBridgeToken is async — wraps the bearer with the
    // per-origin AES-GCM KEK before writing localStorage. Await so
    // the subsequent probe() sees the same envelope the next load
    // will unwrap. The fail-closed hardening pass upgraded this to
    // throw `BridgeSecureStorageUnavailableError` when the KEK is
    // missing — we catch that here and abort the pair instead of
    // silently persisting plaintext.
    try {
      await saveBridgeToken({ aid, base_url: resolvedBase, token: result.token });
    } catch (err) {
      if (err instanceof BridgeSecureStorageUnavailableError) {
        setStatus({
          kind: "error",
          message: t("agents.bridgeSecureStorageUnavailable"),
        });
        return;
      }
      throw err;
    }
    saveBridgeSessionNonce(aid, nonce);
    const hash = await sha256HexBrowser(result.token);
    setStoredTokenHash(hash);
    setPairingCode("");
    setStatus({ kind: "probing" });
    const probed = await probe(resolvedBase, result.token, nonce);
    setPairedSessions(probed.sessions);
    setPolicy(probed.policy);
    setStatus(probed.status);
  }

  async function submitAdvanced() {
    const token = advancedToken.trim();
    if (!token) return;
    const resolvedBase = baseUrl.trim() || "http://127.0.0.1:43417";
    // Same fail-closed story as submitPair: if the browser has no
    // secure keystore we refuse to persist the paste rather than
    // falling back to plaintext.
    try {
      await saveBridgeToken({ aid, base_url: resolvedBase, token });
    } catch (err) {
      if (err instanceof BridgeSecureStorageUnavailableError) {
        setStatus({
          kind: "error",
          message: t("agents.bridgeSecureStorageUnavailable"),
        });
        return;
      }
      throw err;
    }
    // Advanced fallback = manual token paste (shared secret or a
    // 3b-era token). Neither carries a server-side nonce binding;
    // clear any stale per-aid nonce so the client doesn't send one.
    clearBridgeSessionNonce(aid);
    const hash = await sha256HexBrowser(token);
    setStoredTokenHash(hash);
    setAdvancedToken("");
    setStatus({ kind: "probing" });
    const probed = await probe(resolvedBase, token, null);
    setPairedSessions(probed.sessions);
    setPolicy(probed.policy);
    setStatus(probed.status);
  }

  async function revokeThis() {
    const existing = aid ? await loadBridgeToken(aid) : null;
    if (!existing) return;
    const nonce = loadBridgeSessionNonce(aid);
    const client = new BridgeClient({
      baseUrl: existing.base_url,
      token: existing.token,
      sessionNonce: nonce,
    });
    await client.revokeSession();
    clearBridgeToken(aid);
    clearBridgeSessionNonce(aid);
    setStoredTokenHash(null);
    setPairedSessions([]);
    setPolicy(null);
    setStatus({ kind: "idle" });
  }

  async function revokeAll() {
    const existing = aid ? await loadBridgeToken(aid) : null;
    if (!existing) return;
    if (
      typeof window !== "undefined" &&
      !window.confirm(t("agents.bridgeRevokeAllConfirm"))
    ) {
      return;
    }
    const nonce = loadBridgeSessionNonce(aid);
    const client = new BridgeClient({
      baseUrl: existing.base_url,
      token: existing.token,
      sessionNonce: nonce,
    });
    await client.revokeAllSessions();
    clearBridgeToken(aid);
    clearBridgeSessionNonce(aid);
    setStoredTokenHash(null);
    setPairedSessions([]);
    setPolicy(null);
    setStatus({ kind: "idle" });
  }

  const hasStored = storedTokenHash !== null;
  return (
    <div
      className="panel"
      style={{ marginTop: 10 }}
      data-testid="bridge-token-panel"
    >
      <p
        className="item-title"
        style={{ display: "flex", alignItems: "center", gap: 8 }}
      >
        <span>{t("agents.bridgePanelTitle")}</span>
        <span
          title={t("agents.bridgeAdvancedTooltip")}
          aria-label={t("agents.bridgeAdvancedTooltip")}
          style={{
            fontSize: 10,
            fontWeight: 500,
            padding: "1px 7px",
            borderRadius: 999,
            letterSpacing: 0.3,
            whiteSpace: "nowrap",
            background: "rgba(217, 119, 6, 0.14)",
            color: "#b45309",
            border: "1px solid rgba(217, 119, 6, 0.28)",
          }}
        >
          {t("agents.bridgeAdvancedBadge")}
        </span>
      </p>
      <p className="item-sub" style={{ marginTop: 4 }}>
        {t("agents.bridgePanelDesc")}
      </p>

      {/* Pair dialog — primary flow for Phase 3b */}
      {!hasStored ? (
        <div
          style={{
            marginTop: 10,
            padding: 10,
            borderRadius: 8,
            border: "1px solid var(--border, rgba(128,128,128,0.25))",
            display: "flex",
            flexDirection: "column",
            gap: 8,
          }}
        >
          <p className="item-sub" style={{ margin: 0, fontSize: 12 }}>
            {t("agents.bridgePairIntro")}
          </p>
          <label
            className="item-sub"
            style={{
              fontSize: 11,
              display: "flex",
              flexDirection: "column",
              gap: 2,
            }}
          >
            {t("agents.bridgePairCodeLabel")}
            <input
              className="input"
              value={pairingCode}
              onChange={(event) =>
                setPairingCode(event.target.value.toUpperCase())
              }
              placeholder="AIBX-XXXX-XXXX-XXXX"
              autoComplete="off"
              spellCheck={false}
              style={{ fontSize: 13, fontFamily: "ui-monospace, monospace" }}
            />
          </label>
          <label
            className="item-sub"
            style={{
              fontSize: 11,
              display: "flex",
              flexDirection: "column",
              gap: 2,
            }}
          >
            {t("agents.bridgeDeviceLabel")}
            <input
              className="input"
              value={deviceLabel}
              onChange={(event) => setDeviceLabel(event.target.value)}
              maxLength={64}
              style={{ fontSize: 12 }}
            />
          </label>
          <label
            className="item-sub"
            style={{
              fontSize: 11,
              display: "flex",
              flexDirection: "column",
              gap: 2,
            }}
          >
            {t("agents.bridgeBaseUrl")}
            <input
              className="input"
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              style={{ fontSize: 12 }}
              spellCheck={false}
            />
          </label>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <button
              type="button"
              className="btn primary"
              onClick={() => void submitPair()}
              disabled={!pairingCode.trim() || status.kind === "pairing"}
            >
              {status.kind === "pairing"
                ? t("agents.bridgePairBusy")
                : t("agents.bridgePairBtn")}
            </button>
            {status.kind === "error" ? (
              <span className="item-sub" style={{ fontSize: 12, color: "#c5221f" }}>
                {status.message}
              </span>
            ) : null}
          </div>
        </div>
      ) : null}

      {/* Paired-sessions list — always visible when a token is stored */}
      {hasStored ? (
        <div
          style={{
            marginTop: 10,
            padding: 10,
            borderRadius: 8,
            border: "1px solid var(--border, rgba(128,128,128,0.25))",
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 6,
            }}
          >
            <p className="item-sub" style={{ margin: 0, fontSize: 12, fontWeight: 500 }}>
              {t("agents.bridgeSessionsTitle")}
            </p>
            <span
              className="item-sub"
              style={{
                fontSize: 11,
                color:
                  status.kind === "paired"
                    ? "#188038"
                    : status.kind === "offline"
                      ? "#b45309"
                      : status.kind === "error"
                        ? "#c5221f"
                        : "var(--text-muted, #5f6368)",
              }}
            >
              {status.kind === "paired"
                ? t("agents.bridgeStatusOk")
                : status.kind === "offline"
                  ? t("agents.bridgeStatus.offline")
                  : status.kind === "error"
                    ? status.message
                    : status.kind === "probing"
                      ? t("agents.bridgeBtnChecking")
                      : ""}
            </span>
          </div>
          {pairedSessions.length === 0 ? (
            <p className="item-sub" style={{ margin: 0, fontSize: 11 }}>
              {status.kind === "offline"
                ? t("agents.bridgeSessionsOffline")
                : t("agents.bridgeSessionsEmpty")}
            </p>
          ) : (
            <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
              {pairedSessions.map((session, idx) => {
                const isThisBrowser =
                  !!storedTokenHash && session.id === storedTokenHash;
                return (
                  <li
                    key={session.id ?? `shared-${idx}`}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 8,
                      padding: "6px 0",
                      borderTop:
                        idx === 0
                          ? "none"
                          : "1px solid var(--border, rgba(128,128,128,0.18))",
                      opacity: session.shared_secret ? 0.65 : 1,
                    }}
                  >
                    <div style={{ minWidth: 0 }}>
                      <p
                        className="item-sub"
                        style={{
                          margin: 0,
                          fontSize: 12,
                          fontWeight: 500,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                        }}
                      >
                        {session.device_label}
                        {isThisBrowser ? (
                          <span
                            style={{
                              fontSize: 10,
                              padding: "1px 5px",
                              borderRadius: 999,
                              background: "rgba(52, 168, 83, 0.14)",
                              color: "#188038",
                              border: "1px solid rgba(52, 168, 83, 0.28)",
                            }}
                          >
                            {t("agents.bridgeSessionsThis")}
                          </span>
                        ) : null}
                      </p>
                      <p className="item-sub" style={{ margin: 0, fontSize: 10 }}>
                        {t("agents.bridgeSessionsCreated", {
                          at: session.created_at,
                        })}
                        {session.shared_secret
                          ? ""
                          : ` · ${t("agents.bridgeSessionsLastUsed", {
                              at: session.last_used_at,
                            })}`}
                      </p>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
          {policy ? (
            <p
              className="item-sub"
              style={{
                marginTop: 8,
                marginBottom: 0,
                fontSize: 11,
                // Fade to warning colour when the per-day bucket is
                // past 80 % so the user notices before they trip the
                // cap mid-restore.
                color:
                  policy.bridged_decrypts_per_day_used >=
                  Math.max(1, Math.floor(policy.bridged_decrypts_per_day_max * 0.8))
                    ? "#b45309"
                    : "var(--text-muted, #5f6368)",
              }}
              data-testid="bridge-rate-quota"
            >
              {t("agents.bridgeQuota", {
                dayUsed: policy.bridged_decrypts_per_day_used,
                dayMax: policy.bridged_decrypts_per_day_max,
                minUsed: policy.bridged_decrypts_per_min_used,
                minMax: policy.bridged_decrypts_per_min_max,
              })}
            </p>
          ) : null}
          <div
            style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}
          >
            <button type="button" className="btn" onClick={() => void revokeThis()}>
              {t("agents.bridgeRevokeThis")}
            </button>
            <button type="button" className="btn" onClick={() => void revokeAll()}>
              {t("agents.bridgeRevokeAll")}
            </button>
          </div>
        </div>
      ) : null}

      {/* Advanced fallback — manual token paste for Phase 3a migration */}
      <div style={{ marginTop: 10 }}>
        <button
          type="button"
          className="btn"
          style={{ fontSize: 11 }}
          onClick={() => setShowAdvanced((prev) => !prev)}
        >
          {showAdvanced
            ? t("agents.bridgeAdvancedHide")
            : t("agents.bridgeAdvancedShow")}
        </button>
        {showAdvanced ? (
          <div
            style={{
              marginTop: 8,
              padding: 10,
              borderRadius: 8,
              border: "1px dashed var(--border, rgba(128,128,128,0.25))",
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            <p className="item-sub" style={{ margin: 0, fontSize: 11 }}>
              {t("agents.bridgeAdvancedIntro")}
            </p>
            <label
              className="item-sub"
              style={{ fontSize: 11, display: "flex", flexDirection: "column", gap: 2 }}
            >
              {t("agents.bridgeTokenLabel")}
              <input
                className="input"
                type="password"
                autoComplete="off"
                value={advancedToken}
                onChange={(event) => setAdvancedToken(event.target.value)}
                placeholder={t("agents.bridgeTokenPlaceholderEmpty")}
                style={{ fontSize: 12 }}
                spellCheck={false}
              />
            </label>
            <button
              type="button"
              className="btn"
              onClick={() => void submitAdvanced()}
              disabled={!advancedToken.trim()}
              style={{ fontSize: 12, alignSelf: "flex-start" }}
            >
              {t("agents.bridgeBtnSave")}
            </button>
          </div>
        ) : null}
      </div>

      <Link
        href="/help#help-modes"
        className="item-sub"
        style={{
          fontSize: 12,
          marginTop: 8,
          display: "inline-block",
          textDecoration: "underline",
          color: "var(--primary, #1a73e8)",
        }}
      >
        {t("agents.bridgeHelpLink")} →
      </Link>
    </div>
  );
}

export default function AgentsSettingsPage() {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const updateAgent = useUpdateAgentMutation();
  const deleteAgent = useDeleteAgentMutation();
  const credentialsQuery = useAgentCredentialsQuery();
  const createCredential = useCreateAgentCredentialMutation();
  const revokeCredential = useRevokeAgentCredentialMutation();
  const purgeCredential = usePurgeAgentCredentialMutation();
  const emergencyShutdown = useEmergencyShutdownMutation();

  // Server-side grace window for `POST /agent-credentials/:id/purge`. Keep
  // in sync with CREDENTIAL_PURGE_GRACE_DAYS in services/api/src/lib.rs.
  const PURGE_GRACE_DAYS = 7;

  const [activeDid, setActiveDid] = useState<string>("");
  const [editingLabel, setEditingLabel] = useState<string>("");
  const [credLabel, setCredLabel] = useState<string>("");
  const [createdCredential, setCreatedCredential] = useState<CreatedCredentialNotice | null>(null);
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [banner, setBanner] = useState<Banner>(null);
  const [showRevoked, setShowRevoked] = useState<boolean>(false);
  // Ticking clock so the pending-activation countdown re-renders without
  // requiring user interaction. 15s is fine: the TTL is 10 minutes and
  // the display resolution is 1 minute until the last stretch.
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  useEffect(() => {
    const handle = setInterval(() => setNowMs(Date.now()), 15_000);
    return () => clearInterval(handle);
  }, []);

  const { layoutStyle, startResize } = useTwoColumnResize({
    storageKey: "nexusinbox.settings_agents.thread_width.v1",
    initialWidth: 340,
  });

  const agents = useMemo(
    () => agentsQuery.data?.agents ?? [],
    [agentsQuery.data],
  );

  const activeAgent = useMemo(() => {
    if (agents.length === 0) return null;
    if (activeDid) {
      return agents.find((agent) => agent.did === activeDid) ?? agents[0];
    }
    return agents[0];
  }, [agents, activeDid]);

  // Reset per-agent transient state whenever the selection changes so
  // nothing visibly bleeds across agents:
  //   - rename buffer (would clobber the new agent's label)
  //   - one-shot credential notice (the credentialId / enrollmentSecret
  //     panel is bound to the agent it was created for; keeping it
  //     visible after the user switches agents is confusing and looks
  //     like the values belong to the new selection)
  useEffect(() => {
    setIsEditing(false);
    setEditingLabel(activeAgent?.label ?? "");
    setCreatedCredential(null);
  }, [activeAgent?.did, activeAgent?.label]);

  const handleSaveRename = async () => {
    if (!activeAgent) return;
    const label = editingLabel.trim();
    if (!label) {
      setBanner({ tone: "error", text: t("agents.bannerNameEmpty") });
      return;
    }
    if (label === activeAgent.label) {
      setIsEditing(false);
      return;
    }
    try {
      await updateAgent.mutateAsync({ id: activeAgent.id, body: { label } });
      setIsEditing(false);
      setBanner({ tone: "success", text: t("agents.bannerNameUpdated") });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerNameFailed") });
    }
  };

  const handleToggleAutoReply = async () => {
    if (!activeAgent) return;
    try {
      await updateAgent.mutateAsync({
        id: activeAgent.id,
        body: { auto_reply: !activeAgent.auto_reply },
      });
      setBanner({
        tone: "success",
        text: activeAgent.auto_reply
          ? t("agents.bannerAutoReplyOff")
          : t("agents.bannerAutoReplyOn"),
      });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerAutoReplyFailed") });
    }
  };

  const handleDelete = async () => {
    if (!activeAgent) return;
    const confirmed = window.confirm(
      t("agents.confirmDelete", { label: activeAgent.label }),
    );
    if (!confirmed) return;
    try {
      await deleteAgent.mutateAsync(activeAgent.id);
      setActiveDid("");
      setBanner({ tone: "success", text: t("agents.bannerDeleted") });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerDeleteFailed") });
    }
  };

  const copyValue = async (value: string, successText: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setBanner({ tone: "success", text: successText });
    } catch {
      setBanner({ tone: "error", text: t("agents.bannerCopyFailed") });
    }
  };

  const bannerClass =
    banner?.tone === "error"
      ? "item-sub"
      : banner?.tone === "success"
        ? "item-sub"
        : "item-sub";

  return (
    <AppShell
      title={t("agents.title")}
      activePath="/settings/agents"
      rightAction={
        <RefreshIconButton
          onClick={() => agentsQuery.refetch()}
          label={t("agents.refresh")}
        />
      }
    >
      {/* Action bar directly below the topbar search — mirrors the agent
          switcher bar on /agent/{did} so create/refresh affordances stay in
          a consistent location across settings screens. */}
      <section className="agent-switcher-bar">
        <Link className="btn primary" href="/settings/agents/new">
          {t("agents.newAgent")}
        </Link>
      </section>
      <section className="mail-layout" style={layoutStyle}>
        <aside className="thread-list">
          {agents.length === 0 ? (
            <div className="empty-state" style={{ padding: 16 }}>
              {t("agents.empty")}
            </div>
          ) : (
            agents.map((agent, index) => {
              const isActive = activeAgent
                ? activeAgent.did === agent.did
                : index === 0;
              const className = "card-item" + (isActive ? " active" : "");
              return (
                <article
                  className={className}
                  key={agent.id + "-" + agent.did}
                  onClick={() => setActiveDid(agent.did)}
                >
                  <p className="card-title">{agent.label}</p>
                  <p className="card-sub" style={{ wordBreak: "break-all" }}>
                    {agent.did}
                  </p>
                  <p className="card-meta">
                    <span>{t("agents.unread", { count: agent.unread_count })}</span>
                    <span>
                      {agent.auto_reply ? t("agents.autoReplyOn") : t("agents.autoReplyOff")}
                    </span>
                  </p>
                </article>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResize} />

        <article className="reader-pane" style={{ borderRight: "none" }}>
          {activeAgent ? (
            <>
              <header className="reader-header">
                <div
                  className="row"
                  style={{
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    gap: 12,
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    {isEditing ? (
                      <input
                        className="input"
                        value={editingLabel}
                        onChange={(event) => setEditingLabel(event.target.value)}
                        placeholder={t("agents.namePlaceholder")}
                        autoFocus
                      />
                    ) : (
                      <h2 className="reader-subject">{activeAgent.label}</h2>
                    )}
                    {activeAgent.aid ? (
                      <p
                        className="reader-meta"
                        style={{ wordBreak: "break-all", marginTop: 6 }}
                      >
                        {activeAgent.aid}
                      </p>
                    ) : null}
                    <p
                      className="reader-meta"
                      style={{
                        wordBreak: "break-all",
                        marginTop: 4,
                        fontSize: 11,
                        opacity: 0.7,
                      }}
                    >
                      {activeAgent.did}
                    </p>
                  </div>
                  <div className="row" style={{ gap: 8, flexShrink: 0 }}>
                    {isEditing ? (
                      <>
                        <button
                          className="btn primary"
                          type="button"
                          onClick={handleSaveRename}
                          disabled={updateAgent.isPending}
                        >
                          {t("agents.save")}
                        </button>
                        <button
                          className="btn"
                          type="button"
                          onClick={() => {
                            setIsEditing(false);
                            setEditingLabel(activeAgent.label);
                          }}
                          disabled={updateAgent.isPending}
                        >
                          {t("agents.cancel")}
                        </button>
                      </>
                    ) : (
                      <button
                        className="btn"
                        type="button"
                        onClick={() => {
                          setIsEditing(true);
                          setEditingLabel(activeAgent.label);
                          setBanner(null);
                        }}
                      >
                        {t("agents.editName")}
                      </button>
                    )}
                  </div>
                </div>
              </header>

              <div className="reader-body">
                {banner ? (
                  <p className={bannerClass} style={{ marginBottom: 12 }}>
                    {banner.text}
                  </p>
                ) : null}

                <div className="panel">
                  <p className="item-title">{t("agents.overviewTitle")}</p>
                  {activeAgent.aid ? (
                    <div style={{ marginTop: 6 }}>
                      <p className="item-sub" style={{ wordBreak: "break-all" }}>
                        {t("agents.agentId", { aid: activeAgent.aid })}
                      </p>
                      <p className="item-sub" style={{ marginTop: 4 }}>
                        {t("agents.agentIdHelp")}
                      </p>
                      <button
                        className="btn"
                        type="button"
                        style={{ marginTop: 6, fontSize: 12 }}
                        onClick={() =>
                          copyValue(activeAgent.aid, t("agents.bannerAidCopied"))
                        }
                      >
                        {t("agents.copyAgentId")}
                      </button>
                    </div>
                  ) : null}
                  <div style={{ marginTop: activeAgent.aid ? 10 : 6 }}>
                    <p className="item-sub" style={{ wordBreak: "break-all" }}>
                      {t("agents.currentDid", { did: activeAgent.did })}
                    </p>
                    <p className="item-sub" style={{ marginTop: 4 }}>
                      {t("agents.currentDidHelp")}
                    </p>
                    <button
                      className="btn"
                      type="button"
                      style={{ marginTop: 6, fontSize: 12 }}
                      onClick={() =>
                        copyValue(activeAgent.did, t("agents.bannerDidCopied"))
                      }
                    >
                      {t("agents.copyDid")}
                    </button>
                  </div>
                  <p className="item-sub">
                    {t("agents.unreadCount", { count: activeAgent.unread_count })}
                  </p>
                  <p className="item-sub">
                    {t("agents.createdAt", { date: new Date(activeAgent.created_at).toLocaleDateString() })}
                  </p>
                  <p className="item-sub">
                    {activeAgent.is_active ? t("agents.statusActive") : t("agents.statusStopped")}
                  </p>
                </div>

                <AgentModePanel
                  aid={activeAgent.aid}
                  credentials={credentialsQuery.data?.credentials ?? []}
                />

                {/* Per-device "where are this agent's keys reachable
                    from?" panel — pairs with the Mode badge above by
                    answering the orthogonal question of what THIS
                    device can do with the agent right now. Renders
                    only when we know a current did to ask about. */}
                {activeAgent.did ? (
                  <AgentKeyWhereaboutsPanel
                    aid={activeAgent.aid}
                    did={activeAgent.did}
                  />
                ) : null}

                <BridgeTokenPanel
                  aid={activeAgent.aid}
                  credentials={credentialsQuery.data?.credentials ?? []}
                />

                <div className="panel" style={{ marginTop: 10 }}>
                  <div
                    className="row"
                    style={{
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 12,
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p className="item-title">{t("agents.autoReplyTitle")}</p>
                      <p className="item-sub" style={{ marginTop: 4 }}>
                        {t("agents.autoReplyDesc")}
                      </p>
                    </div>
                    <button
                      className="btn"
                      type="button"
                      onClick={handleToggleAutoReply}
                      disabled={updateAgent.isPending}
                    >
                      {activeAgent.auto_reply ? t("agents.autoReplyDisableBtn") : t("agents.autoReplyEnableBtn")}
                    </button>
                  </div>
                </div>

                <AutoReplyPolicyPanel
                  agentId={activeAgent.id}
                  masterEnabled={activeAgent.auto_reply}
                />

                <AutoReplyVisibilityPanel aid={activeAgent.aid} />

                <div className="panel" style={{ marginTop: 10 }}>
                  <p className="item-title">{t("agents.rulesTitle")}</p>
                  <p className="item-sub" style={{ marginTop: 6 }}>
                    {t("agents.rule1")}
                  </p>
                  <p className="item-sub">
                    {t("agents.rule2")}
                  </p>
                </div>

                <div className="panel" style={{ marginTop: 10 }}>
                  <p className="item-title">{t("agents.credentialsTitle")}</p>
                  <p className="item-sub" style={{ marginTop: 4 }}>
                    {t("agents.credentialsDesc")}
                  </p>

                  {(() => {
                    const allForAgent = (credentialsQuery.data?.credentials ?? []).filter(
                      (c) => c.aid === activeAgent.aid,
                    );
                    const isLive = (s: string) => s === "active" || s === "pending";
                    const liveCreds = allForAgent.filter((c) => isLive(c.status));
                    const deadCreds = allForAgent.filter((c) => !isLive(c.status));
                    const visibleCreds = showRevoked
                      ? [...liveCreds, ...deadCreds]
                      : liveCreds;

                    // Render the pending status line with a countdown derived
                    // from enrollment_expires_at. All TTL arithmetic happens
                    // client-side off the server-provided timestamp so the
                    // display stays correct even if the TTL policy changes.
                    const renderPendingStatus = (expiresAtIso: string | null | undefined) => {
                      if (!expiresAtIso) return t("agents.credStatusPending");
                      const expMs = Date.parse(expiresAtIso);
                      if (Number.isNaN(expMs)) return t("agents.credStatusPending");
                      const deltaMs = expMs - nowMs;
                      if (deltaMs <= 0) return t("agents.credExpired");
                      if (deltaMs < 60_000) {
                        return t("agents.credExpiresSoon", {
                          seconds: Math.max(1, Math.ceil(deltaMs / 1000)),
                        });
                      }
                      return t("agents.credExpiresIn", {
                        minutes: Math.ceil(deltaMs / 60_000),
                      });
                    };

                    return (
                      <>
                        {visibleCreds.length > 0 ? (
                          <div style={{ marginTop: 8 }}>
                            {visibleCreds.map((cred) => {
                              const isDead = !isLive(cred.status);
                              return (
                                <div
                                  key={cred.credential_id}
                                  className="row"
                                  style={{
                                    justifyContent: "space-between",
                                    alignItems: "center",
                                    gap: 8,
                                    padding: "6px 0",
                                    borderBottom: "1px solid var(--border)",
                                    opacity: isDead ? 0.55 : 1,
                                  }}
                                >
                                  <div style={{ minWidth: 0 }}>
                                    <p className="card-title" style={{ margin: 0, fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
                                      <span>{cred.label}</span>
                                      <CredentialModeBadge
                                        keyHolder={cred.key_holder ?? "unknown"}
                                      />
                                    </p>
                                    <p className="card-sub" style={{ margin: 0, fontSize: 11 }}>
                                      {t("agents.credIdShort", {
                                        id: cred.credential_id.slice(0, 8),
                                      })}
                                    </p>
                                    <p className="card-sub" style={{ margin: 0, fontSize: 11 }}>
                                      {cred.status === "active"
                                        ? t("agents.credStatusActive")
                                        : cred.status === "pending"
                                          ? renderPendingStatus(cred.enrollment_expires_at)
                                          : cred.status === "revoked"
                                            ? t("agents.credStatusRevoked")
                                            : t("agents.credStatusCompromised")}
                                      {cred.last_used_at
                                        ? t("agents.credLastUsed", { date: new Date(cred.last_used_at).toLocaleDateString() })
                                        : ""}
                                    </p>
                                  </div>
                                  <div className="row" style={{ gap: 6, flexShrink: 0 }}>
                                    <button
                                      className="btn"
                                      type="button"
                                      style={{ fontSize: 12 }}
                                      onClick={() =>
                                        copyValue(
                                          cred.credential_id,
                                          t("agents.bannerCredIdCopied"),
                                        )
                                      }
                                    >
                                      {t("agents.copy")}
                                    </button>
                                    {!isDead ? (
                                      <button
                                        className="btn"
                                        type="button"
                                        style={{
                                          fontSize: 12,
                                          borderColor: "rgba(220, 38, 38, 0.4)",
                                          color: "#dc2626",
                                        }}
                                        disabled={revokeCredential.isPending}
                                        onClick={async () => {
                                          if (!window.confirm(t("agents.confirmRevoke")))
                                            return;
                                          try {
                                            await revokeCredential.mutateAsync(cred.credential_id);
                                            setBanner({ tone: "success", text: t("agents.bannerCredRevoked") });
                                          } catch {
                                            setBanner({ tone: "error", text: t("agents.bannerCredRevokeFailed") });
                                          }
                                        }}
                                      >
                                        {t("agents.credRevoke")}
                                      </button>
                                    ) : null}
                                    {cred.status === "revoked"
                                      ? (() => {
                                          // Compute grace from the server-provided revoked_at,
                                          // not from created_at, so the server's eligibility
                                          // check is what actually gates the button.
                                          const revokedMs = cred.revoked_at
                                            ? Date.parse(cred.revoked_at)
                                            : NaN;
                                          if (Number.isNaN(revokedMs)) return null;
                                          const graceMs =
                                            PURGE_GRACE_DAYS * 24 * 60 * 60 * 1000;
                                          const elapsedMs = nowMs - revokedMs;
                                          const remainingMs = graceMs - elapsedMs;
                                          if (remainingMs > 0) {
                                            return (
                                              <span
                                                className="item-sub"
                                                style={{ fontSize: 11, opacity: 0.8 }}
                                              >
                                                {t("agents.credPurgePendingGrace", {
                                                  days: Math.ceil(remainingMs / (24 * 60 * 60 * 1000)),
                                                })}
                                              </span>
                                            );
                                          }
                                          return (
                                            <button
                                              className="btn"
                                              type="button"
                                              style={{
                                                fontSize: 12,
                                                borderColor: "rgba(220, 38, 38, 0.7)",
                                                color: "#b91c1c",
                                              }}
                                              disabled={purgeCredential.isPending}
                                              onClick={async () => {
                                                if (!window.confirm(t("agents.credPurgeConfirm"))) return;
                                                try {
                                                  await purgeCredential.mutateAsync(
                                                    cred.credential_id,
                                                  );
                                                  setBanner({
                                                    tone: "success",
                                                    text: t("agents.credPurgeSuccess"),
                                                  });
                                                } catch (err) {
                                                  const isGrace =
                                                    err && typeof err === "object" && "status" in err
                                                      ? (err as { status?: number }).status === 409
                                                      : false;
                                                  setBanner({
                                                    tone: "error",
                                                    text: isGrace
                                                      ? t("agents.credPurgeGraceError")
                                                      : t("agents.credPurgeFailed"),
                                                  });
                                                }
                                              }}
                                            >
                                              {t("agents.credPurge")}
                                            </button>
                                          );
                                        })()
                                      : null}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        ) : (
                          <p className="item-sub" style={{ marginTop: 8 }}>
                            {allForAgent.length === 0
                              ? t("agents.credEmpty")
                              : t("agents.credEmptyLive")}
                          </p>
                        )}
                        {deadCreds.length > 0 ? (
                          <div style={{ marginTop: 6 }}>
                            <button
                              type="button"
                              className="btn"
                              style={{ fontSize: 11 }}
                              onClick={() => setShowRevoked((prev) => !prev)}
                            >
                              {showRevoked
                                ? t("agents.credHideRevoked")
                                : t("agents.credShowRevoked", { count: deadCreds.length })}
                            </button>
                          </div>
                        ) : null}
                      </>
                    );
                  })()}

                  <div style={{ marginTop: 10 }}>
                    <input
                      className="input"
                      value={credLabel}
                      onChange={(e) => setCredLabel(e.target.value)}
                      placeholder={t("agents.credNewPlaceholder")}
                      style={{ fontSize: 13 }}
                    />
                    <div className="row" style={{ marginTop: 6, gap: 8 }}>
                      <button
                        className="btn primary"
                        type="button"
                        disabled={createCredential.isPending}
                        onClick={async () => {
                          const label = credLabel.trim();
                          if (!label) {
                            setBanner({ tone: "error", text: t("agents.bannerCredNameEmpty") });
                            return;
                          }
                          try {
                            const result = await createCredential.mutateAsync({
                              agent_id: activeAgent.id,
                              label,
                            });
                            setCredLabel("");
                            setCreatedCredential(
                              result.enrollment_secret
                                ? {
                                    credentialId: result.credential_id,
                                    enrollmentSecret: result.enrollment_secret,
                                    aid: result.aid,
                                  }
                                : null,
                            );
                            setBanner({
                              tone: "success",
                              text: t("agents.bannerCredCreated"),
                            });
                          } catch {
                            setBanner({ tone: "error", text: t("agents.bannerCredCreateFailed") });
                          }
                        }}
                      >
                        {createCredential.isPending ? t("agents.credCreating") : t("agents.credNewBtn")}
                      </button>
                    </div>
                  </div>

                  {createdCredential ? (
                    <div
                      style={{
                        marginTop: 10,
                        padding: 10,
                        background: "rgba(255, 200, 0, 0.1)",
                        border: "1px solid rgba(255, 200, 0, 0.3)",
                        borderRadius: 6,
                      }}
                    >
                      <p className="item-title" style={{ fontSize: 12 }}>
                        {t("agents.enrollmentTitle")}
                      </p>
                      <div style={{ marginTop: 6 }}>
                        <p className="item-sub" style={{ fontSize: 11 }}>
                          {t("agents.enrollmentAid", { aid: createdCredential.aid })}
                        </p>
                        <p className="item-sub" style={{ fontSize: 11, marginTop: 6 }}>
                          {t("agents.enrollmentCredentialId")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            wordBreak: "break-all",
                            fontSize: 12,
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {createdCredential.credentialId}
                        </code>
                        <button
                          className="btn"
                          type="button"
                          style={{ marginTop: 6, fontSize: 12 }}
                          onClick={() =>
                            copyValue(
                              createdCredential.credentialId,
                              t("agents.bannerCredIdCopied"),
                            )
                          }
                        >
                          {t("agents.copyCredentialId")}
                        </button>
                        <p className="item-sub" style={{ fontSize: 11, marginTop: 10 }}>
                          {t("agents.enrollmentSecretLabel")}
                        </p>
                        <code
                          style={{
                            display: "block",
                            wordBreak: "break-all",
                            fontSize: 12,
                            marginTop: 4,
                            userSelect: "all",
                          }}
                        >
                          {createdCredential.enrollmentSecret}
                        </code>
                        <button
                          className="btn"
                          type="button"
                          style={{ marginTop: 6, fontSize: 12 }}
                          onClick={() =>
                            copyValue(
                              createdCredential.enrollmentSecret,
                              t("agents.bannerEnrollmentSecretCopied"),
                            )
                          }
                        >
                          {t("agents.copyEnrollmentSecret")}
                        </button>
                      </div>
                      <button
                        className="btn"
                        type="button"
                        style={{ marginTop: 8, fontSize: 12 }}
                        onClick={() => setCreatedCredential(null)}
                      >
                        {t("agents.enrollmentClose")}
                      </button>
                    </div>
                  ) : null}
                </div>

                <div
                  className="panel"
                  style={{
                    marginTop: 10,
                    borderColor: "rgba(220, 38, 38, 0.35)",
                  }}
                >
                  <p className="item-title" style={{ color: "#dc2626" }}>
                    {t("agents.dangerTitle")}
                  </p>

                  <div style={{ marginTop: 8 }}>
                    <p className="item-sub">
                      {t("agents.emergencyDesc")}
                    </p>
                    <div className="row" style={{ marginTop: 6 }}>
                      <button
                        className="btn"
                        type="button"
                        disabled={emergencyShutdown.isPending}
                        style={{
                          borderColor: "rgba(220, 38, 38, 0.4)",
                          color: "#dc2626",
                          fontWeight: 600,
                        }}
                        onClick={async () => {
                          if (
                            !window.confirm(t("agents.confirmEmergency"))
                          )
                            return;
                          try {
                            const result = await emergencyShutdown.mutateAsync(activeAgent.id);
                            setBanner({
                              tone: "success",
                              text: t("agents.emergencyDone", { creds: result.credentials_revoked, tokens: result.tokens_revoked }),
                            });
                          } catch {
                            setBanner({ tone: "error", text: t("agents.emergencyFailed") });
                          }
                        }}
                      >
                        {emergencyShutdown.isPending ? t("agents.emergencyRunning") : t("agents.emergencyBtn")}
                      </button>
                    </div>
                  </div>

                  <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--border)" }}>
                    <p className="item-sub">
                      {t("agents.deleteDesc")}
                    </p>
                    <div className="row" style={{ marginTop: 6 }}>
                      <button
                        className="btn"
                        type="button"
                        onClick={handleDelete}
                        disabled={deleteAgent.isPending}
                        style={{
                          borderColor: "rgba(220, 38, 38, 0.4)",
                          color: "#dc2626",
                        }}
                      >
                        {deleteAgent.isPending ? t("agents.deleting") : t("agents.deleteBtn")}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="empty-state">
              {t("agents.emptyReader")}
            </div>
          )}
        </article>
      </section>
    </AppShell>
  );
}
