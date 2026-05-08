"use client";

import { useState, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import { AppShell } from "../../_components/AppShell";
import { useAuditLogQuery } from "../../../lib/api/hooks";
import type { AuditLogQuery } from "../../../lib/api/types";
import { useTranslation } from "../../../lib/i18n";

type EventMeta = {
  labelKey: string;
  severity: "info" | "warn" | "critical";
  descriptionKey: string;
};

const EVENT_META: Record<string, EventMeta> = {
  token_issued: {
    labelKey: "audit.tokenIssued",
    severity: "info",
    descriptionKey: "audit.tokenIssuedDesc",
  },
  token_refreshed: {
    labelKey: "audit.tokenRefreshed",
    severity: "info",
    descriptionKey: "audit.tokenRefreshedDesc",
  },
  token_revoked: {
    labelKey: "audit.tokenRevoked",
    severity: "warn",
    descriptionKey: "audit.tokenRevokedDesc",
  },
  credential_created: {
    labelKey: "audit.credentialCreated",
    severity: "info",
    descriptionKey: "audit.credentialCreatedDesc",
  },
  credential_activated: {
    labelKey: "audit.credentialActivated",
    severity: "info",
    descriptionKey: "audit.credentialActivatedDesc",
  },
  credential_revoked: {
    labelKey: "audit.credentialRevoked",
    severity: "warn",
    descriptionKey: "audit.credentialRevokedDesc",
  },
  key_rotation_started: {
    labelKey: "audit.keyRotationStarted",
    severity: "info",
    descriptionKey: "audit.keyRotationStartedDesc",
  },
  credential_compromised: {
    labelKey: "audit.credentialCompromised",
    severity: "critical",
    descriptionKey: "audit.credentialCompromisedDesc",
  },
  refresh_reuse_detected: {
    labelKey: "audit.refreshReuseDetected",
    severity: "critical",
    descriptionKey: "audit.refreshReuseDetectedDesc",
  },
  agent_message_sent: {
    labelKey: "audit.agentMessageSent",
    severity: "info",
    descriptionKey: "audit.agentMessageSentDesc",
  },
  emergency_shutdown: {
    labelKey: "audit.emergencyShutdown",
    severity: "critical",
    descriptionKey: "audit.emergencyShutdownDesc",
  },
  rate_limit_tripped: {
    labelKey: "audit.rateLimitTripped",
    severity: "warn",
    descriptionKey: "audit.rateLimitTrippedDesc",
  },
  policy_violation: {
    labelKey: "audit.policyViolation",
    severity: "warn",
    descriptionKey: "audit.policyViolationDesc",
  },
  // Phase 3c.3 bridge-lifecycle events forwarded by
  // signer-daemon's --bridge-forward-audit. Severity picks mirror
  // the threat model: success paths (decrypt/status/pair ok) are
  // info; pair_failed / pair_revoked are warn (explicit user
  // action or rejected attempt); nonce_mismatch / rate_limited
  // are classified as warn via their outcome rather than event —
  // the severity lookup uses event only, so the detail pane
  // highlights those via the outcome label.
  bridged_decrypt: {
    labelKey: "audit.bridgedDecrypt",
    severity: "info",
    descriptionKey: "audit.bridgedDecryptDesc",
  },
  bridged_status: {
    labelKey: "audit.bridgedStatus",
    severity: "info",
    descriptionKey: "audit.bridgedStatusDesc",
  },
  bridged_pair_requested: {
    labelKey: "audit.bridgedPairRequested",
    severity: "info",
    descriptionKey: "audit.bridgedPairRequestedDesc",
  },
  bridged_pair_succeeded: {
    labelKey: "audit.bridgedPairSucceeded",
    severity: "info",
    descriptionKey: "audit.bridgedPairSucceededDesc",
  },
  bridged_pair_failed: {
    labelKey: "audit.bridgedPairFailed",
    severity: "warn",
    descriptionKey: "audit.bridgedPairFailedDesc",
  },
  bridged_pair_revoked: {
    labelKey: "audit.bridgedPairRevoked",
    severity: "warn",
    descriptionKey: "audit.bridgedPairRevokedDesc",
  },
};

function severityColor(severity: "info" | "warn" | "critical"): string {
  switch (severity) {
    case "info":
      return "#6b7280";
    case "warn":
      return "#d97706";
    case "critical":
      return "#dc2626";
  }
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString("ja-JP", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

function EventGuide() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const sections = [
    {
      titleKey: "audit.guideInfo",
      severity: "info" as const,
      events: ["token_issued", "token_refreshed", "credential_created", "credential_activated", "key_rotation_started", "agent_message_sent"],
    },
    {
      titleKey: "audit.guideWarn",
      severity: "warn" as const,
      events: ["token_revoked", "credential_revoked", "rate_limit_tripped", "policy_violation"],
    },
    {
      titleKey: "audit.guideCritical",
      severity: "critical" as const,
      events: ["refresh_reuse_detected", "credential_compromised", "emergency_shutdown"],
    },
  ];

  return (
    <div style={{ marginBottom: 20 }}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "6px 12px",
          borderRadius: 6,
          border: "1px solid #d1d5db",
          background: open ? "#f3f4f6" : "#fff",
          fontSize: 13,
          color: "#374151",
          cursor: "pointer",
        }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
        {t("audit.guideBtn")}
        <svg
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
            transition: "transform 0.2s",
          }}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {open && (
        <div
          style={{
            marginTop: 12,
            border: "1px solid #e5e7eb",
            borderRadius: 10,
            background: "#fff",
            overflow: "hidden",
          }}
        >
          {sections.map((section) => (
            <div key={section.titleKey}>
              <div
                style={{
                  padding: "10px 16px",
                  background:
                    section.severity === "critical"
                      ? "#fef2f2"
                      : section.severity === "warn"
                        ? "#fffbeb"
                        : "#f0fdf4",
                  borderBottom: "1px solid #e5e7eb",
                  fontSize: 12,
                  fontWeight: 600,
                  color:
                    section.severity === "critical"
                      ? "#dc2626"
                      : section.severity === "warn"
                        ? "#d97706"
                        : "#16a34a",
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                }}
              >
                {t(section.titleKey)}
              </div>
              {section.events.map((key) => {
                const meta = EVENT_META[key];
                if (!meta) return null;
                return (
                  <div
                    key={key}
                    style={{
                      padding: "10px 16px",
                      borderBottom: "1px solid #f3f4f6",
                      display: "flex",
                      gap: 16,
                    }}
                  >
                    <div style={{ minWidth: 180, flexShrink: 0 }}>
                      <span style={{ fontSize: 13, fontWeight: 500, color: "#111827" }}>
                        {t(meta.labelKey)}
                      </span>
                      <br />
                      <code style={{ fontSize: 11, color: "#9ca3af" }}>{key}</code>
                    </div>
                    <p style={{ fontSize: 12, color: "#6b7280", margin: 0, lineHeight: 1.5 }}>
                      {t(meta.descriptionKey)}
                    </p>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function AuditLogPage() {
  const { t } = useTranslation();
  // Deep-link support: `?event=...` (and `?aid=...`) on the URL
  // pre-populates the filters. Used by the per-agent auto-reply
  // visibility panel link from /settings/agents. Read once on mount
  // — subsequent navigation goes through the in-page controls.
  const searchParams = useSearchParams();
  const initialEvent = searchParams?.get("event") ?? "";
  const initialAid = searchParams?.get("aid") ?? "";
  const [eventFilter, setEventFilter] = useState<string>(initialEvent);
  const [aidFilter, setAidFilter] = useState<string>(initialAid);
  // Quick-preset filter. `null` means "no preset" and the event
  // dropdown drives the query. `"bridged_"` activates the Phase
  // 3c.4 bridge-only view — clears the exact-event dropdown so the
  // two don't fight each other (server also prefers `event` when
  // both are supplied, but the UI stays in sync).
  const [presetPrefix, setPresetPrefix] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const toggleExpanded = useCallback((id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);
  const pageSize = 30;

  const query: AuditLogQuery = {
    limit: pageSize,
    offset: page * pageSize,
    ...(eventFilter ? { event: eventFilter } : {}),
    ...(aidFilter ? { aid: aidFilter } : {}),
    ...(presetPrefix && !eventFilter ? { event_prefix: presetPrefix } : {}),
  };

  const auditQuery = useAuditLogQuery(query);
  const events = auditQuery.data?.events ?? [];
  const total = auditQuery.data?.total ?? 0;
  const totalPages = Math.ceil(total / pageSize);

  return (
    <AppShell
      title={t("audit.title")}
      activePath="/settings/audit"
    >
      <div style={{ padding: "24px", maxWidth: 960, margin: "0 auto" }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 8 }}>
          {t("audit.pageTitle")}
        </h1>
        <p style={{ color: "#6b7280", fontSize: 14, marginBottom: 20 }}>
          {t("audit.pageDesc")}
        </p>

        {/* Filters */}
        <div style={{ display: "flex", gap: 12, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
          <select
            value={eventFilter}
            onChange={(e) => {
              setEventFilter(e.target.value);
              setPage(0);
              // A specific event takes precedence over the preset;
              // clearing the preset avoids a mismatched checkbox
              // state ("bridge only" highlighted while showing
              // token_issued).
              if (e.target.value) setPresetPrefix(null);
            }}
            style={{
              padding: "6px 10px",
              borderRadius: 6,
              border: "1px solid #d1d5db",
              fontSize: 13,
              background: "#fff",
            }}
          >
            <option value="">{t("audit.allEvents")}</option>
            {Object.entries(EVENT_META).map(([key, { labelKey }]) => (
              <option key={key} value={key}>
                {t(labelKey)}
              </option>
            ))}
          </select>

          {/* Phase 3c.4 bridge-only preset. Doubles as a visual
              reminder that bridged events flow in via the Phase
              3c.3 forwarder; toggling it off returns to the full
              event stream. */}
          <button
            type="button"
            onClick={() => {
              setPage(0);
              if (presetPrefix === "bridged_") {
                setPresetPrefix(null);
              } else {
                setPresetPrefix("bridged_");
                setEventFilter("");
              }
            }}
            aria-pressed={presetPrefix === "bridged_"}
            style={{
              padding: "6px 12px",
              borderRadius: 6,
              border: presetPrefix === "bridged_"
                ? "1px solid rgba(66, 133, 244, 0.4)"
                : "1px solid #d1d5db",
              background: presetPrefix === "bridged_"
                ? "rgba(66, 133, 244, 0.12)"
                : "#fff",
              color: presetPrefix === "bridged_" ? "#1a73e8" : "#374151",
              fontSize: 13,
              cursor: "pointer",
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: 999,
                background: presetPrefix === "bridged_" ? "#1a73e8" : "#9ca3af",
              }}
              aria-hidden="true"
            />
            {t("audit.presetBridgeOnly")}
          </button>

          <span style={{ fontSize: 13, color: "#6b7280", lineHeight: "32px" }}>
            {total} {t("common.items", { count: total }).replace(`${total} `, "")}
          </span>

          {/* Per-agent filter pill — populated from `?aid=...` deep
              links from /settings/agents (e.g. the auto-reply
              visibility panel "View all" link). Plain badge instead
              of a dropdown because the user can only land here
              filtered, never construct an aid by hand. */}
          {aidFilter ? (
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "4px 8px 4px 10px",
                borderRadius: 999,
                background: "rgba(66, 133, 244, 0.12)",
                border: "1px solid rgba(66, 133, 244, 0.32)",
                color: "#1a73e8",
                fontSize: 12,
              }}
            >
              <span style={{ fontFamily: "monospace", fontSize: 11 }}>
                {aidFilter.length > 28
                  ? `${aidFilter.slice(0, 14)}…${aidFilter.slice(-8)}`
                  : aidFilter}
              </span>
              <button
                type="button"
                onClick={() => {
                  setAidFilter("");
                  setPage(0);
                }}
                aria-label={t("audit.clearAidFilter")}
                style={{
                  border: "none",
                  background: "transparent",
                  color: "#1a73e8",
                  cursor: "pointer",
                  padding: 0,
                  fontSize: 14,
                  lineHeight: 1,
                }}
              >
                ×
              </button>
            </span>
          ) : null}
        </div>

        <EventGuide />

        {/* Event list */}
        {auditQuery.isLoading && (
          <p style={{ color: "#9ca3af", fontSize: 14 }}>{t("audit.loading")}</p>
        )}

        {auditQuery.isError && (
          <p style={{ color: "#dc2626", fontSize: 14 }}>
            {t("audit.loadFailed")}
          </p>
        )}

        {!auditQuery.isLoading && events.length === 0 && (
          <div style={{ textAlign: "center", padding: "40px 24px", color: "#9ca3af" }}>
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" style={{ margin: "0 auto 12px", display: "block", opacity: 0.4 }}>
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="16" y1="13" x2="8" y2="13" />
              <line x1="16" y1="17" x2="8" y2="17" />
            </svg>
            <p style={{ fontSize: 14, marginBottom: 4 }}>{t("audit.emptyTitle")}</p>
            <p style={{ fontSize: 12 }}>
              {t("audit.emptyDesc")}
            </p>
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {events.map((entry) => {
            const meta = EVENT_META[entry.event] ?? {
              labelKey: entry.event,
              severity: "info" as const,
              descriptionKey: "",
            };
            const label = meta.labelKey === entry.event ? entry.event : t(meta.labelKey);
            const description = meta.descriptionKey ? t(meta.descriptionKey) : "";
            const isExpanded = expandedId === entry.id;
            return (
              <div
                key={entry.id}
                style={{
                  border: "1px solid #e5e7eb",
                  borderRadius: 8,
                  padding: "12px 16px",
                  background:
                    meta.severity === "critical"
                      ? "#fef2f2"
                      : meta.severity === "warn"
                        ? "#fffbeb"
                        : "#fff",
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
                  <span
                    style={{
                      fontWeight: 600,
                      fontSize: 14,
                      color: severityColor(meta.severity),
                    }}
                  >
                    {meta.severity === "critical" && "\u26a0 "}
                    {label}
                  </span>
                  <span style={{ fontSize: 12, color: "#9ca3af" }}>
                    {formatTimestamp(entry.created_at)}
                  </span>
                </div>

                <div style={{ fontSize: 12, color: "#6b7280" }}>
                  {entry.aid && (
                    <span style={{ marginRight: 12 }}>
                      AID: <code style={{ fontSize: 11 }}>{entry.aid}</code>
                    </span>
                  )}
                  {entry.credential_id && (
                    <span>
                      Credential:{" "}
                      <code style={{ fontSize: 11 }}>
                        {entry.credential_id.slice(0, 8)}...
                      </code>
                    </span>
                  )}
                </div>

                {Object.keys(entry.detail).length > 0 && (
                  <pre
                    style={{
                      marginTop: 6,
                      fontSize: 11,
                      color: "#4b5563",
                      background: "#f9fafb",
                      padding: "6px 8px",
                      borderRadius: 4,
                      overflow: "auto",
                      maxHeight: 100,
                    }}
                  >
                    {JSON.stringify(entry.detail, null, 2)}
                  </pre>
                )}

                {description && (
                  <div style={{ marginTop: 6 }}>
                    <button
                      type="button"
                      onClick={() => toggleExpanded(entry.id)}
                      style={{
                        background: "none",
                        border: "none",
                        padding: 0,
                        fontSize: 11,
                        color: "#6b7280",
                        cursor: "pointer",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 4,
                      }}
                    >
                      <svg
                        width="12"
                        height="12"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        style={{
                          transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
                          transition: "transform 0.15s",
                        }}
                      >
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                      {isExpanded ? t("audit.guideClose") : t("audit.guideOpen")}
                    </button>
                    {isExpanded && (
                      <p
                        style={{
                          marginTop: 6,
                          fontSize: 12,
                          color: "#4b5563",
                          lineHeight: 1.6,
                          background: "#f9fafb",
                          padding: "8px 12px",
                          borderRadius: 6,
                          borderLeft: `3px solid ${severityColor(meta.severity)}`,
                        }}
                      >
                        {description}
                      </p>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div
            style={{
              display: "flex",
              justifyContent: "center",
              gap: 8,
              marginTop: 16,
            }}
          >
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              style={{
                padding: "4px 12px",
                borderRadius: 4,
                border: "1px solid #d1d5db",
                background: "#fff",
                cursor: page === 0 ? "default" : "pointer",
                opacity: page === 0 ? 0.4 : 1,
              }}
            >
              {t("audit.prev")}
            </button>
            <span style={{ fontSize: 13, lineHeight: "28px", color: "#6b7280" }}>
              {page + 1} / {totalPages}
            </span>
            <button
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
              style={{
                padding: "4px 12px",
                borderRadius: 4,
                border: "1px solid #d1d5db",
                background: "#fff",
                cursor: page >= totalPages - 1 ? "default" : "pointer",
                opacity: page >= totalPages - 1 ? 0.4 : 1,
              }}
            >
              {t("audit.next")}
            </button>
          </div>
        )}
      </div>
    </AppShell>
  );
}
