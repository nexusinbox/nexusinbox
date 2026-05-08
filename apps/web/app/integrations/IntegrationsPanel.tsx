"use client";

import { ReactNode, useCallback, useEffect, useState } from "react";
import { useAgentsQuery, useStatusQuery } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";
import {
  calendarClientId,
  disconnectCalendar,
  isCalendarConnected,
  requestCalendarToken,
} from "../../lib/calendar/gcalAuth";
import {
  DEFAULT_ANTHROPIC_MODEL,
  disconnectLLM,
  getLLMKey,
  getLLMKeyFingerprint,
  saveLLMKey,
} from "../../lib/llm/llmAuth";

type StatusKind = "ok" | "warn" | "off";

function Badge({ kind, label }: { kind: StatusKind; label: string }) {
  return (
    <span className={`integration-row-badge ${kind}`}>
      <span className="dot" aria-hidden="true" />
      {label}
    </span>
  );
}

function IntegrationRow({
  title,
  description,
  kind,
  statusLabel,
  detail,
}: {
  title: string;
  description: string;
  kind: StatusKind;
  statusLabel: string;
  detail?: ReactNode;
}) {
  return (
    <div className="integration-row">
      <div className="integration-row-body">
        <p className="integration-row-title">{title}</p>
        <p className="integration-row-desc">{description}</p>
        {detail ? <p className="integration-row-detail">{detail}</p> : null}
      </div>
      <div className="integration-row-status">
        <Badge kind={kind} label={statusLabel} />
      </div>
    </div>
  );
}

function storageLabel(
  backend: string,
  t: (key: string, vars?: Record<string, string | number>) => string,
): { title: string; description: string } {
  switch (backend) {
    case "localfs":
      return {
        title: t("integrations.storageLocalfs"),
        description: t("integrations.storageLocalfsDesc"),
      };
    case "gdrive":
      return {
        title: t("integrations.storageGdrive"),
        description: t("integrations.storageGdriveDesc"),
      };
    case "gdrive-mock":
      return {
        title: t("integrations.storageGdriveMock"),
        description: t("integrations.storageGdriveMockDesc"),
      };
    case "ipfs":
      return {
        title: t("integrations.storageIpfs"),
        description: t("integrations.storageIpfsDesc"),
      };
    case "s3":
      return {
        title: t("integrations.storageS3"),
        description: t("integrations.storageS3Desc"),
      };
    default:
      return {
        title: t("integrations.storageUnknown", { backend }),
        description: t("integrations.storageUnknownDesc"),
      };
  }
}

export function IntegrationsPanel() {
  const { t } = useTranslation();
  const statusQuery = useStatusQuery();
  const agentsQuery = useAgentsQuery();

  if (statusQuery.isPending) {
    return (
      <div className="settings-container">
        <section className="settings-card">
          <p className="settings-card-desc">{t("integrations.loading")}</p>
        </section>
      </div>
    );
  }

  if (statusQuery.isError || !statusQuery.data) {
    return (
      <div className="settings-container">
        <section className="settings-card">
          <div className="settings-card-header">
            <div className="settings-card-heading">
              <h2 className="settings-card-title">{t("integrations.errorTitle")}</h2>
            </div>
          </div>
          <p className="settings-card-desc">{t("integrations.errorDesc")}</p>
        </section>
      </div>
    );
  }

  const status = statusQuery.data;
  const storage = storageLabel(status.storage_backend, t);
  const agentCount = agentsQuery.data?.agents.length ?? 0;

  return (
    <div className="settings-container">
      {/* API Server */}
      <section className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="3" width="20" height="14" rx="2" />
              <line x1="8" y1="21" x2="16" y2="21" />
              <line x1="12" y1="17" x2="12" y2="21" />
            </svg>
            <h2 className="settings-card-title">{t("integrations.apiServerTitle")}</h2>
          </div>
          <Badge kind="ok" label={`v${status.version}`} />
        </div>
        <ul className="settings-meta-list">
          <li className="settings-meta-row">
            <span className="settings-meta-label">Service</span>
            <span className="settings-meta-value"><code>{status.service}</code></span>
          </li>
          <li className="settings-meta-row">
            <span className="settings-meta-label">Version</span>
            <span className="settings-meta-value"><code>{status.version}</code></span>
          </li>
        </ul>
      </section>

      {/* Connections */}
      <section className="settings-card" data-testid="integrations-list">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
            </svg>
            <h2 className="settings-card-title">{t("integrations.connectionTitle")}</h2>
          </div>
        </div>

        <IntegrationRow
          title={t("integrations.worldIdTitle")}
          description={t("integrations.worldIdDesc")}
          kind={status.world_id_verify_enabled ? "ok" : "warn"}
          statusLabel={
            status.world_id_verify_enabled
              ? t("integrations.worldIdConfigured")
              : t("integrations.worldIdNotConfigured")
          }
          detail={
            status.world_id_verify_enabled
              ? t("integrations.worldIdDetailOk")
              : t("integrations.worldIdDetailMissing")
          }
        />

        <IntegrationRow
          title={storage.title}
          description={storage.description}
          kind="ok"
          statusLabel={t("integrations.byosEnabled")}
          detail={`backend = ${status.storage_backend}`}
        />

        <IntegrationRow
          title={t("integrations.pgTitle")}
          description={t("integrations.pgDesc")}
          kind={
            status.database_configured
              ? status.database_connected
                ? "ok"
                : "warn"
              : "off"
          }
          statusLabel={
            status.database_configured
              ? status.database_connected
                ? t("integrations.pgConnected")
                : t("integrations.pgConfigured")
              : t("integrations.pgNotConfigured")
          }
        />

        <IntegrationRow
          title={t("integrations.wsTitle")}
          description={t("integrations.wsDesc")}
          kind={status.websocket_enabled ? "ok" : "off"}
          statusLabel={
            status.websocket_enabled
              ? t("integrations.wsEnabled")
              : t("integrations.wsDisabled")
          }
        />
        {/*
          Auto-purge engine row was removed 2026-04-22 because the
          engine is not production-wired yet: `AGENT_INBOX_AUTO_PURGE_ENABLED`
          and `AGENT_INBOX_ADMIN_TOKEN` are unset in fly.toml, and
          there is no external cron driving `POST /admin/purge/run`
          (the design deliberately delegates cadence to the operator).
          Showing it as "無効" misled users into thinking it was a
          flip-on toggle. The engine, tests, and HTTP endpoint stay
          in `services/api` as-is — reinstate this row when the cron
          + env are configured. Backing i18n keys
          (`integrations.purge*`) are preserved for that day.
        */}
      </section>

      {/* Google Calendar — Phase 4.4d / docs/25d */}
      <GoogleCalendarCard />

      {/* AI Assistant — Phase 4.5 / docs/25f */}
      <AIAssistantCard />

      {/* Agents */}
      {/* placeholder preserved below */}
      <section className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
              <circle cx="9" cy="7" r="4" />
              <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
              <path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
            <h2 className="settings-card-title">{t("integrations.agentsTitle")}</h2>
          </div>
        </div>
        <p className="settings-card-desc" data-testid="integrations-agent-count">
          {agentsQuery.isPending
            ? t("integrations.agentsLoading")
            : t("integrations.agentsCount", { count: agentCount })}
        </p>
      </section>
    </div>
  );
}

// Phase 4.4d (docs/25d) — Google Calendar card. Self-contained so the
// lazy GIS SDK only loads when the user actually visits this page.
function GoogleCalendarCard() {
  const { t } = useTranslation();
  const [connected, setConnected] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setConnected(await isCalendarConnected());
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const clientId = calendarClientId();
  const sdkMissing = !clientId;

  const onConnect = async () => {
    setError(null);
    setBusy(true);
    try {
      await requestCalendarToken();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onDisconnect = async () => {
    setBusy(true);
    try {
      await disconnectCalendar();
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="settings-card" data-testid="integrations-gcal">
      <div className="settings-card-header">
        <div className="settings-card-heading">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
            <line x1="16" y1="2" x2="16" y2="6" />
            <line x1="8" y1="2" x2="8" y2="6" />
            <line x1="3" y1="10" x2="21" y2="10" />
          </svg>
          <h2 className="settings-card-title">{t("integrations.gcalTitle")}</h2>
        </div>
        <Badge
          kind={sdkMissing ? "off" : connected ? "ok" : "warn"}
          label={
            sdkMissing
              ? t("integrations.gcalNotConfigured")
              : connected
                ? t("integrations.gcalConnected")
                : t("integrations.gcalDisconnected")
          }
        />
      </div>
      <p className="settings-card-desc">{t("integrations.gcalDesc")}</p>
      {sdkMissing ? (
        <p className="settings-card-desc">{t("integrations.gcalClientIdMissing")}</p>
      ) : (
        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center" }}>
          {connected ? (
            <button
              type="button"
              className="btn"
              disabled={busy}
              onClick={onDisconnect}
              data-testid="integrations-gcal-disconnect"
            >
              {t("integrations.gcalDisconnect")}
            </button>
          ) : (
            <button
              type="button"
              className="btn primary"
              disabled={busy}
              onClick={onConnect}
              data-testid="integrations-gcal-connect"
            >
              {t("integrations.gcalConnect")}
            </button>
          )}
          {error ? (
            <span
              style={{ color: "#d93025", fontSize: 12 }}
              data-testid="integrations-gcal-error"
            >
              {error}
            </span>
          ) : null}
        </div>
      )}
    </section>
  );
}

// Phase 4.5 (docs/25f) — AI Assistant card. Browser stores the
// Anthropic API key in IndexedDB; the server never touches it.
function AIAssistantCard() {
  const { t } = useTranslation();
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [model, setModel] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draftKey, setDraftKey] = useState("");

  const refresh = useCallback(async () => {
    const fp = await getLLMKeyFingerprint();
    setFingerprint(fp);
    if (fp) {
      const entry = await getLLMKey();
      setModel(entry?.model ?? null);
    } else {
      setModel(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const onSave = async () => {
    setError(null);
    setBusy(true);
    try {
      await saveLLMKey({ apiKey: draftKey });
      setDraftKey("");
      setEditing(false);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const onDisconnect = async () => {
    setBusy(true);
    try {
      await disconnectLLM();
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const connected = !!fingerprint && !editing;

  return (
    <section className="settings-card" data-testid="integrations-llm">
      <div className="settings-card-header">
        <div className="settings-card-heading">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
          </svg>
          <h2 className="settings-card-title">{t("integrations.aiTitle")}</h2>
        </div>
        <Badge
          kind={connected ? "ok" : "warn"}
          label={
            connected
              ? t("integrations.aiConnected")
              : t("integrations.aiDisconnected")
          }
        />
      </div>
      <p className="settings-card-desc">{t("integrations.aiDesc")}</p>
      <p className="settings-card-desc" style={{ fontSize: 12, color: "#5f6368" }}>
        {t("integrations.aiPrivacyNote")}
      </p>

      {connected ? (
        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
          <span style={{ fontSize: 12, color: "#5f6368" }}>
            {t("integrations.aiKeyFingerprint", { fingerprint: fingerprint! })}
          </span>
          {model ? (
            <span style={{ fontSize: 12, color: "#5f6368" }}>
              {t("integrations.aiModel", { model })}
            </span>
          ) : null}
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={() => {
              setEditing(true);
              setDraftKey("");
            }}
            data-testid="integrations-llm-update"
          >
            {t("integrations.aiUpdateKey")}
          </button>
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={onDisconnect}
            data-testid="integrations-llm-disconnect"
          >
            {t("integrations.aiDisconnect")}
          </button>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 12 }}>
          <input
            type="password"
            placeholder={t("integrations.aiKeyPlaceholder")}
            value={draftKey}
            onChange={(e) => setDraftKey(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            data-testid="integrations-llm-key-input"
            style={{
              padding: "6px 10px",
              borderRadius: 4,
              border: "1px solid #dadce0",
              fontSize: 13,
              fontFamily: "ui-monospace, SFMono-Regular, monospace",
            }}
          />
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button
              type="button"
              className="btn primary"
              disabled={busy || draftKey.trim().length === 0}
              onClick={onSave}
              data-testid="integrations-llm-save"
            >
              {t("integrations.aiSaveKey")} (model: {DEFAULT_ANTHROPIC_MODEL})
            </button>
            {editing ? (
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => {
                  setEditing(false);
                  setDraftKey("");
                  setError(null);
                }}
              >
                {t("integrations.aiCancelEdit")}
              </button>
            ) : null}
            {error ? (
              <span style={{ color: "#d93025", fontSize: 12 }} data-testid="integrations-llm-error">
                {error}
              </span>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
