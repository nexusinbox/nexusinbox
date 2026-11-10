"use client";

// The agent's status at a glance (docs/31 §4 step 3): where it runs and
// whether that computer is answering, which auto-reply preset is on, and
// its latest automatic replies. No DIDs, credentials or key holders here;
// the rest of the settings page has those.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  cloudAccessStatus,
  computerStatus,
  elapsed,
  presetFromSettings,
  recentAutoReplies,
} from "../../lib/agents/agent-status";
import type { AutoReplyPreset } from "../../lib/agents/auto-reply-presets";
import { agentDirName, daemonStartCommand } from "../../lib/agents/enroll-command";
import { indexContactsByDid, resolveParticipantLabel } from "../../lib/api/labels";
import {
  queryKeys,
  useAgentCredentialsQuery,
  useAgentsQuery,
  useAuditLogQuery,
  useAutoReplyPolicyQuery,
  useContactsQuery,
  useOAuthGrantsQuery,
  useSetCloudAccessMutation,
} from "../../lib/api/hooks";
import type { CloudAccessStatus } from "../../lib/agents/agent-status";
import type { Agent, AgentCredential } from "../../lib/api/types";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";
import {
  AutoReplyPresetChoices,
  CommandLine,
  ConnectComputer,
  ErrorLine,
  PRESET_TEXT,
  STRONG,
  useApplyAutoReplyPreset,
} from "./AgentSetup";

// A computer's gateway checks in every 30 s; refresh as often.
const REFRESH_MS = 30_000;
// While the computer gets ready for cloud AIs it reports every 5 s.
const PREPARING_REFRESH_MS = 5_000;

const DOT_COLORS = { ok: "var(--ok)", warn: "var(--warn)", off: "var(--text-muted)" } as const;

function Dot({ tone }: { tone: keyof typeof DOT_COLORS }) {
  return (
    <span
      aria-hidden
      style={{
        display: "inline-block",
        width: 9,
        height: 9,
        borderRadius: "50%",
        background: DOT_COLORS[tone],
        marginRight: 6,
        verticalAlign: 1,
      }}
    />
  );
}

// Label beside the value, or above it when the card is too narrow for both.
function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: "2px 12px",
        padding: "10px 0",
        borderTop: "1px solid var(--line)",
      }}
    >
      <div className="item-sub" style={{ flex: "0 0 7.5em", paddingTop: 1 }}>
        {label}
      </div>
      <div style={{ flex: "1 1 16em", minWidth: 0 }}>{children}</div>
    </div>
  );
}

export function AgentStatusCard({ agent }: { agent: Agent }) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const [fastRefresh, setFastRefresh] = useState(false);
  const credentialsQuery = useAgentCredentialsQuery({
    refetchInterval: fastRefresh ? PREPARING_REFRESH_MS : REFRESH_MS,
  });
  const policyQuery = useAutoReplyPolicyQuery(agent.id);
  const auditQuery = useAuditLogQuery(
    { event: "auto_reply_sent", aid: agent.aid, limit: 20 },
    { refetchInterval: REFRESH_MS },
  );
  const agentsQuery = useAgentsQuery();
  const contactsQuery = useContactsQuery();
  const applyPreset = useApplyAutoReplyPreset();

  const now = useNow(15_000);

  const [connectStage, setConnectStage] = useState<"idle" | "confirm" | "pairing">("idle");
  const [editing, setEditing] = useState(false);
  const [choice, setChoice] = useState<AutoReplyPreset | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveFailed, setSaveFailed] = useState(false);

  // Start over when another agent is shown.
  useEffect(() => {
    setConnectStage("idle");
    setEditing(false);
    setSaveFailed(false);
  }, [agent.id]);

  const computer = computerStatus(credentialsQuery.data?.credentials ?? [], agent.aid, now);
  const cloud = cloudAccessStatus(credentialsQuery.data?.credentials ?? [], agent.aid, now);
  useEffect(() => setFastRefresh(cloud.kind === "preparing"), [cloud.kind]);
  const preset = policyQuery.isSuccess
    ? presetFromSettings(agent.auto_reply, policyQuery.data.policy)
    : null;
  const replies = recentAutoReplies(auditQuery.data?.events ?? []);

  const labelFor = useMemo(() => {
    const contacts = indexContactsByDid(contactsQuery.data?.contacts);
    const ownAgents = new Map((agentsQuery.data?.agents ?? []).map((a) => [a.did, a.label]));
    return (did: string) => resolveParticipantLabel(did, ownAgents.get(did) ?? null, contacts);
  }, [contactsQuery.data, agentsQuery.data]);

  const ago = (at: number) => {
    const { unit, value } = elapsed(at, now);
    return t(`agentStatus.ago.${unit}`, { n: value });
  };

  const save = async () => {
    if (!choice) return;
    setSaving(true);
    setSaveFailed(false);
    try {
      await applyPreset(agent.id, choice);
      setEditing(false);
    } catch {
      setSaveFailed(true);
    } finally {
      setSaving(false);
    }
  };

  return (
    <section
      className="panel"
      data-testid="agent-status"
      style={{ border: "1.5px solid var(--primary)", marginBottom: 12 }}
    >
      <h3 style={{ margin: "0 0 4px", fontSize: 15 }}>{t("agentStatus.title")}</h3>

      <Row label={t("agentStatus.where")}>
        {computer.kind === "connected" ? (
          <div data-testid="agent-status-connected">
            <Dot tone="ok" />
            <span style={STRONG}>{t("agentStatus.computer", { device: computer.device })}</span>{" "}
            {t("agentStatus.connected")}
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("agentStatus.connectedSub", { ago: ago(computer.lastSeenAt) })}
            </p>
          </div>
        ) : computer.kind === "silent" ? (
          <div data-testid="agent-status-silent">
            <Dot tone="warn" />
            <span style={STRONG}>{t("agentStatus.computer", { device: computer.device })}</span>{" "}
            {computer.lastSeenAt === null
              ? t("agentStatus.silentNever")
              : t("agentStatus.silentSince", { ago: ago(computer.lastSeenAt) })}
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("agentStatus.silentSub")}
            </p>
            <div
              style={{
                marginTop: 8,
                padding: "10px 12px",
                borderRadius: 10,
                background: "var(--warn-soft)",
                color: "var(--warn)",
                fontSize: 13,
              }}
            >
              {t("agentStatus.startHint")}
              <CommandLine command={daemonStartCommand(agentDirName(agent.label, agent.aid))} />
              <p style={{ margin: "6px 0 0" }}>{t("agentStatus.startDirNote")}</p>
            </div>
          </div>
        ) : (
          <div data-testid="agent-status-browser">
            <Dot tone="off" />
            <span style={STRONG}>{t("agentStatus.browser")}</span>
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("agentStatus.browserSub")}
            </p>
            {connectStage === "idle" ? (
              <button
                className="btn"
                type="button"
                style={{ marginTop: 8 }}
                onClick={() => setConnectStage("confirm")}
                data-testid="agent-status-connect"
              >
                {t("agentStatus.connectButton")}
              </button>
            ) : connectStage === "confirm" ? (
              <div style={{ marginTop: 8 }}>
                <p className="item-sub" style={{ margin: 0 }}>
                  {t("agentStatus.connectConfirm")}
                </p>
                <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
                  <button
                    className="btn primary"
                    type="button"
                    onClick={() => setConnectStage("pairing")}
                    data-testid="agent-status-connect-yes"
                  >
                    {t("agentStatus.connectYes")}
                  </button>
                  <button className="btn" type="button" onClick={() => setConnectStage("idle")}>
                    {t("agentStatus.cancel")}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ marginTop: 8 }}>
                <p className="item-sub" style={{ margin: 0 }}>
                  {t("firstRun.connect.desc")}
                </p>
                <ConnectComputer
                  agentId={agent.id}
                  onConnected={() => {
                    setConnectStage("idle");
                    void queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
                  }}
                />
                <button
                  className="btn"
                  type="button"
                  style={{ marginTop: 8 }}
                  onClick={() => setConnectStage("idle")}
                >
                  {t("agentStatus.cancel")}
                </button>
              </div>
            )}
          </div>
        )}
      </Row>

      <Row label={t("agentStatus.autoReply")}>
        {preset === null ? (
          <span className="item-sub">{t("common.loading")}</span>
        ) : (
          <div data-testid={`agent-status-preset-${preset}`}>
            <span style={STRONG}>
              {preset === "custom" ? t("agentStatus.customTitle") : t(PRESET_TEXT[preset].title)}
            </span>
            {!editing ? (
              <button
                type="button"
                onClick={() => {
                  setChoice(preset === "custom" ? null : preset);
                  setSaveFailed(false);
                  setEditing(true);
                }}
                style={{
                  marginLeft: 8,
                  border: 0,
                  background: "none",
                  color: "var(--primary)",
                  cursor: "pointer",
                  fontSize: 13,
                  padding: 0,
                }}
                data-testid="agent-status-change"
              >
                {t("agentStatus.change")}
              </button>
            ) : null}
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {preset === "custom" ? t("agentStatus.customDesc") : t(PRESET_TEXT[preset].desc)}
            </p>
            {editing ? (
              <div>
                <AutoReplyPresetChoices value={choice} onChange={setChoice} />
                {preset === "custom" ? (
                  <p className="item-sub" style={{ marginTop: 8 }}>
                    {t("agentStatus.customReplaceNote")}
                  </p>
                ) : null}
                {saveFailed ? <ErrorLine>{t("firstRun.replies.saveFailed")}</ErrorLine> : null}
                <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                  <button
                    className="btn primary"
                    type="button"
                    disabled={!choice || saving}
                    onClick={() => void save()}
                    data-testid="agent-status-save"
                  >
                    {saving ? t("firstRun.replies.saving") : t("agentStatus.save")}
                  </button>
                  <button
                    className="btn"
                    type="button"
                    disabled={saving}
                    onClick={() => setEditing(false)}
                  >
                    {t("agentStatus.cancel")}
                  </button>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Row>

      <Row label={t("cloudAccess.label")}>
        <CloudAccess status={cloud} agentId={agent.id} />
      </Row>

      <Row label={t("agentStatus.recent")}>
        {replies.length === 0 ? (
          <span className="item-sub" data-testid="agent-status-recent-empty">
            {t("agentStatus.recentEmpty")}
          </span>
        ) : (
          <ul
            style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 6 }}
            data-testid="agent-status-recent"
          >
            {replies.map((reply) => (
              <li key={reply.messageId} style={{ fontSize: 14 }}>
                {reply.at !== null ? (
                  <time
                    className="item-sub"
                    style={{ marginRight: 8, fontVariantNumeric: "tabular-nums" }}
                  >
                    {formatListTimestamp(new Date(reply.at).toISOString(), { locale })}
                  </time>
                ) : null}
                {t(`agentStatus.recent_${reply.action}`, { sender: labelFor(reply.senderDid) })}
              </li>
            ))}
          </ul>
        )}
      </Row>
    </section>
  );
}

const LIST: React.CSSProperties = { margin: "8px 0 0", paddingLeft: 20, fontSize: 14 };

/** The cloud-AI row (docs/33 §12): off, on, and the URL to give an AI app. */
function CloudAccess({ status, agentId }: { status: CloudAccessStatus; agentId: string }) {
  const { t } = useTranslation();
  const setCloudAccess = useSetCloudAccessMutation();
  const grantsQuery = useOAuthGrantsQuery();
  const [stage, setStage] = useState<"idle" | "confirmOn" | "confirmOff">("idle");
  const [message, setMessage] = useState("");
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    setStage("idle");
    setMessage("");
    setFailed(false);
  }, [agentId]);

  const apply = async (credentialId: string, enabled: boolean) => {
    setFailed(false);
    setMessage("");
    try {
      const out = await setCloudAccess.mutateAsync({ credentialId, enabled });
      setStage("idle");
      if (!enabled) setMessage(t("cloudAccess.turnedOff", { n: out.disconnected }));
    } catch {
      setFailed(true);
    }
  };
  const busy = setCloudAccess.isPending;
  const sub = (text: string) => (
    <p className="item-sub" style={{ margin: "2px 0 0" }}>
      {text}
    </p>
  );
  const done = message ? sub(message) : null;
  const error = failed ? <ErrorLine>{t("cloudAccess.failed")}</ErrorLine> : null;

  if (status.kind === "unavailable") {
    return (
      <div data-testid="cloud-access-unavailable">
        <Dot tone="off" />
        <span style={STRONG}>{t("cloudAccess.unavailable")}</span>
        {sub(t("cloudAccess.unavailableSub"))}
      </div>
    );
  }

  if (status.kind === "off") {
    return (
      <div data-testid="cloud-access-off">
        <span style={STRONG}>{t("cloudAccess.off")}</span>
        {done}
        {stage !== "confirmOn" ? (
          <>
            {sub(t("cloudAccess.offSub"))}
            <button
              className="btn"
              type="button"
              style={{ marginTop: 8 }}
              onClick={() => setStage("confirmOn")}
              data-testid="cloud-access-turn-on"
            >
              {t("cloudAccess.turnOn")}
            </button>
          </>
        ) : (
          <div
            style={{
              marginTop: 8,
              padding: "12px 14px",
              border: "1px solid var(--line)",
              borderRadius: 10,
              background: "var(--surface-alt)",
            }}
          >
            <p style={{ ...STRONG, margin: 0 }}>{t("cloudAccess.confirmTitle")}</p>
            <ul style={LIST}>
              <li>{t("cloudAccess.confirmDraft")}</li>
              <li>{t("cloudAccess.confirmProvider")}</li>
              <li>{t("cloudAccess.confirmGrant")}</li>
              <li>{t("cloudAccess.confirmComputer")}</li>
            </ul>
            {error}
            <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
              <button
                className="btn primary"
                type="button"
                disabled={busy}
                onClick={() => void apply(status.credentialId, true)}
                data-testid="cloud-access-turn-on-yes"
              >
                {t("cloudAccess.turnOn")}
              </button>
              <button className="btn" type="button" disabled={busy} onClick={() => setStage("idle")}>
                {t("agentStatus.cancel")}
              </button>
            </div>
          </div>
        )}
      </div>
    );
  }

  const turnOff =
    stage !== "confirmOff" ? (
      <button
        type="button"
        onClick={() => setStage("confirmOff")}
        style={{
          marginTop: 8,
          border: 0,
          background: "none",
          color: "var(--primary)",
          cursor: "pointer",
          fontSize: 13,
          padding: 0,
          display: "block",
        }}
        data-testid="cloud-access-turn-off"
      >
        {t("cloudAccess.turnOff")}
      </button>
    ) : (
      <div style={{ marginTop: 8 }}>
        {sub(t("cloudAccess.turnOffConfirm"))}
        {error}
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <button
            className="btn primary"
            type="button"
            disabled={busy}
            onClick={() => void apply(status.credentialId, false)}
            data-testid="cloud-access-turn-off-yes"
          >
            {t("cloudAccess.turnOff")}
          </button>
          <button className="btn" type="button" disabled={busy} onClick={() => setStage("idle")}>
            {t("cloudAccess.keep")}
          </button>
        </div>
      </div>
    );

  if (status.kind === "preparing") {
    return (
      <div data-testid="cloud-access-preparing">
        <Dot tone="warn" />
        <span style={STRONG}>{t("cloudAccess.preparing")}</span>
        {sub(t("cloudAccess.preparingSub"))}
        {sub(t("cloudAccess.preparingSlow"))}
        {turnOff}
      </div>
    );
  }

  if (status.kind === "stopped") {
    return (
      <div data-testid="cloud-access-stopped">
        <Dot tone="warn" />
        <span style={STRONG}>{t("cloudAccess.stopped")}</span>
        {sub(t("cloudAccess.stoppedSub"))}
        {turnOff}
      </div>
    );
  }

  const connected = (grantsQuery.data?.grants ?? []).filter((g) => g.resource === status.url).length;
  return (
    <div data-testid="cloud-access-ready">
      <Dot tone="ok" />
      <span style={STRONG}>{t("cloudAccess.ready")}</span>{" "}
      <span className="item-sub">{t("cloudAccess.connectedCount", { n: connected })}</span>
      <CommandLine command={status.url} testId="cloud-access-url" />
      <ol style={LIST}>
        <li>{t("cloudAccess.step1")}</li>
        <li>{t("cloudAccess.step2")}</li>
        <li>{t("cloudAccess.step3")}</li>
      </ol>
      {sub(t("cloudAccess.urlNote"))}
      {turnOff}
    </div>
  );
}

/** The current time, refreshed every `intervalMs`. */
export function useNow(intervalMs: number): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs]);
  return now;
}

/** One line per agent in the settings list. */
export function AgentStatusLine({
  aid,
  credentials,
  now,
}: {
  aid: string;
  credentials: AgentCredential[];
  now: number;
}) {
  const { t } = useTranslation();
  const status = computerStatus(credentials, aid, now);
  const [tone, key] =
    status.kind === "connected"
      ? (["ok", "agentStatus.listConnected"] as const)
      : status.kind === "silent"
        ? (["warn", "agentStatus.listSilent"] as const)
        : (["off", "agentStatus.listBrowser"] as const);
  return (
    <span className="card-sub" style={{ display: "block" }} data-testid="agent-status-line">
      <Dot tone={tone} />
      {t(key)}
    </span>
  );
}
