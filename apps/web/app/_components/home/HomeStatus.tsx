"use client";

// 「自動対応の状態」 on Home (docs/41 §8): for each agent, the setting and
// what is known of it running, kept apart. The one stop here is the
// auto-reply's; ending a cloud AI's access and the emergency stop stay on
// the agent page.

import Link from "next/link";
import { useState } from "react";
import { computerStatus, elapsed } from "../../../lib/agents/agent-status";
import { useAgentCredentialsQuery, useUpdateAgentMutation } from "../../../lib/api/hooks";
import type { Agent } from "../../../lib/api/types";
import { useTranslation } from "../../../lib/i18n";
import { useNow } from "../AgentStatusCard";
import { runsHere, useBrowserDevices } from "../InboxAgentBar";
import { autoReplyBrowser } from "../../../lib/agents/local-device";

const REFRESH_MS = 30_000;

export function agentPageLink(agent: Agent, deviceDid?: string): string {
  const base = `/settings/agents?agent=${encodeURIComponent(agent.did)}`;
  return deviceDid ? `${base}&device=${encodeURIComponent(deviceDid)}` : base;
}

export function HomeStatus({ agents }: { agents: Agent[] }) {
  const { t } = useTranslation();
  const credentialsQuery = useAgentCredentialsQuery({ refetchInterval: REFRESH_MS });
  const now = useNow(15_000);
  const inBrowser = useBrowserDevices(agents);

  return (
    <section className="home-section" aria-labelledby="home-status-title" data-testid="home-status">
      <div className="home-section-head">
        <h2 id="home-status-title" className="home-section-title">
          {t("home.status.title")}
        </h2>
      </div>
      <div className="home-box">
        {agents.map((agent) => {
          if (credentialsQuery.isError) {
            return (
              <StatusRow key={agent.id} agent={agent} tone="unknown" text={t("home.status.unknown")} sub={t("home.status.unknownSub")}>
                <button type="button" className="home-btn primary" onClick={() => void credentialsQuery.refetch()}>
                  {t("home.status.recheck")}
                </button>
              </StatusRow>
            );
          }
          if (!credentialsQuery.data) {
            return <StatusRow key={agent.id} agent={agent} tone="unknown" text={t("home.loading")} />;
          }
          const computer = computerStatus(credentialsQuery.data.credentials, agent.aid, now);
          const where =
            computer.kind === "browser" ? t("home.status.whereBrowser") : t("home.status.whereComputer", { name: computer.device });
          if (!agent.auto_reply) {
            return (
              <StatusRow key={agent.id} agent={agent} where={where} tone="off" text={t("home.status.off")}>
                <AutoReplySwitch agent={agent} />
              </StatusRow>
            );
          }
          if (computer.kind === "connected") {
            const ago = elapsed(computer.lastSeenAt, now);
            return (
              <StatusRow
                key={agent.id}
                agent={agent}
                where={where}
                tone="ok"
                text={t("home.status.connected", { ago: t(`agentStatus.ago.${ago.unit}`, { n: ago.value }) })}
                sub={t("home.status.autoReplyOn")}
              >
                <AutoReplySwitch agent={agent} />
              </StatusRow>
            );
          }
          if (computer.kind === "silent") {
            const ago = computer.lastSeenAt === null ? null : elapsed(computer.lastSeenAt, now);
            return (
              <StatusRow
                key={agent.id}
                agent={agent}
                where={where}
                tone="warn"
                text={
                  ago
                    ? t("home.status.silent", { ago: t(`agentStatus.ago.${ago.unit}`, { n: ago.value }) })
                    : t("home.status.silentNever")
                }
                sub={t("home.status.silentSub")}
                pageLabel={t("home.status.check")}
              >
                <AutoReplySwitch agent={agent} />
              </StatusRow>
            );
          }
          // Replies run in one browser of the person (docs/40 §17.6).
          const runner = autoReplyBrowser(agent);
          const text =
            inBrowser === null
              ? t("home.loading")
              : runsHere(inBrowser, agent)
                ? t("home.status.browser")
                : t("home.status.otherBrowser", { browser: runner?.label ?? t("inbox.firstBrowser") });
          return (
            <StatusRow
              key={agent.id}
              agent={agent}
              where={where}
              tone="ok"
              text={text}
              sub={t("home.status.autoReplyOn")}
            >
              <AutoReplySwitch agent={agent} />
            </StatusRow>
          );
        })}
      </div>
    </section>
  );
}

function StatusRow({
  agent,
  where,
  tone,
  text,
  sub,
  pageLabel,
  children,
}: {
  agent: Agent;
  /** The agent-page button's label: 「設定」 unless something is to be checked there. */
  pageLabel?: string;
  where?: string;
  tone: "ok" | "warn" | "off" | "unknown";
  text: string;
  sub?: string;
  children?: React.ReactNode;
}) {
  const { t } = useTranslation();
  return (
    <div className="home-status-row" data-testid="home-status-row">
      <div className="home-row-text">
        <div>
          <span className={`home-dot ${tone}`} aria-hidden />
          <span className="home-status-name">{agent.label}</span>
          {where ? <span className="home-muted"> · {where}</span> : null}
        </div>
        <div>{text}</div>
        {sub ? <div className="home-muted">{sub}</div> : null}
      </div>
      <div className="home-acts">
        <Link href={agentPageLink(agent)} className="home-btn">
          {pageLabel ?? t("home.status.settings")}
        </Link>
        {children}
      </div>
    </div>
  );
}

const stoppedHereKey = (agentId: string) => `nexusinbox.home.autoReplyStopped.${agentId}`;

function stoppedHere(agentId: string): boolean {
  try {
    return window.localStorage.getItem(stoppedHereKey(agentId)) !== null;
  } catch {
    return false;
  }
}

/**
 * 「自動返信を停止」 / 「自動返信を再開」: the master switch only, so the
 * conditions stay. Resuming is offered only for a stop made here: an agent
 * that was never set to answer is set up on the agent page.
 */
function AutoReplySwitch({ agent }: { agent: Agent }) {
  const { t } = useTranslation();
  const update = useUpdateAgentMutation();
  const [note, setNote] = useState<string | null>(null);
  const turnOn = !agent.auto_reply;
  if (turnOn && !stoppedHere(agent.id) && !note) return null;
  const toggle = async () => {
    setNote(null);
    try {
      await update.mutateAsync({ id: agent.id, body: { auto_reply: turnOn } });
      try {
        if (turnOn) window.localStorage.removeItem(stoppedHereKey(agent.id));
        else window.localStorage.setItem(stoppedHereKey(agent.id), "1");
      } catch {
        // ignore
      }
      setNote(turnOn ? t("home.status.resumed") : t("home.status.stopped"));
    } catch {
      setNote(t("home.status.switchFailed"));
    }
  };
  return (
    <>
      <button type="button" className="home-btn" onClick={() => void toggle()} disabled={update.isPending}>
        {turnOn ? t("home.status.resume") : t("home.status.stop")}
      </button>
      {note ? (
        <span role="status" className="home-note">
          {note}
        </span>
      ) : null}
    </>
  );
}
