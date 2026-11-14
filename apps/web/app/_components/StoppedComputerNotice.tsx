"use client";

// 「パソコンが止まっています」on Messages (docs/39 §5.3): after a restart the
// computer stays off until someone starts it, and auto-replies and cloud
// AIs stop with it. The agent page already says so; this says it where the
// person looks every day. Dismissed per stop, in this browser only.

import Link from "next/link";
import { useEffect, useState } from "react";
import { elapsed } from "../../lib/agents/agent-status";
import { stoppedComputers } from "../../lib/agents/devices";
import type { Agent } from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";
import { deviceName } from "./AgentDevices";
import { NoticeCard, NoticeRow } from "./NoticeCard";

const dismissKey = (did: string) => `nexusinbox.stopped.dismissed.${did}`;
/** Stopped this long, a computer is likely no longer used: suggest removing it. */
const STALE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

export function StoppedComputerNotice({ agents }: { agents: Agent[] }) {
  const { t } = useTranslation();
  const [now, setNow] = useState(() => Date.now());
  const [dismissed, setDismissed] = useState<Record<string, string>>({});

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);

  const stopped = stoppedComputers(agents, now);
  const key = stopped.map((s) => s.device.did).join(",");
  // Read what this browser dismissed: a dismissal holds for that stop only.
  useEffect(() => {
    const next: Record<string, string> = {};
    for (const s of stopped) {
      try {
        const v = window.localStorage.getItem(dismissKey(s.device.did));
        if (v) next[s.device.did] = v;
      } catch {
        // Storage blocked: show the notice.
      }
    }
    setDismissed(next);
  }, [key]);

  const visible = stopped.filter((s) => dismissed[s.device.did] !== String(s.since));
  if (visible.length === 0) return null;

  const dismiss = (did: string, since: number) => {
    try {
      window.localStorage.setItem(dismissKey(did), String(since));
    } catch {
      // ignore
    }
    setDismissed((d) => ({ ...d, [did]: String(since) }));
  };

  // Most recently stopped first; long stopped ones are likely unused.
  const rows = [...visible].sort((a, b) => b.since - a.since);
  const agentLink = (agent: Agent) => `/settings/agents?agent=${encodeURIComponent(agent.did)}`;

  return (
    <div data-testid="stopped-computer-notice" className="notice-stack">
      <NoticeCard
        tone="info"
        title={
          rows.length === 1
            ? t("stoppedNotice.title", { agent: rows[0].agent.label })
            : t("stoppedNotice.groupTitle", { n: rows.length })
        }
        sub={t("stoppedNotice.groupSub")}
        onLater={() => rows.forEach((r) => dismiss(r.device.did, r.since))}
        laterLabel={t("notices.later")}
      >
        {rows.map(({ agent, device, since }) => {
          const { unit, value } = elapsed(since, now);
          const stale = now - since >= STALE_AFTER_MS;
          const why = [
            deviceName(t, device),
            t("stoppedNotice.since", { ago: t(`agentStatus.ago.${unit}`, { n: value }) }),
          ];
          if (stale) why.push(t("stoppedNotice.stale"));
          return (
            <NoticeRow
              key={device.did}
              name={agent.label}
              why={why}
              action={
                <Link href={agentLink(agent)} className="notice-link">
                  {stale ? t("stoppedNotice.actionRemove") : t("stoppedNotice.actionView")}
                </Link>
              }
            />
          );
        })}
      </NoticeCard>
    </div>
  );
}
