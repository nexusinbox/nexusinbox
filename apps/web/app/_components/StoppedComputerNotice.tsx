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

const dismissKey = (did: string) => `nexusinbox.stopped.dismissed.${did}`;

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

  return (
    <div data-testid="stopped-computer-notice">
      {visible.map(({ agent, device, since }) => {
        const { unit, value } = elapsed(since, now);
        return (
          <div
            key={device.did}
            role="status"
            style={{
              margin: "10px 16px",
              padding: "10px 14px",
              borderRadius: 14,
              border: "1px solid var(--line)",
              background: "var(--surface-alt)",
            }}
          >
            <p style={{ margin: 0, fontWeight: 700 }}>{t("stoppedNotice.title", { agent: agent.label })}</p>
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("stoppedNotice.body", {
                device: deviceName(t, device),
                ago: t(`agentStatus.ago.${unit}`, { n: value }),
              })}
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
              <Link href={`/settings/agents?agent=${encodeURIComponent(agent.did)}`} className="dm-btn accent">
                {t("stoppedNotice.view")}
              </Link>
              <button type="button" className="dm-btn" onClick={() => dismiss(device.did, since)}>
                {t("stoppedNotice.dismiss")}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
