"use client";

// 「読める端末が増えました」(docs/38 stage 4, §6): a device joined one of
// the person's agents since this browser last looked. If nobody here
// connected it, the server (or someone holding it) may have added a key to
// read new messages, so the notice offers the emergency stop right away.
// What this browser has seen lives in this browser only.

import Link from "next/link";
import { useEffect, useState } from "react";
import type { QueryClient } from "@tanstack/react-query";
import { loadSeenDevices, saveSeenDevices, unseenDevices } from "../../lib/agents/devices";
import { defaultApiClient } from "../../lib/api/client";
import { queryKeys, useEmergencyShutdownMutation } from "../../lib/api/hooks";
import type { Agent, AgentDevice } from "../../lib/api/types";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";
import { deviceName } from "./AgentDevices";

/**
 * After the person connects a computer in this browser, record the agent's
 * device list as seen, so the computer they just added raises no notice.
 */
export async function acknowledgeDevicesAfterConnect(queryClient: QueryClient, aid: string): Promise<void> {
  try {
    await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    const data = await queryClient.fetchQuery({
      queryKey: queryKeys.agents(),
      queryFn: () => defaultApiClient.listAgents(),
    });
    const agent = data.agents.find((a) => a.aid === aid);
    if (agent?.devices) saveSeenDevices(aid, agent.devices);
  } catch {
    // The notice may show once; the person can dismiss it.
  }
}

type Pending = { agent: Agent; devices: AgentDevice[] };

export function NewDeviceNotice({ agents }: { agents: Agent[] }) {
  const { t, locale } = useTranslation();
  const shutdown = useEmergencyShutdownMutation();
  const [pending, setPending] = useState<Pending[]>([]);
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);

  const key = agents.map((a) => `${a.aid}:${(a.devices ?? []).map((d) => d.did).join(",")}`).join("|");
  useEffect(() => {
    const next: Pending[] = [];
    for (const agent of agents) {
      const devices = agent.devices ?? [];
      if (devices.length === 0) continue;
      const seen = loadSeenDevices(agent.aid);
      // First look at this agent from this browser: just remember it.
      if (seen === null) {
        saveSeenDevices(agent.aid, devices);
        continue;
      }
      const added = unseenDevices(devices, seen);
      if (added.length > 0) next.push({ agent, devices: added });
    }
    setPending(next);
  }, [key]);

  const acknowledge = (agent: Agent) => {
    saveSeenDevices(agent.aid, agent.devices ?? []);
    setPending((list) => list.filter((p) => p.agent.aid !== agent.aid));
  };

  const stop = async (agent: Agent) => {
    if (!window.confirm(t("agents.confirmEmergency"))) return;
    setNote(null);
    try {
      await shutdown.mutateAsync(agent.id);
      acknowledge(agent);
      setNote({ tone: "ok", text: t("deviceNotice.stopped", { agent: agent.label }) });
    } catch {
      setNote({ tone: "error", text: t("deviceNotice.stopFailed") });
    }
  };

  if (pending.length === 0 && !note) return null;

  return (
    <div data-testid="new-device-notice">
      {pending.map(({ agent, devices }) => (
        <div
          key={agent.aid}
          role="alert"
          style={{
            margin: "10px 16px",
            padding: "12px 14px",
            borderRadius: 14,
            border: "1px solid var(--warn)",
            background: "var(--warn-soft)",
            color: "var(--text)",
          }}
        >
          <p style={{ margin: 0, fontWeight: 700 }}>{t("deviceNotice.title", { agent: agent.label })}</p>
          {devices.map((d) => (
            <p key={d.did} className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("deviceNotice.body", {
                device: deviceName(t, d),
                date: formatListTimestamp(d.activated_at, { locale }),
              })}
            </p>
          ))}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
            <button type="button" className="dm-btn accent" onClick={() => acknowledge(agent)} data-testid="new-device-mine">
              {t("deviceNotice.mine")}
            </button>
            <Link href={`/settings/agents?agent=${encodeURIComponent(agent.did)}`} className="dm-btn">
              {t("deviceNotice.view")}
            </Link>
            <button
              type="button"
              className="dm-btn"
              style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
              onClick={() => void stop(agent)}
              disabled={shutdown.isPending}
              data-testid="new-device-stop"
            >
              {t("deviceNotice.stop")}
            </button>
          </div>
        </div>
      ))}
      {note ? (
        <p
          role="status"
          className="item-sub"
          style={{ margin: "6px 16px", color: note.tone === "error" ? "var(--danger)" : "var(--ok)" }}
        >
          {note.text}
        </p>
      ) : null}
    </div>
  );
}
