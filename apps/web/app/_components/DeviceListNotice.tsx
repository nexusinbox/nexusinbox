"use client";

// The signed device list on Messages (docs/40 stage 1):
//   - an agent with no list yet: in the browser the agent was created in,
//     ask once to check and approve its devices (or, when the only device
//     is this browser, approve it quietly);
//   - a list that does not verify, is older than one seen here, or names a
//     device with a key other than the one the server now returns: warn,
//     with the emergency stop at hand.

import Link from "next/link";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  checkDeviceList,
  holdsRootKey,
  mismatchedDevices,
  onlyRootDevice,
  storeDeviceList,
} from "../../lib/agents/device-list";
import { queryKeys, useEmergencyShutdownMutation } from "../../lib/api/hooks";
import type { Agent, AgentDevice } from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";
import { deviceName } from "./AgentDevices";

const laterKey = (aid: string) => `nexusinbox.devicelist.later.${aid}`;

function askedBefore(aid: string): boolean {
  try {
    return window.localStorage.getItem(laterKey(aid)) !== null;
  } catch {
    return false;
  }
}

type Notice =
  | { kind: "ask"; agent: Agent }
  | { kind: "wrong"; agent: Agent; changed: AgentDevice[] };

export function DeviceListNotice({ agents }: { agents: Agent[] }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const shutdown = useEmergencyShutdownMutation();
  const [notices, setNotices] = useState<Notice[]>([]);
  const [stopped, setStopped] = useState<string | null>(null);
  const quietTried = useRef(new Set<string>());

  const key = agents
    .map((a) => `${a.aid}:${a.device_list?.jws ?? ""}:${(a.devices ?? []).map((d) => `${d.did}=${d.encryption_public_key ?? ""}`).join(",")}`)
    .join("|");
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const next: Notice[] = [];
      for (const agent of agents) {
        if ((agent.devices ?? []).length === 0) continue;
        const status = await checkDeviceList(agent);
        if (status.kind === "broken") {
          next.push({ kind: "wrong", agent, changed: [] });
          continue;
        }
        const changed = mismatchedDevices(agent, status);
        if (changed.length > 0) {
          next.push({ kind: "wrong", agent, changed });
          continue;
        }
        if (status.kind !== "none" || !(await holdsRootKey(agent))) continue;
        if (onlyRootDevice(agent)) {
          // Nothing to ask: this browser approves itself.
          if (!quietTried.current.has(agent.aid)) {
            quietTried.current.add(agent.aid);
            await storeDeviceList(agent, new Set([agent.did]))
              .then(() => queryClient.invalidateQueries({ queryKey: queryKeys.agents() }))
              .catch(() => undefined);
          }
          continue;
        }
        if (!askedBefore(agent.aid)) next.push({ kind: "ask", agent });
      }
      if (!cancelled) setNotices(next);
    })();
    return () => {
      cancelled = true;
    };
  }, [key]);

  const later = (aid: string) => {
    try {
      window.localStorage.setItem(laterKey(aid), "1");
    } catch {
      // ignore
    }
    setNotices((list) => list.filter((n) => !(n.kind === "ask" && n.agent.aid === aid)));
  };

  const stop = async (agent: Agent) => {
    if (!window.confirm(t("agents.confirmEmergency"))) return;
    try {
      await shutdown.mutateAsync(agent.id);
      setStopped(t("deviceNotice.stopped", { agent: agent.label }));
    } catch {
      setStopped(t("deviceNotice.stopFailed"));
    }
  };

  if (notices.length === 0 && !stopped) return null;
  const agentLink = (agent: Agent) => `/settings/agents?agent=${encodeURIComponent(agent.did)}`;

  return (
    <div data-testid="device-list-notice">
      {notices.map((n) =>
        n.kind === "wrong" ? (
          <div
            key={`wrong-${n.agent.aid}`}
            role="alert"
            data-testid="device-list-wrong"
            style={{
              margin: "10px 16px",
              padding: "12px 14px",
              borderRadius: 14,
              border: "1px solid var(--danger)",
              background: "var(--danger-soft)",
              color: "var(--text)",
            }}
          >
            <p style={{ margin: 0, fontWeight: 700 }}>{t("deviceList.wrongTitle", { agent: n.agent.label })}</p>
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {n.changed.length > 0
                ? t("deviceList.wrongMismatch", { device: n.changed.map((d) => deviceName(t, d)).join("、") })
                : t("deviceList.wrongBroken")}
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
              <Link href={agentLink(n.agent)} className="dm-btn">
                {t("deviceNotice.view")}
              </Link>
              <button
                type="button"
                className="dm-btn"
                style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                onClick={() => void stop(n.agent)}
                disabled={shutdown.isPending}
              >
                {t("deviceNotice.stop")}
              </button>
            </div>
          </div>
        ) : (
          <div
            key={`ask-${n.agent.aid}`}
            role="status"
            data-testid="device-list-ask"
            style={{
              margin: "10px 16px",
              padding: "10px 14px",
              borderRadius: 14,
              border: "1px solid var(--line)",
              background: "var(--primary-soft)",
            }}
          >
            <p style={{ margin: 0, fontWeight: 700 }}>{t("deviceList.noticeTitle", { agent: n.agent.label })}</p>
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("deviceList.noticeBody")}
            </p>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
              <Link href={agentLink(n.agent)} className="dm-btn accent" onClick={() => later(n.agent.aid)}>
                {t("deviceList.noticeView")}
              </Link>
              <button type="button" className="dm-btn" onClick={() => later(n.agent.aid)}>
                {t("deviceList.noticeLater")}
              </button>
            </div>
          </div>
        ),
      )}
      {stopped ? (
        <p role="status" className="item-sub" style={{ margin: "6px 16px" }}>
          {stopped}
        </p>
      ) : null}
    </div>
  );
}
