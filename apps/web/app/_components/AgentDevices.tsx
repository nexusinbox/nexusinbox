"use client";

// 読める端末 (docs/38 stage 4): every device that can read this agent's new
// messages, so a device nobody here added stands out. A computer can be
// removed (its credential revoked, which also takes its key out of the
// recipient set).

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { elapsed, parseServerTime } from "../../lib/agents/agent-status";
import { deviceState, saveSeenDevices, type DeviceState } from "../../lib/agents/devices";
import { queryKeys, useRevokeAgentCredentialMutation } from "../../lib/api/hooks";
import type { Agent, AgentDevice } from "../../lib/api/types";
import { hasRecipientPrivateKey } from "../../lib/crypto/recipient-keyring";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";
import { STRONG } from "./AgentSetup";

export function deviceName(t: (key: string, vars?: Record<string, string | number>) => string, d: AgentDevice): string {
  if (d.kind === "browser") return t("agentStatus.deviceBrowser");
  if (d.kind === "computer") {
    return d.label ? t("agentStatus.deviceComputer", { name: d.label }) : t("agentStatus.deviceComputerUnnamed");
  }
  return t("agentStatus.deviceOther");
}

export function AgentDevices({ agent, now }: { agent: Agent; now: number }) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const revoke = useRevokeAgentCredentialMutation();
  const [failed, setFailed] = useState(false);
  const devices = agent.devices ?? [];

  // Which listed keys this browser holds ("この端末").
  const [heldHere, setHeldHere] = useState<Set<string>>(new Set());
  const didsKey = devices.map((d) => d.did).join(",");
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const held = new Set<string>();
      for (const d of devices) if (await hasRecipientPrivateKey(d.did)) held.add(d.did);
      if (!cancelled) setHeldHere(held);
    })();
    return () => {
      cancelled = true;
    };
  }, [didsKey]);

  // Looking at the list counts as having seen it: no "new device" notice
  // for what is shown here.
  useEffect(() => {
    if (devices.length > 0) saveSeenDevices(agent.aid, devices);
  }, [agent.aid, didsKey]);

  const date = (iso: string) => formatListTimestamp(iso, { locale, now: new Date(now) });
  const ago = (iso: string | null | undefined) => {
    const at = parseServerTime(iso);
    if (at === null) return null;
    const { unit, value } = elapsed(at, now);
    return t(`agentStatus.ago.${unit}`, { n: value });
  };

  const remove = async (d: AgentDevice) => {
    if (!d.credential_id) return;
    if (!window.confirm(t("agentStatus.deviceRemoveConfirm", { name: deviceName(t, d) }))) return;
    setFailed(false);
    try {
      await revoke.mutateAsync(d.credential_id);
      await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    } catch {
      setFailed(true);
    }
  };

  const badge = (state: DeviceState) => {
    const tone =
      state === "this"
        ? { color: "var(--primary-text)", background: "var(--primary-soft)", text: t("agentStatus.deviceThis") }
        : state === "connected"
          ? { color: "var(--ok)", background: "var(--ok-soft)", text: t("agentStatus.deviceRunning") }
          : state === "silent"
            ? { color: "var(--warn)", background: "var(--warn-soft)", text: t("agentStatus.deviceStopped") }
            : null;
    if (!tone) return null;
    return (
      <span
        style={{
          marginLeft: 6,
          fontSize: 11,
          fontWeight: 700,
          borderRadius: 6,
          padding: "1px 7px",
          color: tone.color,
          background: tone.background,
          verticalAlign: 1,
        }}
      >
        {tone.text}
      </span>
    );
  };

  return (
    <div data-testid="agent-devices">
      {devices.map((d) => {
        const state = deviceState(d, now, heldHere.has(d.did));
        const seen = d.kind === "computer" ? ago(d.last_used_at ?? d.activated_at) : null;
        return (
          <div
            key={d.did}
            data-testid="agent-device"
            style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "6px 0" }}
          >
            <span aria-hidden style={{ fontSize: 18, lineHeight: "22px" }}>
              {d.kind === "computer" ? "💻" : "🌐"}
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <span style={STRONG}>{deviceName(t, d)}</span>
              {badge(state)}
              <p className="item-sub" style={{ margin: "2px 0 0" }}>
                {d.kind === "browser"
                  ? t("agentStatus.deviceCreated", { date: date(d.activated_at) })
                  : [t("agentStatus.deviceJoined", { date: date(d.activated_at) }), seen ? t("agentStatus.deviceSeen", { ago: seen }) : null]
                      .filter(Boolean)
                      .join(" · ")}
              </p>
            </div>
            {d.credential_id ? (
              <button
                type="button"
                className="btn"
                onClick={() => void remove(d)}
                disabled={revoke.isPending}
                data-testid="agent-device-remove"
              >
                {t("agentStatus.deviceRemove")}
              </button>
            ) : null}
          </div>
        );
      })}
      <p className="item-sub" style={{ margin: "4px 0 0" }}>
        {t("agentStatus.devicesNote")}
      </p>
      {failed ? (
        <p className="item-sub" style={{ margin: "4px 0 0", color: "var(--danger)" }} role="status">
          {t("agentStatus.deviceRemoveFailed")}
        </p>
      ) : null}
    </div>
  );
}
