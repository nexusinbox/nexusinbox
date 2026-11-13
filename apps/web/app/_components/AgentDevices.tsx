"use client";

// 読める端末 (docs/38 stage 4): every device that can read this agent's new
// messages, so a device nobody here added stands out. A computer can be
// removed (its credential revoked, which also takes its key out of the
// recipient set).
//
// Approving (docs/40 stage 1): the browser the agent was created in signs
// the list of devices it approves. Devices it has not approved, or whose
// key differs from the approved one, are marked; only that browser can
// approve.

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { elapsed, parseServerTime } from "../../lib/agents/agent-status";
import {
  approvalOf,
  approvedWith,
  checkDeviceList,
  holdsRootKey,
  storeDeviceList,
  type Approval,
  type ListStatus,
} from "../../lib/agents/device-list";
import { deviceState, saveSeenDevices, type DeviceState } from "../../lib/agents/devices";
import { pairingMismatch } from "../../lib/agents/pairing";
import { defaultApiClient } from "../../lib/api/client";
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

/** The list's status and whether this browser can approve (holds the root key). */
export function useDeviceList(agent: Agent): { status: ListStatus | null; rootHere: boolean } {
  const [status, setStatus] = useState<ListStatus | null>(null);
  const [rootHere, setRootHere] = useState(false);
  const key = `${agent.aid}|${agent.device_list?.jws ?? ""}|${(agent.devices ?? [])
    .map((d) => `${d.did}:${d.encryption_public_key ?? ""}`)
    .join(",")}`;
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const [next, root] = await Promise.all([checkDeviceList(agent), holdsRootKey(agent)]);
      if (!cancelled) {
        setStatus(next);
        setRootHere(root);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [key]);
  return { status, rootHere };
}

/**
 * A computer connected before the connect code carried a secret (docs/40
 * §13.5): its keys were never checked against the code, and it learnt the
 * agent's root from the server. It is asked to reconnect (§15.2).
 */
export function connectedTheOldWay(d: AgentDevice): boolean {
  return d.kind === "computer" && !!d.credential_id && !d.pairing_mac;
}

export function AgentDevices({
  agent,
  now,
  onReconnect,
}: {
  agent: Agent;
  now: number;
  /** After removing a computer connected the old way: show a new connect code. */
  onReconnect?: () => void;
}) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const revoke = useRevokeAgentCredentialMutation();
  const [failed, setFailed] = useState<"remove" | "approve" | null>(null);
  const [busy, setBusy] = useState(false);
  const devices = agent.devices ?? [];
  const { status, rootHere } = useDeviceList(agent);

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

  const refreshed = async (): Promise<Agent | undefined> => {
    await queryClient.invalidateQueries({ queryKey: queryKeys.agents() });
    const data = await queryClient.fetchQuery({
      queryKey: queryKeys.agents(),
      queryFn: () => defaultApiClient.listAgents(),
    });
    return data.agents.find((a) => a.aid === agent.aid);
  };

  const approve = async (dids: string[]) => {
    if (!status) return;
    setFailed(null);
    setBusy(true);
    try {
      await storeDeviceList(agent, approvedWith(agent, status, dids));
      await refreshed();
    } catch {
      setFailed("approve");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (d: AgentDevice, then?: () => void) => {
    if (!d.credential_id) return;
    if (!window.confirm(t("agentStatus.deviceRemoveConfirm", { name: deviceName(t, d) }))) return;
    setFailed(null);
    try {
      await revoke.mutateAsync(d.credential_id);
      const fresh = await refreshed();
      // Sign the list again without it, keeping only what was approved.
      if (fresh && rootHere && status?.kind === "ok") {
        const keep = approvedWith(agent, status, []);
        keep.delete(d.did);
        await storeDeviceList(fresh, keep).catch(() => undefined);
        await refreshed();
      }
      then?.();
    } catch {
      setFailed("remove");
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
    return tone ? <Pill {...tone} /> : null;
  };

  const approvalBadge = (approval: Approval) => {
    if (approval === "pending") {
      return <Pill color="var(--warn)" background="var(--warn-soft)" text={t("deviceList.pending")} />;
    }
    if (approval === "mismatch") {
      return <Pill color="var(--danger)" background="var(--danger-soft)" text={t("deviceList.mismatch")} />;
    }
    return null;
  };

  const listed = status?.kind === "ok";
  // A computer whose keys are not the ones its connect code was typed on
  // is never offered for approval (docs/40 §13.5): remove it instead.
  const approvable = devices.filter((d) => !pairingMismatch(d));
  const allApproved = listed && devices.every((d) => approvalOf(d, status) === "approved");

  return (
    <div data-testid="agent-devices">
      {status?.kind === "broken" ? (
        <p className="item-sub" role="alert" style={{ margin: "0 0 8px", color: "var(--danger)" }}>
          {t("deviceList.broken")}
        </p>
      ) : null}
      {(status?.kind === "none" && devices.length > 1) || status?.kind === "broken" ? (
        <div
          data-testid="device-list-approve"
          style={{ borderRadius: 12, background: "var(--primary-soft)", padding: "10px 12px", marginBottom: 8 }}
        >
          {rootHere ? (
            <>
              <p style={{ margin: 0, fontWeight: 700 }}>{t("deviceList.approveTitle")}</p>
              <p className="item-sub" style={{ margin: "2px 0 0" }}>
                {t("deviceList.approveBody")}
              </p>
              <button
                type="button"
                className="btn primary"
                style={{ marginTop: 8 }}
                disabled={busy}
                onClick={() => void approve(approvable.map((d) => d.did))}
                data-testid="device-list-approve-all"
              >
                {t("deviceList.approveAll", { n: approvable.length })}
              </button>
            </>
          ) : (
            <p className="item-sub" style={{ margin: 0 }}>
              {t("deviceList.otherBrowser")}
            </p>
          )}
        </div>
      ) : null}
      {devices.map((d) => {
        const state = deviceState(d, now, heldHere.has(d.did));
        const approval = listed ? approvalOf(d, status) : null;
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
              {pairingMismatch(d) ? (
                <Pill color="var(--danger)" background="var(--danger-soft)" text={t("pairing.mismatchBadge")} />
              ) : approval ? (
                approvalBadge(approval)
              ) : null}
              {connectedTheOldWay(d) ? (
                <Pill color="var(--warn)" background="var(--warn-soft)" text={t("pairing.oldWayBadge")} />
              ) : null}
              <p className="item-sub" style={{ margin: "2px 0 0" }}>
                {[
                  d.kind === "browser"
                    ? t("agentStatus.deviceCreated", { date: date(d.activated_at) })
                    : t("agentStatus.deviceJoined", { date: date(d.activated_at) }),
                  seen ? t("agentStatus.deviceSeen", { ago: seen }) : null,
                  approval === "pending" && !rootHere ? t("deviceList.pendingOther") : null,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
              {connectedTheOldWay(d) ? (
                <div data-testid="agent-device-old-way" style={{ marginTop: 6 }}>
                  <p
                    className="item-sub"
                    style={{
                      margin: 0,
                      padding: "8px 10px",
                      borderRadius: 10,
                      background: "var(--warn-soft)",
                      color: "var(--text)",
                    }}
                  >
                    {t("pairing.oldWayBody")}
                  </p>
                  <button
                    type="button"
                    className="btn"
                    style={{ marginTop: 6, color: "var(--danger)", borderColor: "var(--danger)" }}
                    onClick={() => void remove(d, onReconnect)}
                    disabled={revoke.isPending}
                    data-testid="agent-device-reconnect"
                  >
                    {t("pairing.oldWayReconnect")}
                  </button>
                </div>
              ) : null}
            </div>
            {approval === "pending" && rootHere && !pairingMismatch(d) ? (
              <button
                type="button"
                className="btn primary"
                onClick={() => void approve([d.did])}
                disabled={busy}
                data-testid="agent-device-approve"
              >
                {t("deviceList.approve")}
              </button>
            ) : null}
            {d.credential_id && !connectedTheOldWay(d) ? (
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
        {allApproved ? ` ${t("deviceList.approved")}` : ""}
      </p>
      {failed ? (
        <p className="item-sub" style={{ margin: "4px 0 0", color: "var(--danger)" }} role="status">
          {failed === "remove" ? t("agentStatus.deviceRemoveFailed") : t("deviceList.failed")}
        </p>
      ) : null}
    </div>
  );
}

function Pill({ color, background, text }: { color: string; background: string; text: string }) {
  return (
    <span
      style={{
        marginLeft: 6,
        fontSize: 11,
        fontWeight: 700,
        borderRadius: 6,
        padding: "1px 7px",
        color,
        background,
        verticalAlign: 1,
      }}
    >
      {text}
    </span>
  );
}
