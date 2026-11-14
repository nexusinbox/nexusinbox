"use client";

// 読める端末 (docs/38 stage 4): every device that can read this agent's new
// messages, so a device nobody here added stands out. A computer can be
// removed (its credential revoked, which also takes its key out of the
// recipient set).
//
// Approving (docs/40 stage 1): the browser the agent was created in signs
// the list of devices it approves. Devices it has not approved, or whose
// key differs from the approved one, are marked; only a browser that can
// sign approves. Since §17 other browsers of the person can be added; every
// browser may sign, and any of them removes another (World ID again).

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { elapsed, parseServerTime } from "../../lib/agents/agent-status";
import {
  approvalOf,
  approvedWith,
  checkDeviceList,
  listSignerDids,
  listSignerHere,
  onlyRootDevice,
  storeDeviceList,
  type Approval,
  type ListStatus,
} from "../../lib/agents/device-list";
import { deviceState, saveSeenDevices, type DeviceState } from "../../lib/agents/devices";
import { agentDirName, daemonStartCommand } from "../../lib/agents/enroll-command";
import { pairingMismatch } from "../../lib/agents/pairing";
import { autoReplyBrowser, localDeviceDid } from "../../lib/agents/local-device";
import { ApiError, defaultApiClient } from "../../lib/api/client";
import { queryKeys, useRevokeAgentCredentialMutation } from "../../lib/api/hooks";
import type { Agent, AgentDevice } from "../../lib/api/types";
import { hasRecipientPrivateKey } from "../../lib/crypto/recipient-keyring";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";
import { AddBrowserPanel } from "./AddBrowserPanel";
import { CommandLine, STRONG } from "./AgentSetup";

/** Where a message can be read instead: 「Safari (iPhone)」 (かパソコン). */
export function elsewhereText(
  t: (key: string, vars?: Record<string, string | number>) => string,
  elsewhere: { browsers: AgentDevice[]; computer: boolean },
  orComputerKey = "inbox.devicesOrComputer",
): string {
  // A browser without a name of its own is the one the agent was made in.
  const names = elsewhere.browsers
    .map((d) => (d.label ? t("inbox.deviceQuoted", { name: d.label }) : t("inbox.firstBrowser")))
    .join(t("inbox.deviceJoin"));
  return elsewhere.computer ? t(orComputerKey, { names }) : names;
}

export function deviceName(t: (key: string, vars?: Record<string, string | number>) => string, d: AgentDevice): string {
  if (d.kind === "browser") return d.label ?? t("agentStatus.firstBrowser");
  if (d.kind === "computer") {
    return d.label ? t("agentStatus.deviceComputer", { name: d.label }) : t("agentStatus.deviceComputerUnnamed");
  }
  return t("agentStatus.deviceOther");
}

/**
 * The list's status, whether this browser can approve (it may sign the
 * list), which browsers may, and this browser's device of the agent.
 */
export function useDeviceList(agent: Agent): {
  status: ListStatus | null;
  rootHere: boolean;
  signers: string[];
  local: string | null;
} {
  const [status, setStatus] = useState<ListStatus | null>(null);
  const [rootHere, setRootHere] = useState(false);
  const [signers, setSigners] = useState<string[]>([]);
  const [local, setLocal] = useState<string | null>(null);
  const key = `${agent.aid}|${agent.device_list?.jws ?? ""}|${(agent.devices ?? [])
    .map((d) => `${d.did}:${d.encryption_public_key ?? ""}`)
    .join(",")}`;
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const [next, signer, all, here] = await Promise.all([
        checkDeviceList(agent),
        listSignerHere(agent),
        listSignerDids(agent),
        localDeviceDid(agent),
      ]);
      if (!cancelled) {
        setStatus(next);
        setRootHere(signer !== null);
        setSigners(all);
        setLocal(here);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [key]);
  return { status, rootHere, signers, local };
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
  const [failed, setFailed] = useState<"remove" | "approve" | "reauth" | null>(null);
  const [busy, setBusy] = useState(false);
  const devices = agent.devices ?? [];
  const { status, rootHere, signers, local } = useDeviceList(agent);
  const browsers = devices.filter((d) => d.kind === "browser");
  // A World ID sign-in just made for adding a browser (docs/40 §17.5).
  const [adding, setAdding] = useState(false);
  useEffect(() => {
    if (new URLSearchParams(window.location.search).get("addBrowser") === "1") setAdding(true);
  }, []);
  // Which browser runs the automatic replies (docs/40 §17.6).
  const runner = autoReplyBrowser(agent);
  const autoReplyDid = runner?.did ?? agent.did;

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

  // Another browser: sign the list without it (docs/40 §17.5). The server
  // stops its key at once; it asks for World ID again first.
  const removeBrowser = async (d: AgentDevice) => {
    if (!status || status.kind !== "ok") return;
    if (!window.confirm(t("deviceList.removeBrowserConfirm", { name: deviceName(t, d) }))) return;
    setFailed(null);
    setBusy(true);
    try {
      const keep = approvedWith(agent, status, []);
      keep.delete(d.did);
      await storeDeviceList(agent, keep);
      await refreshed();
    } catch (error) {
      setFailed(error instanceof ApiError && error.status === 403 ? "reauth" : "remove");
    } finally {
      setBusy(false);
    }
  };

  // A new agent has no list until Messages makes one; make it here too,
  // so 「ほかのブラウザを足す」 shows from the start. Nothing to ask: the
  // only device is this browser (docs/40 stage 1).
  const quietTried = useRef(false);
  useEffect(() => {
    if (quietTried.current || status?.kind !== "none" || !rootHere || !onlyRootDevice(agent)) return;
    quietTried.current = true;
    void storeDeviceList(agent, new Set([agent.did]))
      .then(() => refreshed())
      .catch(() => undefined);
  }, [status, rootHere, agent]);

  const runAutoRepliesHere = async () => {
    if (!local) return;
    setFailed(null);
    try {
      await defaultApiClient.setAutoReplyDevice(agent.id, local === agent.did ? null : local);
      await refreshed();
    } catch {
      setFailed("remove");
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
          style={{ borderRadius: 12, background: "var(--warn-soft)", padding: "10px 12px", marginBottom: 8 }}
        >
          {status?.kind === "none" ? (
            <p style={{ margin: 0, fontWeight: 700 }}>{t("deviceList.notReceivingTitle")}</p>
          ) : null}
          {devices.some(connectedTheOldWay) ? (
            // Approving all would approve the computer connected the old way.
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
              {t("deviceList.notReceivingOldWay")}
            </p>
          ) : rootHere ? (
            <>
              <p className="item-sub" style={{ margin: "2px 0 0" }}>
                {status?.kind === "none"
                  ? t("deviceList.approveBody", { n: approvable.length })
                  : t("deviceList.redoBody", { n: approvable.length })}
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
            <p className="item-sub" style={{ margin: "2px 0 0" }}>
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
            <span aria-hidden style={{ fontSize: "var(--fs-lg)", lineHeight: "22px" }}>
              {d.kind === "computer" ? "💻" : "🌐"}
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <span style={STRONG}>{d.did === local ? t("agentStatus.thisBrowser") : deviceName(t, d)}</span>
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
                  d.kind === "browser" && d.did === agent.did
                    ? t("agentStatus.deviceCreated", { date: date(d.activated_at) })
                    : d.kind === "browser"
                      ? t("deviceList.browserAdded", { date: date(d.activated_at) })
                      : t("agentStatus.deviceJoined", { date: date(d.activated_at) }),
                  seen
                    ? state === "silent"
                      ? t("agentStatus.deviceStoppedSince", { ago: seen })
                      : t("agentStatus.deviceSeen", { ago: seen })
                    : null,
                  d.kind === "browser" && signers.includes(d.did) ? t("deviceList.signer") : null,
                  approval === "pending" && !rootHere ? t("deviceList.pendingOther") : null,
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
              {state === "silent" && !connectedTheOldWay(d) ? (
                // Only for a computer that just needs starting: one connected
                // the old way is asked to reconnect instead.
                <details open data-testid="agent-device-restart" className="item-sub" style={{ margin: "6px 0 0" }}>
                  <summary style={{ cursor: "pointer", fontWeight: 700, color: "var(--text)" }}>
                    {t("agentStatus.restartTitle")}
                  </summary>
                  <p style={{ margin: "4px 0 0" }}>{t("agentStatus.silentSub")}</p>
                  <p style={{ margin: "4px 0 0" }}>{t("agentStatus.startHint")}</p>
                  <CommandLine command={daemonStartCommand(agentDirName(agent.label, agent.aid))} />
                  <p style={{ margin: "6px 0 0" }}>{t("agentStatus.startDirNote")}</p>
                  <p style={{ margin: "6px 0 0" }}>{t("agentStatus.autostartHint")}</p>
                </details>
              ) : null}
              {connectedTheOldWay(d) ? (
                <div data-testid="agent-device-old-way" style={{ marginTop: 6 }}>
                  <p className="item-sub" style={{ margin: 0 }}>
                    {t("pairing.oldWayBody")}
                  </p>
                  <div style={{ display: "flex", gap: 8, marginTop: 6, flexWrap: "wrap" }}>
                    <button
                      type="button"
                      className="btn primary"
                      onClick={() => void remove(d, onReconnect)}
                      disabled={revoke.isPending}
                      data-testid="agent-device-reconnect"
                    >
                      {t("pairing.oldWayReconnect")}
                    </button>
                    <button
                      type="button"
                      className="btn"
                      style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                      onClick={() => void remove(d)}
                      disabled={revoke.isPending}
                      data-testid="agent-device-remove-old-way"
                    >
                      {t("agentStatus.deviceRemove")}
                    </button>
                  </div>
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
            {d.kind === "browser" && d.did !== local && rootHere && browsers.length > 1 ? (
              <button
                type="button"
                className="btn"
                style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                onClick={() => void removeBrowser(d)}
                disabled={busy}
                data-testid="agent-device-remove-browser"
              >
                {t("agentStatus.deviceRemove")}
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
      {rootHere && listed ? (
        <div style={{ marginTop: 10 }}>
          {adding ? (
            <AddBrowserPanel onClose={() => setAdding(false)} onDone={() => void refreshed()} />
          ) : (
            <div>
              <button type="button" className="btn" onClick={() => setAdding(true)} data-testid="add-browser">
                {t("addBrowser.button")}
              </button>
              <p className="item-sub" style={{ margin: "4px 0 0" }}>
                {t("addBrowser.buttonSub")}
              </p>
            </div>
          )}
          {signers.length === 1 && !adding ? (
            <p
              className="item-sub"
              data-testid="single-signer-hint"
              style={{ margin: "8px 0 0", padding: "8px 10px", borderRadius: 10, background: "var(--surface-2, #f1f3f6)" }}
            >
              {t("addBrowser.singleSignerHint")}
            </p>
          ) : null}
        </div>
      ) : null}
      {browsers.length > 1 ? (
        <div data-testid="auto-reply-browser" style={{ marginTop: 10 }}>
          <p style={{ margin: 0, fontWeight: 700 }}>{t("addBrowser.autoReplyTitle")}</p>
          <p className="item-sub" style={{ margin: "2px 0 0" }}>
            {t("addBrowser.autoReplyRunsOn", {
              name: runner ? deviceName(t, runner) : t("agentStatus.deviceBrowser"),
            })}
          </p>
          {local && local !== autoReplyDid ? (
            <button type="button" className="btn" style={{ marginTop: 6 }} onClick={() => void runAutoRepliesHere()}>
              {t("addBrowser.autoReplyHere")}
            </button>
          ) : null}
        </div>
      ) : null}
      {failed ? (
        <p className="item-sub" style={{ margin: "4px 0 0", color: "var(--danger)" }} role="status">
          {failed === "reauth" ? (
            <>
              {t("addBrowser.reauth")}{" "}
              <a href={`/login?next=${encodeURIComponent(window.location.pathname + window.location.search)}`}>
                {t("addBrowser.reauthLink")}
              </a>
            </>
          ) : failed === "remove" ? (
            t("agentStatus.deviceRemoveFailed")
          ) : (
            t("deviceList.failed")
          )}
        </p>
      ) : null}
    </div>
  );
}

function Pill({ color, background, text }: { color: string; background: string; text: string }) {
  return (
    <span
      style={{
        display: "inline-block",
        whiteSpace: "nowrap",
        marginLeft: 6,
        fontSize: "var(--fs-xs)",
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
