"use client";

// Pieces shared by the first-run guide (/onboarding) and the agent status
// card on the settings page (docs/31): connecting a computer with a pairing
// code, and choosing one of the three auto-reply presets.

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { presetSettings, type AutoReplyPreset } from "../../lib/agents/auto-reply-presets";
import { daemonConnectCommand } from "../../lib/agents/enroll-command";
import { defaultApiClient } from "../../lib/api/client";
import { queryKeys, useUpdateAgentMutation } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";

// Emphasis without the .item-title class, which upper-cases Latin text.
export const STRONG: CSSProperties = { fontWeight: 600, color: "var(--text)" };

const POLL_MS = 2000;

export function ErrorLine({ children }: { children: ReactNode }) {
  return (
    <p className="item-sub" role="alert" style={{ marginTop: 10, color: "var(--danger)" }}>
      {children}
    </p>
  );
}

export function ChoiceCard({
  selected,
  onSelect,
  title,
  badge,
  testId,
  children,
}: {
  selected: boolean;
  onSelect: () => void;
  title: string;
  badge?: string;
  testId: string;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      onClick={onSelect}
      data-testid={testId}
      style={{
        textAlign: "left",
        width: "100%",
        padding: "12px 14px",
        borderRadius: 10,
        border: selected ? "2px solid var(--primary)" : "1px solid var(--line)",
        background: selected ? "var(--primary-soft)" : "var(--surface)",
        color: "var(--text)",
        cursor: "pointer",
        display: "flex",
        flexDirection: "column",
        gap: 4,
      }}
    >
      <span style={STRONG}>
        {title}
        {badge ? (
          <span
            style={{
              marginLeft: 8,
              padding: "1px 8px",
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 600,
              background: "var(--surface-alt)",
              border: "1px solid var(--line)",
            }}
          >
            {badge}
          </span>
        ) : null}
      </span>
      <span className="item-sub">{children}</span>
    </button>
  );
}

/** A one-line command with a copy button that scrolls inside its box. */
export function CommandLine({ command, testId }: { command: string; testId?: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // The command stays visible for a manual copy.
    }
  };
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginTop: 10,
        padding: "10px 12px",
        borderRadius: 8,
        background: "var(--surface-alt)",
        border: "1px solid var(--line)",
      }}
    >
      <code
        // Width 0, then grow: a one-line command must not widen the page on
        // a narrow screen; it scrolls inside its box instead.
        style={{
          flex: "1 1 0",
          width: 0,
          minWidth: 0,
          overflowX: "auto",
          whiteSpace: "nowrap",
          fontSize: 13,
        }}
        data-testid={testId}
      >
        {command}
      </code>
      <button className="btn" type="button" onClick={() => void copy()}>
        {copied ? t("firstRun.connect.copied") : t("firstRun.connect.copy")}
      </button>
    </div>
  );
}

type Pairing = { credentialId: string; code: string; expiresAt: number };

/**
 * Show a pairing code and the command that uses it, and watch until the
 * computer activates the credential. Says nothing once connected: the
 * caller shows that.
 */
export function ConnectComputer({
  agentId,
  onConnected,
}: {
  agentId: string;
  onConnected: (device: string) => void;
}) {
  const { t } = useTranslation();
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [issueFailed, setIssueFailed] = useState(false);
  const [connected, setConnected] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const issuing = useRef(false);

  const issue = useCallback(async () => {
    if (issuing.current) return;
    issuing.current = true;
    setIssueFailed(false);
    try {
      const created = await defaultApiClient.createAgentCredential({
        agent_id: agentId,
        label: t("firstRun.connect.credentialLabel"),
        pairing: true,
      });
      if (!created.pairing_code) throw new Error("no pairing code");
      const expiresAt = Date.parse(created.enrollment_expires_at ?? "");
      setPairing({
        credentialId: created.credential_id,
        code: created.pairing_code,
        expiresAt: Number.isNaN(expiresAt) ? Date.now() + 10 * 60_000 : expiresAt,
      });
      setNow(Date.now());
    } catch {
      setIssueFailed(true);
    } finally {
      issuing.current = false;
    }
  }, [agentId, t]);

  useEffect(() => {
    if (!connected && !pairing && !issueFailed) void issue();
  }, [connected, pairing, issueFailed, issue]);

  // Watch the credential until the computer activates it.
  const expired = pairing !== null && now > pairing.expiresAt;
  useEffect(() => {
    if (!pairing || connected || expired) return;
    let stopped = false;
    const timer = setInterval(() => {
      setNow(Date.now());
      void defaultApiClient
        .listAgentCredentials()
        .then(({ credentials }) => {
          const credential = credentials.find((c) => c.credential_id === pairing.credentialId);
          if (!stopped && credential?.status === "active") {
            setConnected(true);
            onConnected(credential.label);
          }
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [pairing, connected, expired, onConnected]);

  if (connected) return null;
  if (issueFailed) {
    return (
      <div style={{ marginTop: 14 }}>
        <ErrorLine>{t("firstRun.connect.issueFailed")}</ErrorLine>
        <button className="btn" type="button" onClick={() => void issue()} style={{ marginTop: 8 }}>
          {t("firstRun.connect.retry")}
        </button>
      </div>
    );
  }
  if (!pairing) {
    return (
      <p className="item-sub" style={{ marginTop: 14 }}>
        {t("firstRun.connect.issuing")}
      </p>
    );
  }
  if (expired) {
    return (
      <div style={{ marginTop: 14 }}>
        <p className="item-sub">{t("firstRun.connect.expired")}</p>
        <button
          className="btn"
          type="button"
          onClick={() => setPairing(null)}
          style={{ marginTop: 8 }}
          data-testid="connect-new-code"
        >
          {t("firstRun.connect.newCode")}
        </button>
      </div>
    );
  }
  return (
    <div style={{ marginTop: 4 }}>
      <CommandLine command={daemonConnectCommand(pairing.code)} testId="connect-command" />
      <p className="item-sub" style={{ marginTop: 10 }}>
        {t("firstRun.connect.passphrase")}
      </p>
      <p className="item-sub" style={{ marginTop: 6 }}>
        {t("firstRun.connect.codeNote", { code: pairing.code })}
      </p>
      <p className="item-sub" style={{ marginTop: 12 }} aria-live="polite">
        {t("firstRun.connect.waiting")}
      </p>
    </div>
  );
}

/** The i18n keys naming each preset. */
export const PRESET_TEXT: Record<AutoReplyPreset, { title: string; desc: string }> = {
  manual: { title: "firstRun.replies.manualTitle", desc: "firstRun.replies.manualDesc" },
  contacts: { title: "firstRun.replies.contactsTitle", desc: "firstRun.replies.contactsDesc" },
  all: { title: "firstRun.replies.allTitle", desc: "firstRun.replies.allDesc" },
};

export function AutoReplyPresetChoices({
  value,
  onChange,
}: {
  value: AutoReplyPreset | null;
  onChange: (preset: AutoReplyPreset) => void;
}) {
  const { t } = useTranslation();
  return (
    <div role="radiogroup" style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
      {(["manual", "contacts", "all"] as const).map((preset) => (
        <ChoiceCard
          key={preset}
          selected={value === preset}
          onSelect={() => onChange(preset)}
          title={t(PRESET_TEXT[preset].title)}
          badge={preset === "manual" ? t("firstRun.replies.manualBadge") : undefined}
          testId={`preset-${preset}`}
        >
          {t(PRESET_TEXT[preset].desc)}
        </ChoiceCard>
      ))}
    </div>
  );
}

/**
 * Save a preset: the policy first, then the switch, so auto-replies never
 * run on a policy the person did not choose.
 */
export function useApplyAutoReplyPreset() {
  const queryClient = useQueryClient();
  const updateAgent = useUpdateAgentMutation();
  return useCallback(
    async (agentId: string, preset: AutoReplyPreset) => {
      const { autoReply, policy } = presetSettings(preset);
      if (policy) {
        const current = await defaultApiClient.getAutoReplyPolicy(agentId);
        const saved = await defaultApiClient.putAutoReplyPolicy(agentId, {
          policy,
          revision: current.revision,
        });
        queryClient.setQueryData(queryKeys.autoReplyPolicy(agentId), saved);
      }
      await updateAgent.mutateAsync({ id: agentId, body: { auto_reply: autoReply } });
    },
    [queryClient, updateAgent],
  );
}
