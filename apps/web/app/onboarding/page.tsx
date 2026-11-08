"use client";

// First-run guide (docs/31): name an agent, choose where it runs, connect
// a computer with a pairing code if wanted, choose how requests are
// handled, and send the agent a test request. Identifiers and keys stay
// out of sight here; the agent settings page has them.

import { useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Suspense,
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
  type ReactNode,
} from "react";
import { AppShell } from "../_components/AppShell";
import { presetSettings, type AutoReplyPreset } from "../../lib/agents/auto-reply-presets";
import { createAgentWithLocalKeys } from "../../lib/agents/create-agent";
import { daemonConnectCommand } from "../../lib/agents/enroll-command";
import {
  selfTestCandidates,
  selfTestSettled,
  selfTestState,
  type SelfTestState,
} from "../../lib/agents/self-test";
import { defaultApiClient } from "../../lib/api/client";
import {
  queryKeys,
  useAgentsQuery,
  useCreateAgentMutation,
  useSendMessageMutation,
  useUpdateAgentMutation,
} from "../../lib/api/hooks";
import type { MessageIndexEntry } from "../../lib/api/types";
import { getSigningPrivateKey } from "../../lib/crypto/signing-keyring";
import { useTranslation } from "../../lib/i18n";
import { sendScheduleProposal } from "../../lib/protocol/send-propose";

type Step = "name" | "where" | "connect" | "replies" | "test" | "done";
type Where = "browser" | "pc";
type NewAgent = { id: string; aid: string; did: string; label: string };

const POLL_MS = 2000;
// Emphasis without the .item-title class, which upper-cases Latin text.
const STRONG: CSSProperties = { fontWeight: 600, color: "var(--text)" };
// How long the test waits for the message and the setting to apply, and
// for a connected computer to answer (its executor runs every 30 s).
const ARRIVAL_TIMEOUT_MS = 60_000;
const COMPUTER_REPLY_TIMEOUT_MS = 180_000;

export default function OnboardingPage() {
  return (
    <Suspense fallback={null}>
      <OnboardingFlow />
    </Suspense>
  );
}

function OnboardingFlow() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const agentsQuery = useAgentsQuery();
  const [step, setStep] = useState<Step>("name");
  const [agent, setAgent] = useState<NewAgent | null>(null);
  const [where, setWhere] = useState<Where>("browser");
  const [device, setDevice] = useState<string | null>(null);
  const [preset, setPreset] = useState<AutoReplyPreset>("manual");

  // After a reload, carry on with the agent created before it rather than
  // creating another one.
  const resumeId = searchParams.get("agent");
  useEffect(() => {
    if (agent || !resumeId) return;
    const found = agentsQuery.data?.agents.find((a) => a.id === resumeId);
    if (found) {
      setAgent({ id: found.id, aid: found.aid, did: found.did, label: found.label });
      setStep("where");
    }
  }, [agent, resumeId, agentsQuery.data]);

  const steps: Step[] =
    where === "pc"
      ? ["name", "where", "connect", "replies", "test", "done"]
      : ["name", "where", "replies", "test", "done"];
  const position = steps.indexOf(step) + 1;

  return (
    <AppShell title={t("firstRun.title")} activePath="/onboarding">
      <section style={{ padding: 24, maxWidth: 640 }} data-testid="first-run">
        <p className="item-sub" style={{ marginBottom: 12 }} data-testid="first-run-step">
          {t("firstRun.stepOf", { current: position, total: steps.length })}
        </p>
        {step === "name" ? (
          <NameStep
            onCreated={(created) => {
              setAgent(created);
              router.replace(`/onboarding?agent=${encodeURIComponent(created.id)}`);
              setStep("where");
            }}
          />
        ) : null}
        {step === "where" ? (
          <WhereStep
            where={where}
            onChange={setWhere}
            onNext={() => setStep(where === "pc" ? "connect" : "replies")}
          />
        ) : null}
        {step === "connect" && agent ? (
          <ConnectStep
            agent={agent}
            device={device}
            onConnected={setDevice}
            onBack={() => setStep("where")}
            onNext={() => setStep("replies")}
          />
        ) : null}
        {step === "replies" && agent ? (
          <RepliesStep
            agent={agent}
            preset={preset}
            onChange={setPreset}
            onBack={() => setStep(where === "pc" ? "connect" : "where")}
            onNext={() => setStep("test")}
          />
        ) : null}
        {step === "test" && agent ? (
          <TestStep
            agent={agent}
            where={where}
            onBack={() => setStep("replies")}
            onNext={() => setStep("done")}
          />
        ) : null}
        {step === "done" && agent ? (
          <DoneStep
            agent={agent}
            onInbox={() => router.push(`/agent/${encodeURIComponent(agent.did)}`)}
            onSettings={() => router.push("/settings/agents")}
          />
        ) : null}
      </section>
    </AppShell>
  );
}

// --- steps -------------------------------------------------------------------

function NameStep({ onCreated }: { onCreated: (agent: NewAgent) => void }) {
  const { t } = useTranslation();
  const createAgent = useCreateAgentMutation();
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const trimmed = label.trim();
    if (!trimmed) {
      setError(t("firstRun.name.empty"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await createAgentWithLocalKeys(trimmed, createAgent.mutateAsync);
      onCreated({ id: created.id, aid: created.aid, did: created.did, label: trimmed });
    } catch {
      setError(t("firstRun.name.failed"));
      setBusy(false);
    }
  };

  return (
    <form className="panel" onSubmit={(e) => void submit(e)}>
      <StepHeading title={t("firstRun.name.title")} desc={t("firstRun.name.desc")} />
      <label style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 14 }}>
        <span style={STRONG}>{t("firstRun.name.label")}</span>
        <input
          className="input"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder={t("firstRun.name.placeholder")}
          maxLength={64}
          autoFocus
          data-testid="first-run-name"
        />
        <span className="item-sub">{t("firstRun.name.hint")}</span>
      </label>
      {error ? <ErrorLine>{error}</ErrorLine> : null}
      <Actions>
        <button className="btn primary" type="submit" disabled={busy} data-testid="first-run-create">
          {busy ? t("firstRun.name.creating") : t("firstRun.name.create")}
        </button>
      </Actions>
    </form>
  );
}

function WhereStep({
  where,
  onChange,
  onNext,
}: {
  where: Where;
  onChange: (where: Where) => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="panel">
      <StepHeading title={t("firstRun.where.title")} desc={t("firstRun.where.desc")} />
      <div role="radiogroup" style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
        <Choice
          selected={where === "browser"}
          onSelect={() => onChange("browser")}
          title={t("firstRun.where.browserTitle")}
          badge={t("firstRun.where.browserBadge")}
          testId="first-run-where-browser"
        >
          {t("firstRun.where.browserDesc")}
        </Choice>
        <Choice
          selected={where === "pc"}
          onSelect={() => onChange("pc")}
          title={t("firstRun.where.pcTitle")}
          testId="first-run-where-pc"
        >
          {t("firstRun.where.pcDesc")}
          <br />
          {t("firstRun.where.pcNote")}
        </Choice>
      </div>
      <Actions>
        <button className="btn primary" type="button" onClick={onNext} data-testid="first-run-next">
          {t("firstRun.next")}
        </button>
      </Actions>
    </div>
  );
}

type Pairing = { credentialId: string; code: string; expiresAt: number };

function ConnectStep({
  agent,
  device,
  onConnected,
  onBack,
  onNext,
}: {
  agent: NewAgent;
  device: string | null;
  onConnected: (device: string) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const [pairing, setPairing] = useState<Pairing | null>(null);
  const [issueFailed, setIssueFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [copied, setCopied] = useState(false);
  const issuing = useRef(false);

  const issue = useCallback(async () => {
    if (issuing.current) return;
    issuing.current = true;
    setIssueFailed(false);
    try {
      const created = await defaultApiClient.createAgentCredential({
        agent_id: agent.id,
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
  }, [agent.id, t]);

  useEffect(() => {
    if (!device && !pairing && !issueFailed) void issue();
  }, [device, pairing, issueFailed, issue]);

  // Watch the credential until the computer activates it.
  const expired = pairing !== null && now > pairing.expiresAt;
  useEffect(() => {
    if (!pairing || device || expired) return;
    let stopped = false;
    const timer = setInterval(() => {
      setNow(Date.now());
      void defaultApiClient
        .listAgentCredentials()
        .then(({ credentials }) => {
          const credential = credentials.find((c) => c.credential_id === pairing.credentialId);
          if (!stopped && credential?.status === "active") onConnected(credential.label);
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [pairing, device, expired, onConnected]);

  const command = pairing ? daemonConnectCommand(pairing.code) : "";
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
    <div className="panel">
      <StepHeading title={t("firstRun.connect.title")} desc={t("firstRun.connect.desc")} />
      {device ? (
        <p style={{ ...STRONG, marginTop: 14, color: "var(--ok)" }} data-testid="first-run-connected">
          ✓ {t("firstRun.connect.connected", { device })}
        </p>
      ) : issueFailed ? (
        <div style={{ marginTop: 14 }}>
          <ErrorLine>{t("firstRun.connect.issueFailed")}</ErrorLine>
          <button className="btn" type="button" onClick={() => void issue()} style={{ marginTop: 8 }}>
            {t("firstRun.connect.retry")}
          </button>
        </div>
      ) : !pairing ? (
        <p className="item-sub" style={{ marginTop: 14 }}>
          {t("firstRun.connect.issuing")}
        </p>
      ) : expired ? (
        <div style={{ marginTop: 14 }}>
          <p className="item-sub">{t("firstRun.connect.expired")}</p>
          <button
            className="btn"
            type="button"
            onClick={() => setPairing(null)}
            style={{ marginTop: 8 }}
            data-testid="first-run-new-code"
          >
            {t("firstRun.connect.newCode")}
          </button>
        </div>
      ) : (
        <>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: 14,
              padding: "10px 12px",
              borderRadius: 8,
              background: "var(--surface-alt)",
              border: "1px solid var(--line)",
            }}
          >
            <code
              // Width 0, then grow: a one-line command must not widen the
              // page on a narrow screen; it scrolls inside its box instead.
              style={{
                flex: "1 1 0",
                width: 0,
                minWidth: 0,
                overflowX: "auto",
                whiteSpace: "nowrap",
                fontSize: 13,
              }}
              data-testid="first-run-command"
            >
              {command}
            </code>
            <button className="btn" type="button" onClick={() => void copy()}>
              {copied ? t("firstRun.connect.copied") : t("firstRun.connect.copy")}
            </button>
          </div>
          <p className="item-sub" style={{ marginTop: 10 }}>
            {t("firstRun.connect.passphrase")}
          </p>
          <p className="item-sub" style={{ marginTop: 6 }}>
            {t("firstRun.connect.codeNote", { code: pairing.code })}
          </p>
          <p className="item-sub" style={{ marginTop: 12 }} aria-live="polite">
            {t("firstRun.connect.waiting")}
          </p>
        </>
      )}
      <Actions>
        {!device ? (
          <button className="btn" type="button" onClick={onBack}>
            {t("firstRun.back")}
          </button>
        ) : null}
        <button
          className="btn primary"
          type="button"
          onClick={onNext}
          disabled={!device}
          data-testid="first-run-next"
        >
          {t("firstRun.next")}
        </button>
      </Actions>
    </div>
  );
}

function RepliesStep({
  agent,
  preset,
  onChange,
  onBack,
  onNext,
}: {
  agent: NewAgent;
  preset: AutoReplyPreset;
  onChange: (preset: AutoReplyPreset) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const updateAgent = useUpdateAgentMutation();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  // The policy first, then the switch, so auto-replies never run on a
  // policy the person did not choose.
  const save = async () => {
    setBusy(true);
    setFailed(false);
    try {
      const { autoReply, policy } = presetSettings(preset);
      if (policy) {
        const current = await defaultApiClient.getAutoReplyPolicy(agent.id);
        const saved = await defaultApiClient.putAutoReplyPolicy(agent.id, {
          policy,
          revision: current.revision,
        });
        queryClient.setQueryData(queryKeys.autoReplyPolicy(agent.id), saved);
      }
      await updateAgent.mutateAsync({ id: agent.id, body: { auto_reply: autoReply } });
      onNext();
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="panel">
      <StepHeading title={t("firstRun.replies.title")} desc={t("firstRun.replies.desc")} />
      <div role="radiogroup" style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
        <Choice
          selected={preset === "manual"}
          onSelect={() => onChange("manual")}
          title={t("firstRun.replies.manualTitle")}
          badge={t("firstRun.replies.manualBadge")}
          testId="first-run-preset-manual"
        >
          {t("firstRun.replies.manualDesc")}
        </Choice>
        <Choice
          selected={preset === "contacts"}
          onSelect={() => onChange("contacts")}
          title={t("firstRun.replies.contactsTitle")}
          testId="first-run-preset-contacts"
        >
          {t("firstRun.replies.contactsDesc")}
        </Choice>
        <Choice
          selected={preset === "all"}
          onSelect={() => onChange("all")}
          title={t("firstRun.replies.allTitle")}
          testId="first-run-preset-all"
        >
          {t("firstRun.replies.allDesc")}
        </Choice>
      </div>
      {failed ? <ErrorLine>{t("firstRun.replies.saveFailed")}</ErrorLine> : null}
      <Actions>
        <button className="btn" type="button" onClick={onBack} disabled={busy}>
          {t("firstRun.back")}
        </button>
        <button
          className="btn primary"
          type="button"
          onClick={() => void save()}
          disabled={busy}
          data-testid="first-run-next"
        >
          {busy ? t("firstRun.replies.saving") : t("firstRun.next")}
        </button>
      </Actions>
    </div>
  );
}

const TEST_LINES: Record<SelfTestState, string> = {
  waiting: "firstRun.test.waiting",
  arrived: "firstRun.test.deciding",
  queued: "firstRun.test.queued",
  queued_not_contact: "firstRun.test.queuedNotContact",
  accept_pending_pc: "firstRun.test.acceptPendingPc",
  accepted_pc: "firstRun.test.acceptedPc",
  accept_in_browser: "firstRun.test.acceptInBrowser",
};

function TestStep({
  agent,
  where,
  onBack,
  onNext,
}: {
  agent: NewAgent;
  where: Where;
  onBack: () => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const sendMessage = useSendMessageMutation();
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<{ messageId: string; recipientDid: string; at: number } | null>(
    null,
  );
  const [row, setRow] = useState<MessageIndexEntry | null>(null);
  const [timedOut, setTimedOut] = useState(false);

  const state = sent ? selfTestState(row, where) : null;
  const settled = state !== null && selfTestSettled(state);

  const send = async () => {
    setSending(true);
    setError(null);
    setRow(null);
    setTimedOut(false);
    try {
      const signingPrivateKey = await getSigningPrivateKey(agent.did);
      if (!signingPrivateKey) throw new Error(t("firstRun.test.noKey"));
      // By AID, so a connected computer's key is the one used.
      const resolved = await defaultApiClient.resolveRecipient(agent.aid);
      const title = t("firstRun.test.eventTitle");
      const { messageId } = await sendScheduleProposal(
        {
          senderDid: agent.did,
          signingPrivateKey,
          recipientDid: resolved.did,
          recipientEncryptionKey: resolved.encryption_public_key,
          subject: title,
          body: t("firstRun.test.body"),
          payload: {
            event_title: title,
            candidates: selfTestCandidates(new Date()),
            required_participants: [],
          },
        },
        sendMessage.mutateAsync,
      );
      setSent({ messageId, recipientDid: resolved.did, at: Date.now() });
    } catch (err) {
      setError(t("firstRun.test.failed", { error: err instanceof Error ? err.message : String(err) }));
    } finally {
      setSending(false);
    }
  };

  // Follow the message until nothing more happens without the person.
  useEffect(() => {
    if (!sent || settled || timedOut) return;
    const timer = setInterval(() => {
      const limit = state === "accept_pending_pc" ? COMPUTER_REPLY_TIMEOUT_MS : ARRIVAL_TIMEOUT_MS;
      if (Date.now() - sent.at > limit) {
        setTimedOut(true);
        return;
      }
      void defaultApiClient
        .listMessages({ agentDid: sent.recipientDid, status: "all", perPage: 20 })
        .then((list) => {
          const found = list.messages.find((m) => m.id === sent.messageId);
          if (found) setRow(found);
        })
        .catch(() => undefined);
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [sent, settled, timedOut, state]);

  return (
    <div className="panel">
      <StepHeading title={t("firstRun.test.title")} desc={t("firstRun.test.desc")} />
      {!sent ? (
        <div style={{ marginTop: 14 }}>
          <button
            className="btn primary"
            type="button"
            onClick={() => void send()}
            disabled={sending}
            data-testid="first-run-send-test"
          >
            {sending ? t("firstRun.test.sending") : error ? t("firstRun.test.retry") : t("firstRun.test.send")}
          </button>
          {error ? <ErrorLine>{error}</ErrorLine> : null}
        </div>
      ) : (
        <ul style={{ listStyle: "none", padding: 0, margin: "14px 0 0", display: "flex", flexDirection: "column", gap: 8 }} aria-live="polite" data-testid="first-run-test-result">
          {row ? (
            <li style={{ ...STRONG, color: "var(--ok)" }}>
              ✓ {t("firstRun.test.arrived")}
            </li>
          ) : null}
          {state ? (
            <li
              className={settled ? undefined : "item-sub"}
              style={settled ? { ...STRONG, color: "var(--ok)" } : undefined}
              data-testid={`first-run-test-${state}`}
            >
              {settled ? "✓ " : ""}
              {t(TEST_LINES[state])}
            </li>
          ) : null}
          {timedOut ? <li className="item-sub">{t("firstRun.test.timeout")}</li> : null}
        </ul>
      )}
      <Actions>
        <button className="btn" type="button" onClick={onBack} disabled={sending}>
          {t("firstRun.back")}
        </button>
        <button
          className={sent ? "btn primary" : "btn"}
          type="button"
          onClick={onNext}
          data-testid="first-run-next"
        >
          {sent ? t("firstRun.next") : t("firstRun.test.skip")}
        </button>
      </Actions>
    </div>
  );
}

function DoneStep({
  agent,
  onInbox,
  onSettings,
}: {
  agent: NewAgent;
  onInbox: () => void;
  onSettings: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="panel" data-testid="first-run-done">
      <StepHeading title={t("firstRun.done.title")} desc={t("firstRun.done.desc", { name: agent.label })} />
      <p className="item-sub" style={{ marginTop: 10 }}>
        {t("firstRun.done.inbox")}
      </p>
      <p className="item-sub" style={{ marginTop: 6 }}>
        {t("firstRun.done.details")}
      </p>
      <Actions>
        <button className="btn" type="button" onClick={onSettings}>
          {t("firstRun.done.toSettings")}
        </button>
        <button className="btn primary" type="button" onClick={onInbox} data-testid="first-run-to-inbox">
          {t("firstRun.done.toInbox")}
        </button>
      </Actions>
    </div>
  );
}

// --- pieces ------------------------------------------------------------------

function StepHeading({ title, desc }: { title: string; desc: string }) {
  return (
    <>
      <h2 style={{ margin: 0, fontSize: 18 }}>{title}</h2>
      <p className="item-sub" style={{ marginTop: 6 }}>
        {desc}
      </p>
    </>
  );
}

function Choice({
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

function Actions({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", marginTop: 18, gap: 8, justifyContent: "flex-end" }}>
      {children}
    </div>
  );
}

function ErrorLine({ children }: { children: ReactNode }) {
  return (
    <p className="item-sub" role="alert" style={{ marginTop: 10, color: "var(--danger)" }}>
      {children}
    </p>
  );
}
