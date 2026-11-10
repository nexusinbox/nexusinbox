"use client";

// First-run guide (docs/31): name an agent, choose where it runs, connect
// a computer with a pairing code if wanted, choose how requests are
// handled, and send the agent a test request. Identifiers and keys stay
// out of sight here; the agent settings page has them.

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  AutoReplyPresetChoices,
  ChoiceCard,
  ConnectComputer,
  ErrorLine,
  STRONG,
  useApplyAutoReplyPreset,
} from "../_components/AgentSetup";
import { AppShell } from "../_components/AppShell";
import { InviteCard, useInviteName } from "../_components/InviteCard";
import { type AutoReplyPreset } from "../../lib/agents/auto-reply-presets";
import { createAgentWithLocalKeys } from "../../lib/agents/create-agent";
import {
  selfTestCandidates,
  selfTestSettled,
  selfTestState,
  type SelfTestState,
} from "../../lib/agents/self-test";
import { defaultApiClient } from "../../lib/api/client";
import {
  useAgentsQuery,
  useCreateAgentMutation,
  useSendMessageMutation,
} from "../../lib/api/hooks";
import type { Agent, MessageIndexEntry } from "../../lib/api/types";
import { getSigningPrivateKey } from "../../lib/crypto/signing-keyring";
import { useTranslation } from "../../lib/i18n";
import { sendScheduleProposal } from "../../lib/protocol/send-propose";

type Step = "name" | "where" | "connect" | "replies" | "test" | "done";
type Where = "browser" | "pc";
type NewAgent = { id: string; aid: string; did: string; label: string };

const POLL_MS = 2000;
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
  // An address to write to once the agent exists (from 新しい会話 opened
  // by a shared intro page, docs/36). Only agent addresses are kept.
  const withParam = searchParams.get("with")?.trim() ?? "";
  const returnTo = withParam.startsWith("aid:ai:")
    ? `/compose?with=${encodeURIComponent(withParam)}`
    : null;
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
              router.replace(
                `/onboarding?agent=${encodeURIComponent(created.id)}` +
                  (returnTo ? `&with=${encodeURIComponent(withParam)}` : ""),
              );
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
            onInbox={() => router.push(`/?agent=${encodeURIComponent(agent.did)}`)}
            onSettings={() => router.push("/settings/agents")}
            onReturn={returnTo ? () => router.push(returnTo) : undefined}
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
        <ChoiceCard
          selected={where === "browser"}
          onSelect={() => onChange("browser")}
          title={t("firstRun.where.browserTitle")}
          badge={t("firstRun.where.browserBadge")}
          testId="first-run-where-browser"
        >
          {t("firstRun.where.browserDesc")}
        </ChoiceCard>
        <ChoiceCard
          selected={where === "pc"}
          onSelect={() => onChange("pc")}
          title={t("firstRun.where.pcTitle")}
          testId="first-run-where-pc"
        >
          {t("firstRun.where.pcDesc")}
          <br />
          {t("firstRun.where.pcNote")}
        </ChoiceCard>
      </div>
      <Actions>
        <button className="btn primary" type="button" onClick={onNext} data-testid="first-run-next">
          {t("firstRun.next")}
        </button>
      </Actions>
    </div>
  );
}

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
  return (
    <div className="panel">
      <StepHeading title={t("firstRun.connect.title")} desc={t("firstRun.connect.desc")} />
      {device ? (
        <p style={{ ...STRONG, marginTop: 14, color: "var(--ok)" }} data-testid="first-run-connected">
          ✓ {t("firstRun.connect.connected", { device })}
        </p>
      ) : (
        <ConnectComputer agentId={agent.id} onConnected={onConnected} />
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
  const applyPreset = useApplyAutoReplyPreset();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  const save = async () => {
    setBusy(true);
    setFailed(false);
    try {
      await applyPreset(agent.id, preset);
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
      <AutoReplyPresetChoices value={preset} onChange={onChange} />
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
  onReturn,
}: {
  agent: NewAgent;
  onInbox: () => void;
  onSettings: () => void;
  /** Back to the message that brought them here, when there is one. */
  onReturn?: () => void;
}) {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const full = agentsQuery.data?.agents.find((a) => a.id === agent.id);
  const [inviteLater, setInviteLater] = useState(false);
  return (
    <div className="panel" data-testid="first-run-done">
      <StepHeading title={t("firstRun.done.title")} desc={t("firstRun.done.desc", { name: agent.label })} />
      {full && !inviteLater ? (
        <DoneInvite agent={full} onLater={() => setInviteLater(true)} />
      ) : null}
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
        <button
          className={onReturn ? "btn" : "btn primary"}
          type="button"
          onClick={onInbox}
          data-testid="first-run-to-inbox"
        >
          {t("firstRun.done.toInbox")}
        </button>
        {onReturn ? (
          <button className="btn primary" type="button" onClick={onReturn} data-testid="first-run-return">
            {t("firstRun.done.toMessage")}
          </button>
        ) : null}
      </Actions>
    </div>
  );
}

function DoneInvite({ agent, onLater }: { agent: Agent; onLater: () => void }) {
  const { t } = useTranslation();
  const name = useInviteName(agent);
  return (
    <InviteCard
      agent={agent}
      title={t("share.inviteTitle")}
      desc={t("share.inviteDesc", { name })}
      onLater={onLater}
    />
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

function Actions({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", marginTop: 18, gap: 8, justifyContent: "flex-end" }}>
      {children}
    </div>
  );
}
