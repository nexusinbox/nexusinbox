"use client";

// First-run guide (docs/41 §5, mock docs/41_stage_b_onboarding_mock.html):
// choose the AI, create the address, connect the AI, choose what to leave
// to it, try it, and see what is ready. Picking up again is decided from
// the server and this browser's keys (lib/onboarding/flow.ts). Only AI
// tools checked end to end can be chosen (docs/41 §5.2.1).

import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  AutoReplyPresetChoices,
  ChoiceCard,
  CommandLine,
  ConnectComputer,
  ErrorLine,
  PRESET_TEXT,
  STRONG,
  useApplyAutoReplyPreset,
} from "../_components/AgentSetup";
import { AppShell } from "../_components/AppShell";
import { useNow } from "../_components/AgentStatusCard";
import { InviteCard, useInviteName } from "../_components/InviteCard";
import { cloudAccessStatus, computerStatus } from "../../lib/agents/agent-status";
import { type AutoReplyPreset } from "../../lib/agents/auto-reply-presets";
import { createAgentWithLocalKeys } from "../../lib/agents/create-agent";
import { selfTestCandidates, selfTestSettled, selfTestState, type SelfTestState } from "../../lib/agents/self-test";
import { defaultApiClient } from "../../lib/api/client";
import {
  queryKeys,
  useAgentCredentialsQuery,
  useAgentsQuery,
  useCreateAgentMutation,
  useOAuthGrantsQuery,
  useSendMessageMutation,
  useSetCloudAccessMutation,
} from "../../lib/api/hooks";
import type { Agent, AgentCredential, MessageIndexEntry, OAuthGrant } from "../../lib/api/types";
import { planSend } from "../../lib/crypto/device-wraps";
import { getSigningPrivateKey, hasSigningPrivateKeyMaterial } from "../../lib/crypto/signing-keyring";
import { acknowledgeDevicesAfterConnect } from "../../lib/home/device-attention";
import { useTranslation } from "../../lib/i18n";
import { decryptMessageBody } from "../../lib/inbox/decrypt-message";
import { onboardingHref, parseAi, resumeStep, stepsFor, type OnboardingAi, type Step } from "../../lib/onboarding/flow";
import { sendScheduleProposal } from "../../lib/protocol/send-propose";

type Screen = Step | "mobile" | "resume" | "elsewhere";
type NewAgent = { id: string; aid: string; did: string; label: string };
type AiRead = "shown" | "not_shown" | "later";
type AutoResult = "skipped" | "ok" | "not_yet";

const POLL_MS = 2000;
// How long the test waits for the message and the setting to apply, and
// for a connected computer to answer (its executor runs every 30 s).
const ARRIVAL_TIMEOUT_MS = 60_000;
const COMPUTER_REPLY_TIMEOUT_MS = 180_000;
// While connecting, look for the computer and the AI's permission this often.
const CONNECT_POLL_MS = 5000;

/** The AI's name as the person knows it. */
const AI_NAME: Record<Exclude<OnboardingAi, "web">, string> = { claude_code: "Claude Code" };

/** A phone: connecting an AI needs a computer, so stop before creating anything (docs/41 §5.3). */
function isPhone(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(pointer: coarse) and (max-width: 820px)").matches;
}

function allowedGrant(grants: OAuthGrant[] | undefined, aid: string): OAuthGrant | null {
  return (grants ?? []).find((g) => g.aid === aid) ?? null;
}

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
  const grantsQuery = useOAuthGrantsQuery();
  const credentialsQuery = useAgentCredentialsQuery();

  const resumeId = searchParams.get("agent");
  // An address to write to once the agent exists (from 新しい会話 opened
  // by a shared intro page, docs/36). Only agent addresses are kept.
  const withParam = searchParams.get("with")?.trim() ?? "";
  const keepWith = withParam.startsWith("aid:ai:") ? withParam : "";
  const returnTo = keepWith ? `/compose?with=${encodeURIComponent(keepWith)}` : null;

  const [screen, setScreen] = useState<Screen | null>(resumeId ? null : "ai");
  const [resumeAt, setResumeAt] = useState<Step>("replies");
  const [ai, setAi] = useState<OnboardingAi | null>(parseAi(searchParams.get("ai")));
  const [agent, setAgent] = useState<NewAgent | null>(null);
  const [preset, setPreset] = useState<AutoReplyPreset>("manual");
  const [aiRead, setAiRead] = useState<AiRead | null>(null);
  const [autoResult, setAutoResult] = useState<AutoResult | null>(null);

  // Picking up again after a reload or a later visit: from the server's
  // agents and permissions and this browser's keys, never a flag kept here.
  useEffect(() => {
    if (agent || !resumeId || !agentsQuery.data || !grantsQuery.isFetched) return;
    const found = agentsQuery.data.agents.find((a) => a.id === resumeId);
    if (!found) {
      setScreen("ai");
      return;
    }
    let cancelled = false;
    void hasSigningPrivateKeyMaterial(found.did).then((keyHere) => {
      if (cancelled) return;
      setAgent({ id: found.id, aid: found.aid, did: found.did, label: found.label });
      const at = resumeStep({ ai, keyHere, allowed: allowedGrant(grantsQuery.data?.grants, found.aid) !== null });
      if (at === "elsewhere" || at === "ai") {
        setScreen(at);
      } else {
        setResumeAt(at);
        setScreen("resume");
      }
    });
    return () => {
      cancelled = true;
    };
  }, [agent, resumeId, agentsQuery.data, grantsQuery.isFetched, grantsQuery.data, ai]);

  const flow = stepsFor(ai ?? "claude_code");
  const isStep = (s: Screen | null): s is Step => s !== null && (flow as string[]).includes(s);
  const next = (from: Step): Step => flow[Math.min(flow.indexOf(from) + 1, flow.length - 1)];
  const go = (s: Screen) => {
    setScreen(s);
    window.scrollTo({ top: 0 });
  };

  const granted = agent ? allowedGrant(grantsQuery.data?.grants, agent.aid) : null;
  const computerHere = agent
    ? computerStatus(credentialsQuery.data?.credentials ?? [], agent.aid, Date.now()).kind !== "browser"
    : false;

  return (
    <AppShell title={t("firstRun.title")} activePath="/onboarding">
      <section style={{ padding: 24, maxWidth: 640 }} data-testid="first-run">
        {isStep(screen) ? <StepBar position={flow.indexOf(screen) + 1} total={flow.length} /> : null}

        {screen === "ai" ? (
          <AiStep
            ai={ai}
            onChange={setAi}
            onNext={() => {
              if (ai !== "web" && isPhone()) return go("mobile");
              if (!agent) return go("name");
              go(ai === "web" ? "replies" : "connect");
            }}
          />
        ) : null}

        {screen === "mobile" ? (
          <MobileStep
            href={onboardingHref({ ai, with: keepWith })}
            invited={keepWith !== ""}
            onWebOnly={() => {
              setAi("web");
              go("name");
            }}
            onRechoose={() => go("ai")}
          />
        ) : null}

        {screen === "name" ? (
          <NameStep
            onBack={() => go("ai")}
            onCreated={(created) => {
              setAgent(created);
              router.replace(onboardingHref({ agent: created.id, ai, with: keepWith }));
              go(next("name"));
            }}
          />
        ) : null}

        {screen === "connect" && agent && ai && ai !== "web" ? (
          <ConnectStep
            agent={agent}
            aiName={AI_NAME[ai]}
            onBack={() => go("ai")}
            onNext={() => go("replies")}
          />
        ) : null}

        {screen === "replies" && agent ? (
          <RepliesStep
            agent={agent}
            preset={preset}
            onChange={setPreset}
            onBack={() => go(ai === "web" ? "ai" : "connect")}
            onNext={() => go("test")}
          />
        ) : null}

        {screen === "test" && agent ? (
          <TestStep
            agent={agent}
            where={computerHere ? "pc" : "browser"}
            preset={preset}
            aiName={ai && ai !== "web" && granted ? AI_NAME[ai] : null}
            aiRead={aiRead}
            onAiRead={setAiRead}
            onAutoResult={setAutoResult}
            onBack={() => go("replies")}
            onNext={() => go("done")}
          />
        ) : null}

        {screen === "done" && agent ? (
          <DoneStep
            agent={agent}
            aiName={ai && ai !== "web" && granted ? AI_NAME[ai] : null}
            aiRead={aiRead}
            preset={preset}
            autoResult={autoResult}
            onConnectAi={() => {
              setAi("claude_code");
              go("connect");
            }}
            onTestAgain={() => go("test")}
            onReturn={returnTo ? () => router.push(returnTo) : undefined}
          />
        ) : null}

        {screen === "resume" && agent ? (
          <ResumeStep
            agent={agent}
            ai={ai}
            at={resumeAt}
            onContinue={() => go(resumeAt)}
            onLater={() => router.push("/")}
          />
        ) : null}

        {screen === "elsewhere" && agent ? <ElsewhereStep agent={agent} /> : null}
      </section>
    </AppShell>
  );
}

// --- steps -------------------------------------------------------------------

function AiStep({
  ai,
  onChange,
  onNext,
}: {
  ai: OnboardingAi | null;
  onChange: (ai: OnboardingAi) => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const needsPc = <span style={{ display: "block", color: "var(--warn)", fontWeight: 700 }}>{t("firstRun.ai.needsPc")}</span>;
  return (
    <div className="panel">
      <StepHeading title={t("firstRun.ai.title")} desc={t("firstRun.ai.desc")} />
      <Note>{t("firstRun.ai.pcNote")}</Note>
      <div role="radiogroup" style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 14 }}>
        <ChoiceCard selected={false} onSelect={() => undefined} disabled title={t("firstRun.ai.museTitle")} badge={t("firstRun.ai.checking")} testId="first-run-ai-muse">
          {needsPc}
          {t("firstRun.ai.checkingDesc")}
        </ChoiceCard>
        <ChoiceCard selected={false} onSelect={() => undefined} disabled title={t("firstRun.ai.desktopTitle")} badge={t("firstRun.ai.checking")} testId="first-run-ai-desktop">
          {needsPc}
          {t("firstRun.ai.checkingDesc")}
        </ChoiceCard>
        <ChoiceCard selected={ai === "claude_code"} onSelect={() => onChange("claude_code")} title={t("firstRun.ai.codeTitle")} testId="first-run-ai-claude-code">
          {needsPc}
          {t("firstRun.ai.codeDesc")}
        </ChoiceCard>
        <ChoiceCard selected={ai === "web"} onSelect={() => onChange("web")} title={t("firstRun.ai.webTitle")} badge={t("firstRun.ai.webBadge")} testId="first-run-ai-web">
          {t("firstRun.ai.webDesc")}
        </ChoiceCard>
      </div>
      <p className="item-sub" style={{ marginTop: 12 }}>
        {t("firstRun.ai.others")}{" "}
        <Link href="/help#ai" style={{ color: "var(--primary)", fontWeight: 600 }}>
          {t("firstRun.ai.othersLink")}
        </Link>
      </p>
      <Actions>
        <button className="btn primary" type="button" onClick={onNext} disabled={!ai} data-testid="first-run-next">
          {t("firstRun.next")}
        </button>
      </Actions>
    </div>
  );
}

function MobileStep({
  href,
  invited,
  onWebOnly,
  onRechoose,
}: {
  href: string;
  invited: boolean;
  onWebOnly: () => void;
  onRechoose: () => void;
}) {
  const { t } = useTranslation();
  const url = typeof window === "undefined" ? href : `${window.location.origin}${href}`;
  return (
    <div className="panel" data-testid="first-run-mobile">
      <StepHeading title={t("firstRun.mobile.title")} desc={t("firstRun.mobile.desc")} />
      <ol style={STEPS}>
        <li>
          <span style={STRONG}>{t("firstRun.mobile.step1")}</span>
          <CommandLine command={url} />
          <span className="item-sub">{t("firstRun.mobile.step1Note")}</span>
        </li>
        <li>
          <span style={STRONG}>{t("firstRun.mobile.step2")}</span>
          <span className="item-sub" style={{ display: "block" }}>
            {t("firstRun.mobile.step2Note")}
            {invited ? ` ${t("firstRun.mobile.step2Invite")}` : ""}
          </span>
        </li>
      </ol>
      <Actions>
        <button className="btn" type="button" onClick={onRechoose}>
          {t("firstRun.mobile.rechoose")}
        </button>
        <button className="btn primary" type="button" onClick={onWebOnly} data-testid="first-run-web-only">
          {t("firstRun.mobile.webOnly")}
        </button>
      </Actions>
    </div>
  );
}

function NameStep({ onBack, onCreated }: { onBack: () => void; onCreated: (agent: NewAgent) => void }) {
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
      <Note>{t("firstRun.name.keyNote")}</Note>
      {error ? <ErrorLine>{error}</ErrorLine> : null}
      <Actions>
        <button className="btn" type="button" onClick={onBack} disabled={busy}>
          {t("firstRun.back")}
        </button>
        <button className="btn primary" type="submit" disabled={busy} data-testid="first-run-create">
          {busy ? t("firstRun.name.creating") : t("firstRun.name.create")}
        </button>
      </Actions>
    </form>
  );
}

function ConnectStep({
  agent,
  aiName,
  onBack,
  onNext,
}: {
  agent: NewAgent;
  aiName: string;
  onBack: () => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const credentialsQuery = useAgentCredentialsQuery({ refetchInterval: CONNECT_POLL_MS });
  const grantsQuery = useOAuthGrantsQuery({ refetchInterval: CONNECT_POLL_MS });
  const setCloudAccess = useSetCloudAccessMutation();
  const [cloudFailed, setCloudFailed] = useState(false);
  const now = useNow(CONNECT_POLL_MS);

  const credentials: AgentCredential[] = credentialsQuery.data?.credentials ?? [];
  // "Connected" only once the computer itself reached the API, not when a
  // command said it started (docs/41 §5.2.1).
  const computer = computerStatus(credentials, agent.aid, now);
  const cloud = cloudAccessStatus(credentials, agent.aid, now);
  const url = cloud.kind === "ready" ? cloud.url : null;
  const grant = allowedGrant(grantsQuery.data?.grants, agent.aid);

  const turnOn = async (credentialId: string) => {
    setCloudFailed(false);
    try {
      await setCloudAccess.mutateAsync({ credentialId, enabled: true });
    } catch {
      setCloudFailed(true);
    }
  };

  const stage = (done: boolean, current: boolean): "done" | "now" | "later" => (done ? "done" : current ? "now" : "later");
  const pcDone = computer.kind === "connected";
  const cloudDone = url !== null;

  return (
    <div className="panel" data-testid="first-run-connect">
      <StepHeading title={t("firstRun.connect2.title")} desc={t("firstRun.connect2.desc")} />
      <ol style={STEPS}>
        <StepItem state={stage(pcDone, true)} title={t("firstRun.connect2.pcStep")}>
          {computer.kind === "connected" ? (
            <span className="item-sub" data-testid="first-run-connected">
              {t("firstRun.connect2.pcDone", { device: computer.device })}
            </span>
          ) : computer.kind === "silent" ? (
            <span className="item-sub" style={{ color: "var(--warn)" }}>
              {t("firstRun.connect2.pcSilent")}
            </span>
          ) : (
            <ConnectComputer
              agent={agent}
              onConnected={(_device, credentialId) => {
                void acknowledgeDevicesAfterConnect(queryClient, agent.aid, credentialId);
                void queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials() });
              }}
            />
          )}
        </StepItem>
        <StepItem state={stage(cloudDone, pcDone)} title={t("firstRun.connect2.cloudStep")}>
          {cloud.kind === "off" && pcDone ? (
            <>
              <span className="item-sub" style={{ display: "block" }}>
                {t("firstRun.connect2.cloudNote")}
              </span>
              <button
                className="btn"
                type="button"
                style={{ marginTop: 8 }}
                disabled={setCloudAccess.isPending}
                onClick={() => void turnOn(cloud.credentialId)}
                data-testid="first-run-cloud-on"
              >
                {t("firstRun.connect2.cloudTurnOn")}
              </button>
              {cloudFailed ? <ErrorLine>{t("firstRun.connect2.cloudFailed")}</ErrorLine> : null}
            </>
          ) : cloud.kind === "preparing" ? (
            <span className="item-sub">{t("firstRun.connect2.cloudPreparing")}</span>
          ) : cloud.kind === "ready" ? (
            <span className="item-sub">{t("firstRun.connect2.cloudReady")}</span>
          ) : null}
        </StepItem>
        <StepItem state={stage(grant !== null, cloudDone)} title={t("firstRun.connect2.addStep")}>
          {url ? <CommandLine command={`claude mcp add --transport http nexusinbox ${url}`} testId="first-run-mcp-add" /> : null}
        </StepItem>
        <StepItem state={stage(grant !== null, cloudDone)} title={t("firstRun.connect2.allowStep")}>
          {grant ? (
            <span className="item-sub" data-testid="first-run-granted">
              {t("firstRun.connect2.granted", { client: grant.client_name || aiName })}
            </span>
          ) : url ? (
            <span className="item-sub">{t("firstRun.connect2.allowDesc")}</span>
          ) : null}
        </StepItem>
      </ol>
      {url && !grant ? <Note>{t("firstRun.connect2.waitingGrant")}</Note> : null}
      <Note>{t("firstRun.connect2.oldMessages")}</Note>
      <Actions>
        <button className="btn" type="button" onClick={onBack}>
          {t("firstRun.back")}
        </button>
        {grant ? (
          <button className="btn primary" type="button" onClick={onNext} data-testid="first-run-next">
            {t("firstRun.next")}
          </button>
        ) : (
          <button className="btn" type="button" onClick={onNext} data-testid="first-run-connect-later">
            {t("firstRun.connect2.later")}
          </button>
        )}
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
      <Note>{t("firstRun.replies.whenNote")}</Note>
      {failed ? <ErrorLine>{t("firstRun.replies.saveFailed")}</ErrorLine> : null}
      <Actions>
        <button className="btn" type="button" onClick={onBack} disabled={busy}>
          {t("firstRun.back")}
        </button>
        <button className="btn primary" type="button" onClick={() => void save()} disabled={busy} data-testid="first-run-next">
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
  preset,
  aiName,
  aiRead,
  onAiRead,
  onAutoResult,
  onBack,
  onNext,
}: {
  agent: NewAgent;
  where: "browser" | "pc";
  preset: AutoReplyPreset;
  /** The connected and allowed AI, if any. */
  aiName: string | null;
  aiRead: AiRead | null;
  onAiRead: (read: AiRead) => void;
  onAutoResult: (result: AutoResult) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const { t } = useTranslation();
  const sendMessage = useSendMessageMutation();
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<{ messageId: string; recipientDid: string; at: number } | null>(null);
  const [row, setRow] = useState<MessageIndexEntry | null>(null);
  const [web, setWeb] = useState<"ok" | "no" | null>(null);
  // When the current wait started; checking again restarts it without sending again.
  const [waitFrom, setWaitFrom] = useState(0);
  const [timedOut, setTimedOut] = useState(false);

  const state = sent ? selfTestState(row, where) : null;
  const settled = state !== null && selfTestSettled(state);
  const autoSkipped = preset === "manual";

  const send = async () => {
    setSending(true);
    setError(null);
    try {
      const signingPrivateKey = await getSigningPrivateKey(agent.did);
      if (!signingPrivateKey) throw new Error(t("firstRun.test.noKey"));
      // By AID, so a connected computer's key is the one used.
      const resolved = await defaultApiClient.resolveRecipient(agent.aid);
      const plan = await planSend(resolved, agent.aid, agent.did);
      const title = t("firstRun.test.eventTitle");
      const { messageId } = await sendScheduleProposal(
        {
          senderDid: agent.did,
          signingPrivateKey,
          plan,
          subject: title,
          body: t("firstRun.test.body"),
          payload: { event_title: title, candidates: selfTestCandidates(new Date()), required_participants: [] },
        },
        sendMessage.mutateAsync,
      );
      setSent({ messageId, recipientDid: plan.recipient.did, at: Date.now() });
      setWaitFrom(Date.now());
    } catch (err) {
      setError(t("firstRun.test.failed", { error: err instanceof Error ? err.message : String(err) }));
    } finally {
      setSending(false);
    }
  };

  // Follow the one test message until nothing more happens without the person.
  useEffect(() => {
    if (!sent || settled || timedOut) return;
    const timer = setInterval(() => {
      const limit = state === "accept_pending_pc" ? COMPUTER_REPLY_TIMEOUT_MS : ARRIVAL_TIMEOUT_MS;
      if (Date.now() - waitFrom > limit) {
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
  }, [sent, settled, timedOut, state, waitFrom]);

  // Once it is here: can this browser open it?
  useEffect(() => {
    if (!row || web !== null) return;
    let cancelled = false;
    void defaultApiClient
      .getMessageContent(row.id)
      .then((content) => decryptMessageBody(content, row, false, [agent.did]))
      .then((opened) => {
        if (!cancelled) setWeb(opened.state === "readable" ? "ok" : "no");
      })
      .catch(() => {
        if (!cancelled) setWeb("no");
      });
    return () => {
      cancelled = true;
    };
  }, [row, web, agent.did]);

  const autoResult: AutoResult | null = autoSkipped
    ? "skipped"
    : settled
      ? "ok"
      : timedOut && row
        ? "not_yet"
        : null;
  useEffect(() => {
    if (autoResult) onAutoResult(autoResult);
  }, [autoResult, onAutoResult]);

  const waitedMin = Math.max(1, Math.round((state === "accept_pending_pc" ? COMPUTER_REPLY_TIMEOUT_MS : ARRIVAL_TIMEOUT_MS) / 60_000));

  return (
    <div className="panel">
      <StepHeading title={t("firstRun.test.title")} desc={t("firstRun.test.desc")} />
      {!sent ? (
        <div style={{ marginTop: 14 }}>
          <button className="btn primary" type="button" onClick={() => void send()} disabled={sending} data-testid="first-run-send-test">
            {sending ? t("firstRun.test.sending") : error ? t("firstRun.test.retry") : t("firstRun.test.send")}
          </button>
          {error ? <ErrorLine>{error}</ErrorLine> : null}
        </div>
      ) : (
        <ul style={CHECKS} aria-live="polite" data-testid="first-run-test-result">
          <CheckRow
            state={row ? "ok" : timedOut ? "warn" : "wait"}
            title={t("firstRun.check.received")}
            sub={row ? t("firstRun.check.receivedOk") : timedOut ? t("firstRun.test.timeout") : t("firstRun.check.waiting")}
          />
          <CheckRow
            state={web === "ok" ? "ok" : web === "no" ? "warn" : "wait"}
            title={t("firstRun.check.web")}
            sub={web === "ok" ? t("firstRun.check.webOk") : web === "no" ? t("firstRun.check.webNo") : t("firstRun.check.waiting")}
          />
          {aiName ? (
            <>
              <CheckRow state="ok" title={t("firstRun.check.grant", { ai: aiName })} sub={t("firstRun.check.grantOk", { ai: aiName })} />
              <CheckRow
                state={aiRead === "shown" ? "ok" : aiRead === "not_shown" ? "warn" : "wait"}
                title={t("firstRun.check.aiRead", { ai: aiName })}
                sub={
                  aiRead === "shown"
                    ? t("firstRun.check.aiShownDone")
                    : aiRead === "not_shown"
                      ? t("firstRun.check.aiNotShownDone")
                      : t("firstRun.check.aiReadAsk", { ai: aiName })
                }
              >
                {aiRead === null || aiRead === "later" ? (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8 }}>
                    <button className="btn" type="button" onClick={() => onAiRead("shown")} data-testid="first-run-ai-shown">
                      {t("firstRun.check.aiShown")}
                    </button>
                    <button className="btn" type="button" onClick={() => onAiRead("not_shown")}>
                      {t("firstRun.check.aiNotShown")}
                    </button>
                    {aiRead === null ? (
                      <button className="btn" type="button" onClick={() => onAiRead("later")}>
                        {t("firstRun.check.aiLater")}
                      </button>
                    ) : null}
                  </div>
                ) : null}
              </CheckRow>
            </>
          ) : null}
          <CheckRow
            state={autoSkipped ? "none" : settled ? "ok" : timedOut ? "warn" : "wait"}
            title={t("firstRun.check.auto")}
            sub={
              autoSkipped
                ? t("firstRun.check.autoSkipped")
                : timedOut && !settled
                  ? t("firstRun.check.autoNotYet", { min: waitedMin })
                  : state
                    ? t(TEST_LINES[state])
                    : t("firstRun.check.waiting")
            }
          >
            {!autoSkipped && timedOut && !settled ? (
              <button
                className="btn"
                type="button"
                style={{ marginTop: 8 }}
                onClick={() => {
                  setTimedOut(false);
                  setWaitFrom(Date.now());
                }}
              >
                {t("firstRun.check.checkAgain")}
              </button>
            ) : null}
          </CheckRow>
        </ul>
      )}
      <Actions>
        <button className="btn" type="button" onClick={onBack} disabled={sending}>
          {t("firstRun.back")}
        </button>
        <button className={sent ? "btn primary" : "btn"} type="button" onClick={onNext} data-testid="first-run-next">
          {sent ? t("firstRun.next") : t("firstRun.test.skip")}
        </button>
      </Actions>
    </div>
  );
}

function DoneStep({
  agent,
  aiName,
  aiRead,
  preset,
  autoResult,
  onConnectAi,
  onTestAgain,
  onReturn,
}: {
  agent: NewAgent;
  aiName: string | null;
  aiRead: AiRead | null;
  preset: AutoReplyPreset;
  autoResult: AutoResult | null;
  onConnectAi: () => void;
  onTestAgain: () => void;
  /** Back to the message that brought them here, when there is one. */
  onReturn?: () => void;
}) {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const full = agentsQuery.data?.agents.find((a) => a.id === agent.id);
  const [inviting, setInviting] = useState(false);
  const readLine =
    aiRead === "shown"
      ? t("firstRun.check.aiShownDone")
      : aiRead === "not_shown"
        ? t("firstRun.check.aiNotShownDone")
        : t("firstRun.check.aiLaterDone");
  return (
    <div className="panel" data-testid="first-run-done">
      <StepHeading
        title={aiName ? t("firstRun.done2.titleReady") : t("firstRun.done2.titleWeb")}
        desc={aiName ? "" : t("firstRun.done2.descWeb")}
      />
      <ul style={CHECKS}>
        <CheckRow state="ok" title={t("firstRun.done2.agent", { name: agent.label })} sub={t("firstRun.done2.agentOk")} />
        {aiName ? (
          <>
            <CheckRow state="ok" title={t("firstRun.check.grant", { ai: aiName })} sub={t("firstRun.done2.aiOk")} />
            <CheckRow
              state={aiRead === "shown" ? "ok" : aiRead === "not_shown" ? "warn" : "wait"}
              title={t("firstRun.check.aiRead", { ai: aiName })}
              sub={readLine}
            >
              {aiRead !== "shown" ? (
                <button className="btn" type="button" style={{ marginTop: 8 }} onClick={onTestAgain}>
                  {t("firstRun.check.checkAgain")}
                </button>
              ) : null}
            </CheckRow>
          </>
        ) : (
          <CheckRow state="none" title={t("firstRun.done2.aiNone")} sub={t("firstRun.done2.aiNoneSub")}>
            <button className="btn" type="button" style={{ marginTop: 8 }} onClick={onConnectAi} data-testid="first-run-connect-ai">
              {t("firstRun.done2.connectAi")}
            </button>
          </CheckRow>
        )}
        <CheckRow state="ok" title={t("firstRun.done2.scope")} sub={t(PRESET_TEXT[preset].title)}>
          <Link href={`/settings/agents?agent=${encodeURIComponent(agent.did)}`} style={{ color: "var(--primary)", fontWeight: 600, fontSize: "var(--fs-sm)" }}>
            {t("firstRun.done2.change")}
          </Link>
        </CheckRow>
        {preset !== "manual" ? (
          <CheckRow
            state={autoResult === "ok" ? "ok" : "warn"}
            title={t("firstRun.done2.autoTest")}
            sub={autoResult === "ok" ? t("firstRun.test.acceptedPc") : t("firstRun.check.aiLaterDone")}
          >
            {autoResult !== "ok" ? (
              <button className="btn" type="button" style={{ marginTop: 8 }} onClick={onTestAgain}>
                {t("firstRun.check.checkAgain")}
              </button>
            ) : null}
          </CheckRow>
        ) : null}
      </ul>
      {full && inviting ? <DoneInvite agent={full} onLater={() => setInviting(false)} /> : null}
      <Actions>
        {!inviting ? (
          <button className="btn" type="button" onClick={() => setInviting(true)}>
            {t("firstRun.done2.invite")}
          </button>
        ) : null}
        {onReturn ? (
          <button className="btn primary" type="button" onClick={onReturn} data-testid="first-run-return">
            {t("firstRun.done.toMessage")}
          </button>
        ) : (
          <Link href="/" className="btn primary" data-testid="first-run-to-home">
            {t("firstRun.done2.toHome")}
          </Link>
        )}
      </Actions>
    </div>
  );
}

function ResumeStep({
  agent,
  ai,
  at,
  onContinue,
  onLater,
}: {
  agent: NewAgent;
  ai: OnboardingAi | null;
  at: Step;
  onContinue: () => void;
  onLater: () => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="panel" data-testid="first-run-resume">
      <StepHeading title={t("firstRun.resume.title")} desc={t("firstRun.resume.desc")} />
      <ul style={CHECKS}>
        {ai ? (
          <CheckRow
            state="ok"
            title={t("firstRun.resume.rowAi")}
            sub={ai === "web" ? t("firstRun.ai.webTitle") : AI_NAME[ai]}
          />
        ) : null}
        <CheckRow state="ok" title={t("firstRun.resume.rowAgent", { name: agent.label })} sub={t("firstRun.resume.rowAgentDone")} />
        <CheckRow state="wait" title={t("firstRun.resume.rowNext", { step: t(`firstRun.stepNames.${at}`) })} sub="" />
      </ul>
      <Actions>
        <button className="btn" type="button" onClick={onLater}>
          {t("firstRun.resume.later")}
        </button>
        <button className="btn primary" type="button" onClick={onContinue} data-testid="first-run-continue">
          {t("firstRun.resume.continue")}
        </button>
      </Actions>
    </div>
  );
}

function ElsewhereStep({ agent }: { agent: NewAgent }) {
  const { t } = useTranslation();
  return (
    <div className="panel" data-testid="first-run-elsewhere">
      <StepHeading title={t("firstRun.elsewhere.title")} desc={t("firstRun.elsewhere.desc", { name: agent.label })} />
      <Note>{t("firstRun.elsewhere.note")}</Note>
      <Actions>
        <Link href="/" className="btn primary">
          {t("firstRun.elsewhere.toHome")}
        </Link>
      </Actions>
    </div>
  );
}

function DoneInvite({ agent, onLater }: { agent: Agent; onLater: () => void }) {
  const { t } = useTranslation();
  const name = useInviteName(agent);
  return <InviteCard agent={agent} title={t("share.inviteTitle")} desc={t("share.inviteDesc", { name })} onLater={onLater} />;
}

// --- pieces ------------------------------------------------------------------

const STEPS = { listStyle: "none", padding: 0, margin: "14px 0 0", display: "grid", gap: 14 } as const;
const CHECKS = {
  listStyle: "none",
  padding: 0,
  margin: "14px 0 0",
  border: "1px solid var(--line-strong)",
  borderRadius: 14,
  overflow: "hidden",
} as const;

function StepBar({ position, total }: { position: number; total: number }) {
  const { t } = useTranslation();
  return (
    <div style={{ marginBottom: 14 }} data-testid="first-run-step">
      <p className="item-sub" style={{ margin: 0, fontWeight: 600 }}>
        {t("firstRun.stepOf", { current: position, total })}
      </p>
      <div style={{ display: "flex", gap: 4, marginTop: 6 }} aria-hidden>
        {Array.from({ length: total }, (_, i) => (
          <span
            key={i}
            style={{ flex: 1, height: 4, borderRadius: 2, background: i < position ? "var(--primary)" : "var(--line-strong)" }}
          />
        ))}
      </div>
    </div>
  );
}

function StepItem({ state, title, children }: { state: "done" | "now" | "later"; title: string; children?: ReactNode }) {
  const mark = state === "done" ? "✓" : "";
  return (
    <li style={{ display: "grid", gridTemplateColumns: "24px minmax(0, 1fr)", gap: "2px 12px" }} data-state={state}>
      <span
        aria-hidden
        style={{
          width: 24,
          height: 24,
          borderRadius: "50%",
          display: "grid",
          placeItems: "center",
          fontWeight: 800,
          fontSize: "var(--fs-xs)",
          background: state === "done" ? "var(--ok-soft)" : state === "now" ? "var(--primary)" : "var(--surface-alt)",
          color: state === "done" ? "var(--ok)" : state === "now" ? "var(--on-primary)" : "var(--text-muted)",
        }}
      >
        {mark || "•"}
      </span>
      <div style={{ minWidth: 0, opacity: state === "later" ? 0.6 : 1 }}>
        <span style={STRONG}>{title}</span>
        {children ? <div>{children}</div> : null}
      </div>
    </li>
  );
}

function CheckRow({
  state,
  title,
  sub,
  children,
}: {
  state: "ok" | "warn" | "wait" | "none";
  title: string;
  sub: string;
  children?: ReactNode;
}) {
  const icon = { ok: "✓", warn: "!", wait: "?", none: "–" }[state];
  const colors = {
    ok: ["var(--ok-soft)", "var(--ok)"],
    warn: ["var(--warn-soft)", "var(--warn)"],
    wait: ["var(--primary-soft)", "var(--primary-text)"],
    none: ["var(--surface-alt)", "var(--text-muted)"],
  }[state];
  return (
    <li
      style={{ display: "grid", gridTemplateColumns: "26px minmax(0, 1fr)", gap: "2px 10px", padding: "12px 14px", borderTop: "1px solid var(--line)" }}
      data-check={state}
    >
      <span
        aria-hidden
        style={{ width: 24, height: 24, borderRadius: "50%", display: "grid", placeItems: "center", fontWeight: 800, fontSize: "var(--fs-xs)", background: colors[0], color: colors[1] }}
      >
        {icon}
      </span>
      <div style={{ minWidth: 0 }}>
        <span style={STRONG}>{title}</span>
        {sub ? (
          <p className="item-sub" style={{ margin: "2px 0 0" }}>
            {sub}
          </p>
        ) : null}
        {children}
      </div>
    </li>
  );
}

function Note({ children }: { children: ReactNode }) {
  return (
    <p style={{ margin: "14px 0 0", padding: "10px 12px", borderRadius: 12, background: "var(--surface-alt)", fontSize: "var(--fs-sm)" }}>
      {children}
    </p>
  );
}

function StepHeading({ title, desc }: { title: string; desc: string }) {
  return (
    <>
      <h2 style={{ margin: 0, fontSize: "var(--fs-lg)" }}>{title}</h2>
      {desc ? (
        <p className="item-sub" style={{ marginTop: 6 }}>
          {desc}
        </p>
      ) : null}
    </>
  );
}

function Actions({ children }: { children: ReactNode }) {
  return <div style={{ display: "flex", flexWrap: "wrap", marginTop: 18, gap: 8, justifyContent: "flex-end" }}>{children}</div>;
}
