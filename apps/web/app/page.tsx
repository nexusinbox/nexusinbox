"use client";

// メッセージ (docs/35 §2): one row per conversation partner, and the
// conversation as chat bubbles. Wide screens show both side by side;
// phones show the list, then the conversation full screen.

import { useRouter, useSearchParams } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { Suspense, useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "./_components/AppShell";
import { RefreshIconButton } from "./_components/RefreshIconButton";
import { InboxAgentBar } from "./_components/InboxAgentBar";
import {
  Avatar,
  ConversationView,
  EmptyConversationView,
} from "./_components/messages/ConversationView";
import { parseProtocolBody } from "./_components/protocol/parseProtocolBody";
import { useTranslation } from "../lib/i18n";
import { formatListTimestamp } from "../lib/format/messageTime";
import {
  formatPartyLabel,
  indexContactsByDid,
  resolveParticipantLabel,
} from "../lib/api/labels";
import { defaultApiClient } from "../lib/api/client";
import {
  queryKeys as apiQueryKeys,
  useAgentsQuery,
  useContactsQuery,
  useMessagesQuery,
} from "../lib/api/hooks";
import type { MessageContentResponse } from "../lib/api/types";
import { hasRecipientPrivateKey } from "../lib/crypto/recipient-keyring";
import {
  groupConversations,
  previewSnippet,
  relativeAge,
  rowsForView,
  type Conversation,
} from "../lib/inbox/conversations";
import { candidateDids, decryptMessageBody } from "../lib/inbox/decrypt-message";

// Bounded concurrency for the preview decrypt below. Picked 4 by hand:
// the bottleneck in practice is the X25519 keystore unwrap, which is
// cheap but still hits IndexedDB, so running more than a handful in
// parallel doesn't speed anything up and just inflates the number of
// in-flight `/messages/:id/content` fetches.
const PREVIEW_DECRYPT_CONCURRENCY = 4;

// One page of each list. Older messages than this are not grouped in.
const MESSAGES_PER_LIST = 100;

/** The latest message's one-line preview, once this browser tried it. */
type Preview = {
  state: "readable" | "no_key" | "error";
  text: string;
  protocolType: string | null;
};

// Shared outer frame for the two inbox onboarding variants. Kept
// local to this file (rather than exported to a shared component
// module) because the copy blocks are very specific to the
// first-time-user "what do I do now?" moment and don't get reused
// elsewhere.
function InboxWelcomeFrame({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="empty-state"
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "48px 32px",
        gap: 20,
        textAlign: "center",
      }}
    >
      <div
        style={{
          maxWidth: 560,
          display: "flex",
          flexDirection: "column",
          gap: 18,
          alignItems: "stretch",
        }}
      >
        {children}
      </div>
    </div>
  );
}

/**
 * Empty-inbox state when the authenticated user has no agents yet.
 * Replaces the old "(no body to show)" placeholder with a three-step
 * "what do I do first" card so a fresh login lands on a useful page
 * rather than an intimidatingly blank one. Help live on `/help`
 * already; this is the funnel into the agent-creation flow.
 */
function WelcomeNoAgents({
  t,
  onCreateAgent,
  onOpenHelp,
}: {
  t: (key: string) => string;
  onCreateAgent: () => void;
  onOpenHelp: () => void;
}) {
  return (
    <InboxWelcomeFrame>
      <h2 style={{ margin: 0, fontSize: 22, fontWeight: 600 }}>
        👋 {t("inbox.welcomeTitle")}
      </h2>
      <p style={{ margin: 0, color: "var(--text-muted, #5f6368)", lineHeight: 1.6 }}>
        {t("inbox.welcomeDesc")}
      </p>
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 12,
          textAlign: "left",
          marginTop: 8,
        }}
      >
        <div>
          <p style={{ margin: 0, fontWeight: 600 }}>{t("inbox.welcomeStep1Title")}</p>
          <p style={{ margin: "4px 0 10px 0", color: "var(--text-muted, #5f6368)", fontSize: 14 }}>
            {t("inbox.welcomeStep1Desc")}
          </p>
          <button
            className="btn primary"
            type="button"
            onClick={onCreateAgent}
            data-testid="welcome-create-agent"
          >
            {t("inbox.welcomeStep1Cta")} →
          </button>
        </div>
        <div>
          <p style={{ margin: 0, fontWeight: 600 }}>{t("inbox.welcomeStep2Title")}</p>
          <p style={{ margin: "4px 0 0 0", color: "var(--text-muted, #5f6368)", fontSize: 14 }}>
            {t("inbox.welcomeStep2Desc")}
          </p>
        </div>
        <div>
          <p style={{ margin: 0, fontWeight: 600 }}>{t("inbox.welcomeStep3Title")}</p>
          <p style={{ margin: "4px 0 10px 0", color: "var(--text-muted, #5f6368)", fontSize: 14 }}>
            {t("inbox.welcomeStep3Desc")}
          </p>
          <button
            className="btn"
            type="button"
            onClick={onOpenHelp}
            data-testid="welcome-open-help"
          >
            {t("inbox.welcomeStep3Cta")} →
          </button>
        </div>
      </div>
    </InboxWelcomeFrame>
  );
}

/**
 * Empty-inbox state when the user has at least one agent but no
 * messages yet. Surfaces their first AID for copy-to-clipboard +
 * offers a "send yourself a test" shortcut so the inbox feels
 * inhabited after ~30 seconds rather than staying empty until a
 * third party actually sends them something.
 */
function WelcomeNoMessages({
  aid,
  t,
  onSelfSend,
  onManageAgents,
}: {
  aid: string;
  t: (key: string) => string;
  onSelfSend: () => void;
  onManageAgents: () => void;
}) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(aid);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard permission denied — keep the button clickable so
      // the user can select + manual-copy from the input instead.
    }
  }
  return (
    <InboxWelcomeFrame>
      <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>
        📨 {t("inbox.noMessagesTitle")}
      </h2>
      <p style={{ margin: 0, color: "var(--text-muted, #5f6368)", lineHeight: 1.6 }}>
        {t("inbox.noMessagesDesc")}
      </p>
      <div
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          padding: "8px 12px",
          borderRadius: 8,
          border: "1px solid var(--border, rgba(128,128,128,0.28))",
          background: "rgba(66, 133, 244, 0.04)",
        }}
      >
        <code
          style={{
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontFamily: "ui-monospace, monospace",
            fontSize: 13,
            textAlign: "left",
          }}
          title={aid}
        >
          {aid}
        </code>
        <button
          className="btn"
          type="button"
          onClick={() => void copy()}
          data-testid="welcome-copy-aid"
          style={{ flexShrink: 0 }}
        >
          {copied ? t("inbox.noMessagesCopied") : t("inbox.noMessagesCopyAid")}
        </button>
      </div>
      <div style={{ display: "flex", gap: 8, justifyContent: "center", flexWrap: "wrap" }}>
        <button
          className="btn primary"
          type="button"
          onClick={onSelfSend}
          data-testid="welcome-self-send"
        >
          {t("inbox.noMessagesSelfSend")} →
        </button>
        <button
          className="btn"
          type="button"
          onClick={onManageAgents}
          data-testid="welcome-manage-agents"
        >
          {t("inbox.noMessagesMoreAgents")}
        </button>
      </div>
    </InboxWelcomeFrame>
  );
}

export default function MessagesPage() {
  return (
    <Suspense fallback={null}>
      <MessagesPageInner />
    </Suspense>
  );
}

function MessagesPageInner() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const { t, locale } = useTranslation();
  const archiveView = searchParams.get("view") === "archive";
  // /?with=<DID or AID>&as=<own agent DID>: open that conversation (from
  // 新しい会話), or an empty one when there are no messages yet.
  const withParam = archiveView ? "" : (searchParams.get("with") ?? "").trim();
  const asParam = searchParams.get("as") ?? "";

  // "all", "unread", or an own agent's DID.
  const [chip, setChip] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [activeKey, setActiveKey] = useState<string>("");
  const [mobileView, setMobileView] = useState<"list" | "detail">(
    withParam ? "detail" : "list",
  );
  const [previews, setPreviews] = useState<Record<string, Preview>>({});

  // Received messages (by folder) and everything the person's agents sent;
  // sent messages live inside the conversations.
  const receivedQuery = useMessagesQuery({
    agentDid: "all",
    status: "all",
    folder: archiveView ? "archive" : "inbox",
    page: 1,
    perPage: MESSAGES_PER_LIST,
  });
  const sentQuery = useMessagesQuery({
    agentDid: "all",
    status: "all",
    folder: "sent",
    page: 1,
    perPage: MESSAGES_PER_LIST,
  });

  const agentsQuery = useAgentsQuery();
  const agentList = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const agentCount = agentsQuery.data?.agents.length ?? null;
  const firstAgentAid = agentsQuery.data?.agents?.[0]?.aid ?? null;

  const contactsQuery = useContactsQuery();
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );

  const conversations = useMemo(
    () =>
      groupConversations(
        rowsForView(
          receivedQuery.data?.messages ?? [],
          sentQuery.data?.messages ?? [],
          archiveView ? "archive" : "main",
        ),
        agentList,
      ),
    [receivedQuery.data, sentQuery.data, archiveView, agentList],
  );

  // "Name(Agent)" → "Name さんの Agent" (docs/35 §3); a contact's own
  // name still wins inside resolveParticipantLabel.
  const nameFor = useMemo(
    () => (did: string, serverLabel: string | null) =>
      formatPartyLabel(resolveParticipantLabel(did, serverLabel, contactsByDid, agentList), t),
    [contactsByDid, agentList, t],
  );

  // The counterpart's name, from the newest row that carries a server label.
  const counterpartName = (c: Conversation) => {
    const labelled = [...c.messages]
      .reverse()
      .map((m) => (m.mine ? m.entry.recipient_label : m.entry.sender_label))
      .find(Boolean);
    return nameFor(c.counterpartDid, labelled ?? null);
  };

  // "Name(Agent)" from a contact or the server → "Name さんのエージェント".
  const counterpartSubLine = (c: Conversation) => {
    const contact = contactsByDid.get(c.counterpartDid);
    if (contact?.readable && contact.person_name) {
      return t("messages.subPerson", { person: contact.person_name });
    }
    const labelled = [...c.messages]
      .reverse()
      .map((m) => (m.mine ? m.entry.recipient_label : m.entry.sender_label))
      .find(Boolean);
    const person = labelled?.match(/^(.+?)\(.*\)$/)?.[1];
    return person ? t("messages.subPerson", { person }) : null;
  };

  // A contact, or one of the person's own agents (grouping folds their
  // DIDs into the agent's first DID).
  const isKnown = (did: string) =>
    contactsByDid.has(did) || agentList.some((a) => a.did === did);

  const previewText = (c: Conversation): string => {
    const p = previews[c.latest.entry.id];
    let text: string;
    if (!p) text = t("inbox.previewLoading");
    else if (p.state === "readable") text = p.text || t("inbox.previewEmpty");
    else if (c.latest.mine) text = t("messages.previewMineLocked");
    else if (p.state === "no_key") text = t("inbox.unavailableOnThisDevicePreview");
    else text = t("inbox.previewUnavailable");
    return c.latest.mine ? t("messages.you", { text }) : text;
  };

  const visible = useMemo(() => {
    const keyword = searchQuery.trim().toLowerCase();
    return conversations.filter((c) => {
      if (chip === "unread" && c.unread === 0) return false;
      if (chip !== "all" && chip !== "unread" && c.ownAgent?.did !== chip) return false;
      if (!keyword) return true;
      const p = previews[c.latest.entry.id];
      const haystack = [counterpartName(c), p?.state === "readable" ? p.text : ""]
        .join(" ")
        .toLowerCase();
      return haystack.includes(keyword);
    });
    // counterpartName reads contacts/agents, already covered by nameFor.
  }, [conversations, chip, searchQuery, previews, nameFor]);

  const active = conversations.find((c) => c.key === activeKey) ?? null;

  // The `with` counterpart as a DID: as given, an own agent's AID, or
  // resolved on the server (an AID, to its current DID).
  const [withTarget, setWithTarget] = useState<
    { input: string; did: string | null; label: string | null; failed: boolean } | null
  >(null);
  useEffect(() => {
    if (!withParam) {
      setWithTarget(null);
      return;
    }
    if (withParam.startsWith("did:")) {
      setWithTarget({ input: withParam, did: withParam, label: null, failed: false });
      return;
    }
    const own = agentList.find((a) => a.aid === withParam);
    if (own) {
      setWithTarget({ input: withParam, did: own.did, label: own.label, failed: false });
      return;
    }
    let cancelled = false;
    setWithTarget({ input: withParam, did: null, label: null, failed: false });
    defaultApiClient
      .resolveRecipient(withParam)
      .then((resolved) => {
        if (!cancelled) {
          setWithTarget({ input: withParam, did: resolved.did, label: resolved.label, failed: false });
        }
      })
      .catch(() => {
        if (!cancelled) setWithTarget({ input: withParam, did: null, label: null, failed: true });
      });
    return () => {
      cancelled = true;
    };
  }, [withParam, agentList]);

  const withOwnAgent = withParam
    ? (agentList.find((a) => a.did === asParam || a.dids?.includes(asParam)) ?? agentList[0])
    : undefined;
  const withDid = withTarget?.did ?? null;
  const withConversation =
    withDid && withOwnAgent
      ? (conversations.find((c) => {
          if (c.ownAgent?.did !== withOwnAgent.did) return false;
          if (c.counterpartDid === withDid) return true;
          // Another of the person's agents: grouping folds its DIDs.
          const agent = agentList.find((a) => a.did === c.counterpartDid);
          return Boolean(agent?.dids?.includes(withDid));
        }) ?? null)
      : null;

  // Select it once found (also right after the first message is sent).
  useEffect(() => {
    if (withConversation) {
      setActiveKey(withConversation.key);
      setMobileView("detail");
    }
  }, [withConversation?.key]);

  // The conversation went away (archived, or moved to another view).
  useEffect(() => {
    if (activeKey && !active && !receivedQuery.isLoading && !sentQuery.isLoading) {
      setActiveKey("");
      setMobileView("list");
    }
  }, [activeKey, active, receivedQuery.isLoading, sentQuery.isLoading]);

  // Decrypt the latest message of each visible conversation for its
  // preview, a few at a time. Seeds the content cache so opening the
  // conversation does not fetch again. Skips messages this browser has no
  // key for (an agent that runs on a computer) without fetching. Each
  // message is queued once; runs are not cancelled when a preview lands,
  // only when the page goes away.
  const keyPresence = useRef(new Map<string, boolean>());
  const queuedRef = useRef(new Set<string>());
  const aliveRef = useRef(true);
  useEffect(() => {
    aliveRef.current = true;
    return () => {
      aliveRef.current = false;
    };
  }, []);
  useEffect(() => {
    const queue = visible.filter((c) => !queuedRef.current.has(c.latest.entry.id));
    if (queue.length === 0) return;
    for (const c of queue) queuedRef.current.add(c.latest.entry.id);

    const hasKey = async (dids: string[]) => {
      for (const did of dids) {
        let has = keyPresence.current.get(did);
        if (has === undefined) {
          has = await hasRecipientPrivateKey(did);
          keyPresence.current.set(did, has);
        }
        if (has) return true;
      }
      return false;
    };

    const worker = async () => {
      while (aliveRef.current) {
        const c = queue.shift();
        if (!c) return;
        const { entry, mine } = c.latest;
        let preview: Preview;
        try {
          if (!(await hasKey(candidateDids(entry, mine, c.ownDids)))) {
            preview = { state: "no_key", text: "", protocolType: null };
          } else {
            const content = await queryClient.fetchQuery<MessageContentResponse>({
              queryKey: apiQueryKeys.messageContent(entry.id),
              queryFn: () => defaultApiClient.getMessageContent(entry.id),
              staleTime: 30_000,
            });
            const body = await decryptMessageBody(content, entry, mine, c.ownDids);
            if (body.state === "readable") {
              const parsed = parseProtocolBody(body.text, content.content_type ?? null);
              preview = {
                state: "readable",
                text: previewSnippet(parsed?.body ?? body.text),
                protocolType: parsed?.protocol?.type ?? null,
              };
            } else {
              preview = { state: body.state, text: "", protocolType: null };
            }
          }
        } catch {
          preview = { state: "error", text: "", protocolType: null };
        }
        if (!aliveRef.current) return;
        setPreviews((prev) => ({ ...prev, [entry.id]: preview }));
      }
    };
    void Promise.all(Array.from({ length: PREVIEW_DECRYPT_CONCURRENCY }, worker));
  }, [visible, queryClient]);

  const openConversation = (key: string) => {
    setActiveKey(key);
    setMobileView("detail");
  };

  const timeText = (iso: string) => {
    const age = relativeAge(iso);
    switch (age.kind) {
      case "now":
        return t("messages.timeNow");
      case "minutes":
        return t("messages.timeMinutes", { n: age.n });
      case "hours":
        return t("messages.timeHours", { n: age.n });
      case "yesterday":
        return t("messages.timeYesterday");
      default:
        return formatListTimestamp(iso, { locale });
    }
  };

  const loading = receivedQuery.isLoading || sentQuery.isLoading;
  const fetchError = receivedQuery.error || sentQuery.error;
  const showWelcomeNoAgents = !archiveView && agentCount === 0;
  const showWelcomeNoMessages =
    !archiveView &&
    !withParam &&
    !loading &&
    !fetchError &&
    agentCount !== null &&
    agentCount > 0 &&
    conversations.length === 0 &&
    firstAgentAid;

  const chips: Array<{ key: string; label: string }> = [
    { key: "all", label: t("messages.chipAll") },
    ...(agentList.length >= 2 ? agentList.map((a) => ({ key: a.did, label: a.label })) : []),
    { key: "unread", label: t("messages.chipUnread") },
  ];

  return (
    <AppShell
      title={archiveView ? t("inbox.archiveTitle") : t("inbox.title")}
      activePath={archiveView ? "/?view=archive" : "/"}
      rightAction={
        <RefreshIconButton
          onClick={() => void queryClient.invalidateQueries({ queryKey: ["messages"] })}
          label={t("inbox.refresh")}
        />
      }
      searchValue={searchQuery}
      searchPlaceholder={t("topbar.searchPlaceholder")}
      onSearchChange={setSearchQuery}
    >
      {/* The auto-reply note, and the browser-side auto-reply itself: it
          runs while this screen is open, so it stays mounted. */}
      <InboxAgentBar agents={agentList} />

      {showWelcomeNoAgents ? (
        // First-time user, no agents yet → the "what do I do first" card.
        <WelcomeNoAgents
          t={t}
          onCreateAgent={() => router.push("/onboarding")}
          onOpenHelp={() => router.push("/help")}
        />
      ) : showWelcomeNoMessages && firstAgentAid ? (
        // Agents set up, but no messages yet → share the address, or test.
        <WelcomeNoMessages
          aid={firstAgentAid}
          t={t}
          onSelfSend={() => router.push(`/compose?to=${encodeURIComponent(firstAgentAid)}`)}
          onManageAgents={() => router.push("/settings/agents")}
        />
      ) : (
        <section className={`dm-layout mobile-${mobileView}`}>
          <aside className="dm-list">
            <div className="dm-chips" role="tablist" aria-label={t("messages.chipsLabel")}>
              {chips.map((c) => (
                <button
                  key={c.key}
                  type="button"
                  role="tab"
                  aria-selected={chip === c.key}
                  className={"dm-chip" + (chip === c.key ? " on" : "")}
                  onClick={() => setChip(c.key)}
                >
                  {c.label}
                </button>
              ))}
            </div>
            {fetchError ? (
              <div className="inbox-fetch-error" role="alert">
                {t("inbox.fetchError")}
              </div>
            ) : null}
            {loading ? (
              <div className="dm-empty">{t("inbox.loading")}</div>
            ) : visible.length === 0 ? (
              <div className="dm-empty">
                {conversations.length === 0
                  ? archiveView
                    ? t("inbox.archiveEmpty")
                    : t("inbox.emptyMessage")
                  : t("messages.noMatch")}
              </div>
            ) : (
              visible.map((c) => {
                const name = counterpartName(c);
                const protocolType = previews[c.latest.entry.id]?.protocolType ?? null;
                // Not a contact (nor one of the person's own agents); no tag
                // when the name already says so.
                const unknown =
                  !isKnown(c.counterpartDid) && name !== t("messages.tagUnknown");
                return (
                  <button
                    type="button"
                    key={c.key}
                    className={
                      "dm-row" +
                      (c.unread > 0 ? " unread" : "") +
                      (c.key === activeKey ? " active" : "")
                    }
                    onClick={() => openConversation(c.key)}
                    data-testid="dm-row"
                  >
                    <Avatar did={c.counterpartDid} name={name} />
                    <span className="dm-row-body">
                      <span className="dm-line1">
                        <span className="dm-name">{name}</span>
                        {agentList.length >= 2 && c.ownAgent ? (
                          <span className="dm-to">
                            {t("messages.toAgent", { agent: c.ownAgent.label })}
                          </span>
                        ) : null}
                        <span className="dm-time">{timeText(c.latest.entry.created_at)}</span>
                      </span>
                      <span className="dm-preview">{previewText(c)}</span>
                      {protocolType || c.autoReplied || unknown ? (
                        <span className="dm-tags">
                          {protocolType === "schedule_negotiation" ? (
                            <span className="dm-tag sched">{t("messages.tagSchedule")}</span>
                          ) : protocolType === "task_delegation" ? (
                            <span className="dm-tag">{t("messages.tagTask")}</span>
                          ) : null}
                          {c.autoReplied ? (
                            <span className="dm-tag auto">{t("messages.tagAutoReplied")}</span>
                          ) : null}
                          {unknown ? (
                            <span className="dm-tag">{t("messages.tagUnknown")}</span>
                          ) : null}
                        </span>
                      ) : null}
                    </span>
                    {c.unread > 0 ? (
                      <span
                        className="dm-dot"
                        aria-label={t("messages.unreadCount", { count: c.unread })}
                      />
                    ) : null}
                  </button>
                );
              })
            )}
          </aside>

          <div className="dm-pane">
            {active ? (
              <ConversationView
                key={active.key}
                conversation={active}
                name={counterpartName(active)}
                subLine={counterpartSubLine(active)}
                isContact={isKnown(active.counterpartDid)}
                archiveView={archiveView}
                agents={agentList}
                nameFor={nameFor}
                onBack={() => setMobileView("list")}
                onArchived={() => {
                  setActiveKey("");
                  setMobileView("list");
                }}
              />
            ) : withParam ? (
              withTarget?.failed ? (
                <div className="dm-empty" role="alert">
                  {t("messages.recipientNotFound")}
                </div>
              ) : loading || !withDid || !withOwnAgent ? (
                <div className="dm-empty">{t("inbox.loading")}</div>
              ) : (
                <EmptyConversationView
                  key={withOwnAgent.did + "|" + withParam}
                  ownAgent={withOwnAgent}
                  counterpart={withDid}
                  avatarDid={withDid}
                  name={nameFor(withDid, withTarget?.label ?? null)}
                  subLine={
                    agentList.length >= 2
                      ? t("messages.fromAgent", { agent: withOwnAgent.label })
                      : null
                  }
                  onBack={() => setMobileView("list")}
                />
              )
            ) : (
              <div className="dm-empty">{t("messages.selectPrompt")}</div>
            )}
          </div>
        </section>
      )}
    </AppShell>
  );
}
