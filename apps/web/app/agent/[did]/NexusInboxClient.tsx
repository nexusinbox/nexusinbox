"use client";

import { CSSProperties, MouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { AppShell } from "../../_components/AppShell";
import { RefreshIconButton } from "../../_components/RefreshIconButton";
import { ConversationThread } from "../../_components/ConversationThread";
import { groupMessagesByThread } from "../../../lib/inbox/group-by-thread";
import { useRouter, useSearchParams } from "next/navigation";
import type { MessageFolderQuery } from "../../../lib/api/types";

// Phase 4.7 — values the inbox toolbar offers in its folder dropdown.
// Subset of MessageFolderQuery (excludes spam / trash / pending_approval
// / drafts which aren't part of the basic-usability surface).
const VISIBLE_FOLDERS: MessageFolderQuery[] = [
  "inbox",
  "sent",
  "archive",
  "starred",
  "all",
];

type StatusFilter = "all" | "unread";
import {
  useAgentsQuery,
  useAutoReplyPolicyQuery,
  useContactsQuery,
  useMessageContentQuery,
  useMessagesQuery,
  useUpdateMessageStatusMutation,
} from "../../../lib/api/hooks";
import { decryptEnvelopeText, ENCRYPTED_PLACEHOLDER } from "../../../lib/crypto/envelope";
import { hasRecipientPrivateKey } from "../../../lib/crypto/recipient-keyring";
import { indexContactsByDid, resolveParticipantLabel } from "../../../lib/api/labels";
import { useTranslation } from "../../../lib/i18n";
import { formatListTimestamp } from "../../../lib/format/messageTime";
import { defaultApiClient } from "../../../lib/api/client";
import { getSigningPrivateKey } from "../../../lib/crypto/signing-keyring";
import { runAutoReplyExecutor } from "../../../lib/protocol/autoReplyExecutor";
import { sendProtocolReply as realSendProtocolReply } from "../../_components/protocol/sendProtocolReply";
import { getCalendarToken } from "../../../lib/calendar/gcalAuth";
import { findFirstFreeCandidate } from "../../../lib/calendar/gcalFreebusy";

type NexusInboxClientProps = {
  did: string;
};

type ThreadView = {
  id: string;
  sender: string;
  senderDid?: string;
  recipientDid?: string;
  subject: string;
  encryptedSubject?: string;
  preview: string;
  time: string;
  unread: boolean;
  trust: number;
  source: "api" | "fallback";
  autoReplyDecision?: import("../../../lib/api/types").AutoReplyDecision;
  autoReplyReason?: string;
  autoReplySentAt?: string;
  /**
   * Number of messages collapsed into this row. 1 for a standalone
   * message, ≥2 for an actual thread. The list renders a `(N)`
   * badge next to the sender when this is > 1, mirroring Gmail.
   */
  messageCount: number;
};

// Inline formatter retired in favour of the shared
// `formatListTimestamp` (apps/web/lib/format/messageTime.ts) so the
// per-agent inbox list reads with the same Gmail-style today /
// this-year / earlier fallthrough as the main /inbox list.

export function NexusInboxClient({ did }: NexusInboxClientProps) {
  const { t, locale } = useTranslation();
  const router = useRouter();
  const agentsQuery = useAgentsQuery();
  const agents = useMemo(
    () => agentsQuery.data?.agents ?? [],
    [agentsQuery.data],
  );
  const currentAgent = useMemo(
    () => agents.find((a) => a.did === did),
    [agents, did],
  );
  const contactsQuery = useContactsQuery();
  const knownContactDids = useMemo(() => {
    const dids = contactsQuery.data?.contacts?.map((contact) => contact.did) ?? [];
    return new Set(dids);
  }, [contactsQuery.data]);
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );
  const [activeId, setActiveId] = useState<string>("");
  const [threadWidth, setThreadWidth] = useState<number>(380);
  const [localRead, setLocalRead] = useState<Record<string, boolean>>({});
  const [subjectTextById, setSubjectTextById] = useState<Record<string, string>>({});
  // Same per-recipient-DID keystore presence tracking as the unified
  // inbox (apps/web/app/page.tsx). `undefined` = optimistic, resolved
  // values drive the Daemon-isolated badge on each thread row.
  const [keyPresenceByDid, setKeyPresenceByDid] = useState<
    Record<string, boolean>
  >({});
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [bodyText, setBodyText] = useState<string>("");

  const startResizeThread = (event: MouseEvent<HTMLDivElement>) => {
    event.preventDefault();
    const startX = event.clientX;
    const startWidth = threadWidth;
    const onMouseMove = (moveEvent: globalThis.MouseEvent) => {
      setThreadWidth(Math.max(200, Math.min(800, startWidth + (moveEvent.clientX - startX))));
    };
    const onMouseUp = () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      document.body.style.cursor = "";
    };
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "col-resize";
  };


  // Phase 4.7 — URL-synced search + filter state. Source of truth
  // is the URL (`?q=&folder=&status=`); local state mirrors it so
  // typing into the search box doesn't roundtrip through the router
  // for every keystroke. Bookmark / share / back-button all work
  // because the URL is canonical.
  const searchParams = useSearchParams();
  const initialFolder = useMemo<MessageFolderQuery>(() => {
    const v = searchParams?.get("folder");
    return v && VISIBLE_FOLDERS.includes(v as MessageFolderQuery)
      ? (v as MessageFolderQuery)
      : "inbox";
  }, [searchParams]);
  const initialStatus = useMemo<StatusFilter>(() => {
    const v = searchParams?.get("status");
    return v === "unread" ? "unread" : "all";
  }, [searchParams]);
  const initialQuery = useMemo<string>(() => {
    return searchParams?.get("q") ?? "";
  }, [searchParams]);

  const [folder, setFolder] = useState<MessageFolderQuery>(initialFolder);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(initialStatus);
  const [searchQuery, setSearchQuery] = useState<string>(initialQuery);

  // 300ms debounce on URL writeback for free-text typing. Folder /
  // status updates flush immediately because they don't fire-hose.
  const urlSyncTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const syncQueryToUrl = useCallback(
    (next: { q?: string; folder?: MessageFolderQuery; status?: StatusFilter }) => {
      if (urlSyncTimerRef.current) {
        clearTimeout(urlSyncTimerRef.current);
      }
      const apply = () => {
        const params = new URLSearchParams(window.location.search);
        const q = next.q ?? searchQuery;
        const f = next.folder ?? folder;
        const s = next.status ?? statusFilter;
        if (q) params.set("q", q);
        else params.delete("q");
        if (f && f !== "inbox") params.set("folder", f);
        else params.delete("folder");
        if (s && s !== "all") params.set("status", s);
        else params.delete("status");
        const qs = params.toString();
        const newPath = qs
          ? `${window.location.pathname}?${qs}`
          : window.location.pathname;
        router.replace(newPath, { scroll: false });
      };
      // Free text gets debounced; the others apply immediately.
      if (next.q !== undefined) {
        urlSyncTimerRef.current = setTimeout(apply, 300);
      } else {
        apply();
      }
    },
    [router, searchQuery, folder, statusFilter],
  );

  const messagesQuery = useMessagesQuery({
    agentDid: did,
    status: statusFilter === "unread" ? "unread" : "all",
    folder,
    page: 1,
    perPage: 50,
  });
  const updateStatus = useUpdateMessageStatusMutation();
  const policyQuery = useAutoReplyPolicyQuery(currentAgent?.id ?? null);
  const queryClient = useQueryClient();
  // Guards against overlapping executor runs. Without this the
  // StrictMode double-invocation and every messagesQuery refetch
  // would kick off a concurrent executor pass — the server column
  // would still gate double sends, but we'd burn API + crypto work.
  const executorRunningRef = useRef(false);

  useEffect(() => {
    const agent = currentAgent;
    if (!agent) return;
    if (executorRunningRef.current) return;
    const messages = messagesQuery.data?.messages ?? [];
    const hasEligible = messages.some((m) => {
      if (m.auto_reply_sent_at) return false;
      if (
        m.auto_reply_decision === "auto_accept" ||
        m.auto_reply_decision === "auto_decline"
      ) {
        return true;
      }
      // Phase 4.4d: the server stamped queue_for_human because the
      // server evaluator can't see protocols.*, but the client
      // evaluator + Calendar check may still resolve it to accept.
      if (
        m.auto_reply_decision === "queue_for_human" &&
        m.auto_reply_reason === "calendar_unavailable"
      ) {
        return true;
      }
      return false;
    });
    if (!hasEligible) return;

    let cancelled = false;
    executorRunningRef.current = true;
    (async () => {
      try {
        const signingKey = await getSigningPrivateKey(agent.did);
        if (cancelled) return;
        const gcalEntry = await getCalendarToken();
        const gcalToken = gcalEntry?.access_token ?? null;
        await runAutoReplyExecutor({
          viewerAgentDid: agent.did,
          viewerHasSigningKey: !!signingKey,
          messages,
          policy: (policyQuery.data?.policy as Record<string, unknown>) ?? null,
          masterAutoReplyEnabled: agent.auto_reply,
          isContact: (senderDid) => knownContactDids.has(senderDid),
          api: {
            getMessageContent: (id) => defaultApiClient.getMessageContent(id),
            markAutoReplySent: (id, params) =>
              defaultApiClient.markAutoReplySent(id, params),
          },
          sendProtocolReply: (input) =>
            realSendProtocolReply({
              protocolType: input.protocolType,
              reply: input.reply,
              threadId: input.threadId,
              originalProtocolId: input.originalProtocolId,
              subject: input.subject,
              bodySummary: input.bodySummary,
              viewerAgentDid: input.viewerAgentDid,
              proposerDid: input.proposerDid,
              autoReplyOrigin: input.autoReplyOrigin,
              sendMessage: (payload) =>
                defaultApiClient.seedMessage({
                  senderDid: payload.senderDid,
                  recipientDid: payload.recipientDid,
                  subjectEncrypted: payload.subjectEncrypted,
                  encryptedContent: payload.encryptedContent,
                  encryptedKey: payload.encryptedKey,
                  nonce: payload.nonce,
                  signature: payload.signature,
                  threadId: payload.threadId,
                  contentType: payload.contentType,
                  autoReplyOrigin: payload.autoReplyOrigin,
                }),
            }),
          decrypt: (ciphertext, encryptedKey, recipientDid) =>
            decryptEnvelopeText(ciphertext, encryptedKey, recipientDid),
          // Phase 4.4d: wire Google Calendar freebusy when the user
          // has connected their account. Callback omitted → executor
          // treats auto_accept_if_free as calendar_unavailable and
          // escalates to the human queue. Callback present + throws
          // → treated as transient API error and left for retry.
          calendarFreebusy: gcalToken
            ? async (candidates) =>
                findFirstFreeCandidate(candidates, gcalToken)
            : undefined,
        });
        if (!cancelled) {
          queryClient.invalidateQueries({ queryKey: ["messages"] });
        }
      } finally {
        executorRunningRef.current = false;
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [
    currentAgent,
    knownContactDids,
    messagesQuery.data,
    policyQuery.data,
    queryClient,
  ]);

  const apiThreads = useMemo<ThreadView[]>(() => {
    const messages = messagesQuery.data?.messages ?? [];
    // Collapse messages with the same `thread_id` into one row so the
    // list reads like Gmail (one row per conversation, count badge
    // for replies). The representative is the newest message — the
    // one whose subject + auto-reply state we surface in the row,
    // and the seed for ConversationThread when the user clicks in.
    const groups = groupMessagesByThread(messages);
    return groups.map((group) => {
      const m = group.representative;
      return {
        id: m.id,
        sender: resolveParticipantLabel(
          m.sender_did,
          m.sender_label,
          contactsByDid,
        ),
        senderDid: m.sender_did,
        recipientDid: m.recipient_did,
        subject: t("inbox.decryptingSubject"),
        encryptedSubject: m.subject_encrypted,
        preview: t("inbox.bodyHidden"),
        time: formatListTimestamp(m.created_at, { locale }),
        // Bold the row when *any* message in the thread is unread —
        // matches Gmail and keeps replies discoverable even after
        // the original was opened.
        unread: group.hasUnread,
        trust: m.trust_score,
        source: "api",
        autoReplyDecision: m.auto_reply_decision,
        autoReplyReason: m.auto_reply_reason,
        autoReplySentAt: m.auto_reply_sent_at,
        messageCount: group.count,
      };
    });
  }, [messagesQuery.data, contactsByDid, t, locale]);

  const baseThreads = apiThreads;
  const threads = useMemo(
    () =>
      baseThreads.map((thread) => ({
        ...thread,
        unread: localRead[thread.id] ? false : thread.unread,
      })),
    [baseThreads, localRead],
  );

  // Phase 4.7 — client-side filter pass. We only filter on subject
  // (already decrypted into subjectTextById) and on the visible
  // sender label. Body search is intentionally out of scope (would
  // force decrypt-on-mount for every entry, see plan).
  const trimmedQuery = searchQuery.trim();
  const filteredThreads = useMemo(() => {
    if (!trimmedQuery) return threads;
    const needle = trimmedQuery.toLowerCase();
    return threads.filter((thread) => {
      const subject = subjectTextById[thread.id];
      const subjectMatch =
        subject != null && subject.toLowerCase().includes(needle);
      const senderMatch = thread.sender.toLowerCase().includes(needle);
      return subjectMatch || senderMatch;
    });
  }, [threads, trimmedQuery, subjectTextById]);
  const isFiltering = trimmedQuery.length > 0;
  const hitCount = filteredThreads.length;

  useEffect(() => {
    if (threads.length === 0) {
      setActiveId("");
      return;
    }
    if (!threads.some((thread) => thread.id === activeId)) {
      setActiveId(threads[0].id);
    }
  }, [threads, activeId]);

  const activeThread = threads.find((thread) => thread.id === activeId) ?? null;
  const contentQuery = useMessageContentQuery(activeThread && activeThread.source === "api" ? activeThread.id : null);

  const handleOpen = async (thread: ThreadView) => {
    setActiveId(thread.id);
    setLocalRead((prev) => ({ ...prev, [thread.id]: true }));

    if (thread.source === "api" && thread.unread) {
      try {
        await updateStatus.mutateAsync({ id: thread.id, status: "read" });
      } catch {
        // keep local read state for UX continuity
      }
    }
  };

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!activeThread) {
        if (!cancelled) setBodyText("");
        return;
      }
      const raw =
        activeThread.source === "api"
          ? contentQuery.data?.encrypted_content ??
            (contentQuery.isLoading ? t("inbox.bodyLoading") : t("inbox.bodyFailed"))
          : "";
      const encryptedKey = activeThread.source === "api" ? contentQuery.data?.encrypted_key : undefined;
      const decrypted = await decryptEnvelopeText(raw, encryptedKey, activeThread.recipientDid);
      if (!cancelled) setBodyText(decrypted);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeThread, contentQuery.data?.encrypted_content, contentQuery.isLoading, t]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!activeThread || activeThread.source !== "api") return;
      const encryptedKey = contentQuery.data?.encrypted_key;
      if (!encryptedKey || !activeThread.encryptedSubject) return;

      const decryptedSubject = await decryptEnvelopeText(
        activeThread.encryptedSubject,
        encryptedKey,
        activeThread.recipientDid,
      );
      if (cancelled) return;
      if (decryptedSubject !== ENCRYPTED_PLACEHOLDER) {
        setSubjectTextById((prev) => ({ ...prev, [activeThread.id]: decryptedSubject }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeThread, contentQuery.data?.encrypted_key]);

  useEffect(() => {
    const unresolved = threads.filter((thread) => !subjectTextById[thread.id] && thread.source !== "api");
    if (unresolved.length === 0) return;

    let cancelled = false;
    void (async () => {
      const pairs = await Promise.all(
        unresolved.map(
          async (thread) => [thread.id, await decryptEnvelopeText(thread.subject, undefined, thread.recipientDid)] as const,
        ),
      );
      if (cancelled) return;
      setSubjectTextById((prev) => {
        const next = { ...prev };
        pairs.forEach(([id, text]) => {
          next[id] = text;
        });
        return next;
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [threads, subjectTextById]);

  useEffect(() => {
    const dids = Array.from(
      new Set(
        threads
          .map((thread) => thread.recipientDid)
          .filter((did): did is string => Boolean(did)),
      ),
    );
    const toCheck = dids.filter((did) => keyPresenceByDid[did] === undefined);
    if (toCheck.length === 0) return;
    let cancelled = false;
    void (async () => {
      const pairs = await Promise.all(
        toCheck.map(async (did) => [did, await hasRecipientPrivateKey(did)] as const),
      );
      if (cancelled) return;
      setKeyPresenceByDid((prev) => {
        const next = { ...prev };
        for (const [did, has] of pairs) next[did] = has;
        return next;
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [threads, keyPresenceByDid]);

  const layoutStyle: CSSProperties = {
    ["--thread-width" as string]: threadWidth + "px",
  };

  const handleAgentSwitch = (nextDid: string) => {
    if (!nextDid || nextDid === did) return;
    router.push(`/agent/${encodeURIComponent(nextDid)}`);
  };

  return (
    <AppShell
      title={currentAgent?.label ?? t("agentView.inboxTitle")}
      activePath={"/agent/" + encodeURIComponent(did)}
      rightAction={
        <RefreshIconButton
          onClick={() => messagesQuery.refetch()}
          label={t("agentView.refresh")}
        />
      }
    >
      {/* Agent switcher sits directly below the search box so it's easy to
          discover. Hidden when the user has only one agent. */}
      {agents.length > 1 ? (
        <section className="agent-switcher-bar">
          <label className="agent-switcher">
            <span className="agent-switcher-label">
              {t("agentView.switcherLabel")}
            </span>
            <select
              className="agent-switcher-select"
              value={did}
              onChange={(event) => handleAgentSwitch(event.target.value)}
              aria-label={t("agentView.switcherLabel")}
            >
              {agents.map((agent) => {
                const unread = agent.unread_count ?? 0;
                const suffix = unread > 0 ? ` (${unread})` : "";
                return (
                  <option key={agent.did} value={agent.did}>
                    {agent.label}{suffix}
                  </option>
                );
              })}
            </select>
          </label>
        </section>
      ) : null}
      <section className="mail-layout" style={layoutStyle}>
        <aside className="thread-list">
          <div
            className="thread-list-toolbar"
            data-testid="thread-list-toolbar"
            style={{
              display: "flex",
              gap: 6,
              padding: "8px 10px",
              borderBottom: "1px solid rgba(60,64,67,0.12)",
              flexWrap: "wrap",
              alignItems: "center",
            }}
          >
            <input
              type="search"
              className="thread-list-search"
              placeholder={t("agentView.search.placeholder")}
              value={searchQuery}
              onChange={(e) => {
                const next = e.target.value;
                setSearchQuery(next);
                syncQueryToUrl({ q: next });
              }}
              data-testid="thread-list-search-input"
              style={{
                flex: "1 1 160px",
                minWidth: 0,
                padding: "4px 8px",
                fontSize: 12,
                border: "1px solid rgba(60,64,67,0.24)",
                borderRadius: 4,
              }}
            />
            <select
              value={folder}
              onChange={(e) => {
                const next = e.target.value as MessageFolderQuery;
                setFolder(next);
                syncQueryToUrl({ folder: next });
              }}
              data-testid="thread-list-folder-select"
              style={{ fontSize: 12, padding: "4px 6px" }}
            >
              {VISIBLE_FOLDERS.map((f) => (
                <option key={f} value={f}>
                  {t(`agentView.folder.${f}`)}
                </option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => {
                const next = e.target.value as StatusFilter;
                setStatusFilter(next);
                syncQueryToUrl({ status: next });
              }}
              data-testid="thread-list-status-select"
              style={{ fontSize: 12, padding: "4px 6px" }}
            >
              <option value="all">{t("agentView.status.all")}</option>
              <option value="unread">{t("agentView.status.unread")}</option>
            </select>
            {isFiltering ? (
              <span
                style={{ fontSize: 11, color: "#5f6368" }}
                data-testid="thread-list-hit-count"
              >
                {t("agentView.search.hits", { count: hitCount })}
              </span>
            ) : null}
          </div>
          {filteredThreads.length === 0 ? (
            <div className="empty-state">
              {isFiltering ? (
                <>
                  {t("agentView.search.empty", { query: trimmedQuery })}
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      setSearchQuery("");
                      syncQueryToUrl({ q: "" });
                    }}
                    style={{ marginTop: 8, fontSize: 12 }}
                    data-testid="thread-list-search-clear"
                  >
                    {t("agentView.search.clear")}
                  </button>
                </>
              ) : (
                t("agentView.emptyThreads")
              )}
            </div>
          ) : (
            filteredThreads.map((thread) => {
              const className = "thread-item" + (activeThread?.id === thread.id ? " active" : "");
              const keyKnownMissing = thread.recipientDid
                ? keyPresenceByDid[thread.recipientDid] === false
                : false;
              return (
                <article className={className} key={thread.id} onClick={() => handleOpen(thread)}>
                  <div className="thread-item-top">
                    <p className="thread-sender">
                      {thread.sender}
                      {thread.messageCount > 1 ? (
                        <span
                          className="thread-count-badge"
                          aria-label={t("inbox.threadCountSr", {
                            count: thread.messageCount,
                          })}
                          style={{
                            marginLeft: 6,
                            color: "var(--text-muted, #5f6368)",
                            fontWeight: 400,
                            fontVariantNumeric: "tabular-nums",
                          }}
                        >
                          ({thread.messageCount})
                        </span>
                      ) : null}
                    </p>
                    <span className="thread-time">{thread.time}</span>
                  </div>
                  {keyKnownMissing ? (
                    <>
                      <p
                        className="thread-subject"
                        data-state="unavailable_on_this_device"
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          flexWrap: "wrap",
                        }}
                      >
                        <span
                          style={{
                            fontSize: 10,
                            fontWeight: 500,
                            padding: "1px 7px",
                            borderRadius: 999,
                            letterSpacing: 0.3,
                            whiteSpace: "nowrap",
                            background: "rgba(66, 133, 244, 0.14)",
                            color: "#1a73e8",
                            border: "1px solid rgba(66, 133, 244, 0.28)",
                          }}
                        >
                          {t("inbox.unavailableOnThisDeviceBadge")}
                        </span>
                        <span style={{ color: "var(--text-muted, #5f6368)" }}>
                          {t("inbox.unavailableOnThisDeviceSubject")}
                        </span>
                      </p>
                      <p
                        className="thread-preview"
                        style={{ color: "var(--text-muted, #5f6368)" }}
                      >
                        {t("inbox.unavailableOnThisDevicePreview")}
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="thread-subject">{subjectTextById[thread.id] ?? thread.subject}</p>
                      <p className="thread-preview">{thread.preview}</p>
                      {thread.autoReplySentAt ? (
                        <p
                          className="thread-autoreply-badge"
                          title={t("inbox.autoReply.sentTooltip")}
                          style={{
                            marginTop: 4,
                            fontSize: 10,
                            fontWeight: 500,
                            letterSpacing: 0.2,
                            color: "#0f9d58",
                          }}
                        >
                          {t("inbox.autoReply.sentAt", {
                            time: formatListTimestamp(thread.autoReplySentAt, {
                              locale,
                            }),
                          })}
                        </p>
                      ) : thread.autoReplyDecision ? (
                        <p
                          className="thread-autoreply-badge"
                          title={
                            thread.autoReplyReason
                              ? t(`inbox.autoReply.reason.${thread.autoReplyReason}`)
                              : undefined
                          }
                          style={{
                            marginTop: 4,
                            fontSize: 10,
                            fontWeight: 500,
                            letterSpacing: 0.2,
                            color:
                              thread.autoReplyDecision === "auto_accept"
                                ? "#0f9d58"
                                : thread.autoReplyDecision === "auto_decline"
                                  ? "#d93025"
                                  : "#5f6368",
                          }}
                        >
                          {t(`inbox.autoReply.decision.${thread.autoReplyDecision}`)}
                          {thread.autoReplyReason
                            ? ` · ${t(`inbox.autoReply.reason.${thread.autoReplyReason}`)}`
                            : null}
                        </p>
                      ) : null}
                    </>
                  )}
                </article>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResizeThread} />

        <article className="reader-pane">
          {activeThread ? (
            <>
              <ConversationThread rootMessageId={activeThread.id} />

              <footer className="reader-actions">
                <button
                  className="btn primary"
                  type="button"
                  onClick={() =>
                    router.push(`/compose?reply=${encodeURIComponent(activeThread.id)}`)
                  }
                  data-testid="reader-reply"
                >
                  {t("inbox.reply")}
                </button>
                <button
                  className="btn"
                  type="button"
                  onClick={() =>
                    router.push(`/compose?reply=${encodeURIComponent(activeThread.id)}&ai=1`)
                  }
                  data-testid="reader-ai-approve"
                >
                  {t("inbox.aiDraftApprove")}
                </button>
                <button
                  className="btn"
                  type="button"
                  onClick={() =>
                    router.push(`/compose?forward=${encodeURIComponent(activeThread.id)}`)
                  }
                  data-testid="reader-forward"
                >
                  {t("inbox.forward")}
                </button>
                {activeThread.senderDid && !knownContactDids.has(activeThread.senderDid) ? (
                  <button
                    className="btn"
                    type="button"
                    onClick={() =>
                      router.push(
                        `/contacts?add=${encodeURIComponent(activeThread.senderDid ?? "")}`,
                      )
                    }
                    data-testid="reader-add-contact"
                  >
                    {t("agentView.addToContacts")}
                  </button>
                ) : null}
              </footer>
            </>
          ) : (
            <div className="empty-state">{t("agentView.noBody")}</div>
          )}
        </article>

        {messagesQuery.error || updateStatus.error ? (
          <div className="inbox-fetch-error" role="alert">
            {t("inbox.fetchError")}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}
