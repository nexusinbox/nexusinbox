"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { CSSProperties, Suspense, useEffect, useMemo, useState } from "react";
import { AppShell } from "./_components/AppShell";
import { ConversationThread } from "./_components/ConversationThread";
import { RefreshIconButton } from "./_components/RefreshIconButton";
import { useTranslation } from "../lib/i18n";
import { formatListTimestamp } from "../lib/format/messageTime";
import { groupMessagesByThread } from "../lib/inbox/group-by-thread";
import { indexContactsByDid, resolveParticipantLabel } from "../lib/api/labels";
import { defaultApiClient } from "../lib/api/client";
import {
  queryKeys as apiQueryKeys,
  useAgentsQuery,
  useContactsQuery,
  useDeleteMessageMutation,
  useMessageContentQuery,
  useMessagesQuery,
  useUpdateMessageFlagsMutation,
  useUpdateMessageStatusMutation,
} from "../lib/api/hooks";
import {
  MessageFolderQuery,
  MessagePriority,
  MessageStatus,
  type MessageContentResponse,
} from "../lib/api/types";
import { decryptEnvelopeText, ENCRYPTED_PLACEHOLDER } from "../lib/crypto/envelope";
import { hasRecipientPrivateKey } from "../lib/crypto/recipient-keyring";

type FilterType = "all" | "unread" | "starred";
type ViewKey =
  | "inbox"
  | "starred"
  | "sent"
  | "drafts"
  | "all"
  | "spam"
  | "trash";

type ViewConfig = {
  title: string;
  folder: MessageFolderQuery;
  filter: FilterType;
  priority?: MessagePriority;
  emptyMessage: string;
  activePath: string;
};

function buildViewConfigs(t: (key: string) => string): Record<ViewKey, ViewConfig> {
  return {
    inbox: {
      title: t("inbox.title"),
      folder: "inbox",
      filter: "all",
      emptyMessage: t("inbox.emptyMessage"),
      activePath: "/",
    },
    starred: {
      title: t("inbox.starredTitle"),
      folder: "starred",
      filter: "all",
      emptyMessage: t("inbox.starredEmpty"),
      activePath: "/?view=starred",
    },
    sent: {
      title: t("inbox.sentTitle"),
      folder: "sent",
      filter: "all",
      emptyMessage: t("inbox.sentEmpty"),
      activePath: "/?view=sent",
    },
    drafts: {
      title: t("inbox.draftsTitle"),
      folder: "drafts",
      filter: "all",
      emptyMessage: t("inbox.draftsEmpty"),
      activePath: "/?view=drafts",
    },
    all: {
      title: t("inbox.allTitle"),
      folder: "all",
      filter: "all",
      emptyMessage: t("inbox.allEmpty"),
      activePath: "/?view=all",
    },
    spam: {
      title: t("inbox.spamTitle"),
      folder: "spam",
      filter: "all",
      emptyMessage: t("inbox.spamEmpty"),
      activePath: "/?view=spam",
    },
    trash: {
      title: t("inbox.trashTitle"),
      folder: "trash",
      filter: "all",
      emptyMessage: t("inbox.trashEmpty"),
      activePath: "/?view=trash",
    },
  };
}

const validViewKeys: ReadonlySet<string> = new Set<ViewKey>(["inbox", "starred", "sent", "drafts", "all", "spam", "trash"]);

function resolveViewKey(raw: string | null): ViewKey {
  if (!raw) return "inbox";
  if (validViewKeys.has(raw)) return raw as ViewKey;
  return "inbox";
}

// mapStatusLabel available for future use:
// "unread" → t("inbox.statusUnread"), "read" → t("inbox.statusRead"), "archived" → t("inbox.statusArchived")
type DashboardUiPrefs = {
  filter: FilterType;
  searchQuery: string;
  threadWidth: number;
};

type ThreadView = {
  id: string;
  sender: string;
  senderDid?: string;
  recipientDid?: string;
  time: string;
  subject: string;
  encryptedSubject?: string;
  preview: string;
  body: string;
  status: MessageStatus;
  starred: boolean;
  priority: MessagePriority;
  trust: number;
  source: "api" | "mock";
  /** Number of messages collapsed into this row (≥1). The list
   *  renders a "(N)" badge when > 1. See lib/inbox/group-by-thread. */
  messageCount: number;
};

function buildFilterTabs(t: (key: string) => string): Array<{ key: FilterType; label: string }> {
  return [
    { key: "all", label: t("inbox.filterAll") },
    { key: "unread", label: t("inbox.filterUnread") },
    { key: "starred", label: t("inbox.filterStarred") },
  ];
}

const DASHBOARD_UI_PREFS_KEY = "nexusinbox.dashboard.ui.v1";

// Inline formatter retired in favour of the shared
// `formatListTimestamp` helper (apps/web/lib/format/messageTime.ts)
// which implements the Gmail-style today/this-year/earlier
// fallthrough. Call sites now pass through `locale` from
// `useTranslation()` so ja and en lists pick the right shape.

/**
 * Collapse a decrypted body into a Gmail-style inline preview
 * snippet: first non-empty line, whitespace collapsed, clipped to
 * `maxChars`. Keeping the logic pure + deterministic means the same
 * body → same snippet → no render jitter when the decrypt effect
 * re-runs with cached content.
 *
 * `maxChars` defaults to 140 — roughly what fits next to the subject
 * at the narrowest thread-list width (~280 px) before the whole
 * line ellipses. Server doesn't truncate; we truncate here so the
 * user can still widen the list pane and see more without a refetch.
 */
function previewSnippet(body: string, maxChars = 140): string {
  const firstLine =
    body
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? "";
  const collapsed = firstLine.replace(/\s+/g, " ").trim();
  if (collapsed.length === 0) return "";
  return collapsed.length > maxChars
    ? collapsed.slice(0, maxChars).trimEnd() + "…"
    : collapsed;
}

// Bounded concurrency for the bulk decrypt effect below. Picked 4 by
// hand: the bottleneck in practice is the X25519 keystore unwrap,
// which is cheap but still hits IndexedDB, so running more than a
// handful in parallel doesn't speed anything up and just inflates
// the number of in-flight `/messages/:id/content` fetches.
const PREVIEW_DECRYPT_CONCURRENCY = 4;

const DASHBOARD_PER_PAGE = 50;

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

export default function DashboardPage() {
  return (
    <Suspense fallback={null}>
      <DashboardPageInner />
    </Suspense>
  );
}

function DashboardPageInner() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  const { t, locale } = useTranslation();
  const viewConfigs = useMemo(() => buildViewConfigs(t), [t]);
  const filterTabs = useMemo(() => buildFilterTabs(t), [t]);
  const viewKey = resolveViewKey(searchParams.get("view"));
  const view = viewConfigs[viewKey];
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [activeId, setActiveId] = useState<string>("");
  const [mobileView, setMobileView] = useState<"list" | "detail">("list");
  const [filter, setFilter] = useState<FilterType>(view.filter);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [threadWidth, setThreadWidth] = useState<number>(380);
  const [page, setPage] = useState<number>(1);

  const startResizeThread = (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = threadWidth;
    const onMouseMove = (moveEvent: MouseEvent) => {
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
  const [localStars, setLocalStars] = useState<Record<string, boolean>>({});
  const [localStatus, setLocalStatus] = useState<Record<string, MessageStatus>>({});
  const [subjectTextById, setSubjectTextById] = useState<Record<string, string>>({});
  // Gmail-style inline body preview per row. Value is either the
  // decrypted snippet (up to `previewSnippet`'s char cap), the
  // `ENCRYPTED_PLACEHOLDER` sentinel (decrypt failed / key missing
  // after a real try), or an empty string (decrypted body was empty).
  // `undefined` means the bulk-decrypt effect hasn't touched this id
  // yet, so the render falls back to the original static placeholder.
  const [previewTextById, setPreviewTextById] = useState<Record<string, string>>({});
  // Per-recipient-DID presence map for the current browser keystore.
  // `undefined` → not yet checked (optimistic render: assume key
  // available so subjects still try to decrypt). `true` / `false` →
  // resolved. Drives the Daemon-isolated badge on list rows without
  // blocking the initial paint on IndexedDB reads.
  const [keyPresenceByDid, setKeyPresenceByDid] = useState<
    Record<string, boolean>
  >({});
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [activeBodyText, setActiveBodyText] = useState<string>("");

  // Reset filter when the user switches sidebar views, but still allow
  // them to override it locally via the filter tabs afterwards.
  useEffect(() => {
    setFilter(view.filter);
    setPage(1);
  }, [viewKey, view.filter]);

  const messagesQuery = useMessagesQuery({
    agentDid: "all",
    status: "all",
    folder: view.folder,
    priority: view.priority,
    page,
    perPage: DASHBOARD_PER_PAGE,
  });

  // Drives the inbox onboarding card in the reader pane: we show a
  // welcome state when the user has 0 agents, and a "share your AID"
  // prompt when they have ≥1 agent but nothing in the inbox yet.
  // Only relevant on the inbox view; other folders (sent / trash /
  // etc) keep their minimal empty-state so they don't nag repeat
  // users.
  const agentsQuery = useAgentsQuery();
  const agentCount = agentsQuery.data?.agents.length ?? null;
  const firstAgentAid = agentsQuery.data?.agents?.[0]?.aid ?? null;

  const totalMessages = messagesQuery.data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalMessages / DASHBOARD_PER_PAGE));
  const hasPrevPage = page > 1;
  const hasNextPage = page < totalPages;

  const goToPreviousPage = () => {
    if (hasPrevPage) setPage((current) => Math.max(1, current - 1));
  };
  const goToNextPage = () => {
    if (hasNextPage) setPage((current) => current + 1);
  };

  const updateStatus = useUpdateMessageStatusMutation();
  const updateFlags = useUpdateMessageFlagsMutation();
  const deleteMessage = useDeleteMessageMutation();
  const contactsQuery = useContactsQuery();
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );
  const knownContactDids = useMemo(() => {
    const dids = contactsQuery.data?.contacts?.map((contact) => contact.did) ?? [];
    return new Set(dids);
  }, [contactsQuery.data]);

  const apiThreads = useMemo<ThreadView[]>(() => {
    const messages = messagesQuery.data?.messages ?? [];
    // Same Gmail-style thread collapse as the per-agent inbox: group
    // by `thread_id` so the list shows one row per conversation with
    // a `(N)` count badge instead of a row per message. The
    // representative is the newest message in the group, and that's
    // also the seed used when the user opens the detail view —
    // ConversationThread walks the rest from there.
    const groups = groupMessagesByThread(messages);
    return groups.map((group) => {
      const m = group.representative;
      // Bold the row when ANY message in the group is unread, matching
      // Gmail. We OR over the group's statuses rather than just the
      // representative's so a fresh reply re-surfaces the row.
      const status: MessageStatus = group.hasUnread ? "unread" : m.status;
      return {
        id: m.id,
        sender: resolveParticipantLabel(
          m.sender_did,
          m.sender_label,
          contactsByDid,
        ),
        senderDid: m.sender_did,
        recipientDid: m.recipient_did,
        time: formatListTimestamp(m.created_at, { locale }),
        subject: t("inbox.decryptingSubject"),
        encryptedSubject: m.subject_encrypted,
        preview: t("inbox.bodyHidden"),
        body: t("inbox.bodyDecryptPrompt"),
        status,
        // Starred at the thread level: any starred message lights up
        // the row. Same behaviour Gmail uses.
        starred: group.messages.some((x) => x.starred),
        priority: m.priority,
        trust: m.trust_score,
        source: "api",
        messageCount: group.count,
      };
    });
  }, [messagesQuery.data, contactsByDid, locale, t]);

  const baseThreads = apiThreads;

  const derivedThreads = useMemo<ThreadView[]>(() => {
    return baseThreads.map((thread) => {
      const forcedStar = localStars[thread.id];
      const forcedStatus = localStatus[thread.id];

      const starred = typeof forcedStar === "boolean" ? forcedStar : thread.starred;
      const status = forcedStatus ?? thread.status;

      return { ...thread, starred, status };
    });
  }, [baseThreads, localStars, localStatus]);

  const filteredThreads = useMemo(() => {
    const keyword = searchQuery.trim().toLowerCase();
    // Folder routing is now done server-side via view.folder, so the
    // client only has to apply the secondary filter (unread / starred /
    // high) plus the free-text search.
    return derivedThreads
      .filter((thread) => {
        if (filter === "unread") return thread.status === "unread";
        if (filter === "starred") return thread.starred;
        return true;
      })
      .filter((thread) => {
        if (!keyword) return true;
        const subjectText = subjectTextById[thread.id] ?? thread.subject;
        const haystack = [thread.sender, subjectText, thread.preview].join(" ").toLowerCase();
        return haystack.includes(keyword);
      });
  }, [derivedThreads, filter, searchQuery, subjectTextById]);

  useEffect(() => {
    if (filteredThreads.length === 0) {
      setActiveId("");
      return;
    }
    if (!filteredThreads.some((thread) => thread.id === activeId)) {
      setActiveId(filteredThreads[0].id);
    }
  }, [filteredThreads, activeId]);

  const activeThread = filteredThreads.find((thread) => thread.id === activeId) ?? null;

  const contentQuery = useMessageContentQuery(activeThread && activeThread.source === "api" ? activeThread.id : null);

  const allVisibleSelected =
    filteredThreads.length > 0 && filteredThreads.every((thread) => selectedIds.includes(thread.id));

  const selectedVisibleThreads = filteredThreads.filter((thread) => selectedIds.includes(thread.id));
  const selectedCount = selectedVisibleThreads.length;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const allSelectedStarred =
    selectedVisibleThreads.length > 0 && selectedVisibleThreads.every((thread) => thread.starred);

  const layoutStyle: CSSProperties = {
    ["--thread-width" as string]: threadWidth + "px",
  };

  const handleOpenThread = (id: string) => {
    setActiveId(id);
    setMobileView("detail");
    const target = filteredThreads.find((thread) => thread.id === id);
    if (target && target.source === "api" && target.status === "unread") {
      setLocalStatus((prev) => ({ ...prev, [id]: "read" }));
      updateStatus.mutate({ id, status: "read" });
    } else if (target && target.status === "unread") {
      setLocalStatus((prev) => ({ ...prev, [id]: "read" }));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      if (prev.includes(id)) return prev.filter((target) => target !== id);
      return prev.concat(id);
    });
  };

  const toggleSelectAll = () => {
    if (allVisibleSelected) {
      const visibleSet = new Set(filteredThreads.map((thread) => thread.id));
      setSelectedIds((prev) => prev.filter((id) => !visibleSet.has(id)));
      return;
    }

    const merged = new Set(selectedIds);
    filteredThreads.forEach((thread) => merged.add(thread.id));
    setSelectedIds(Array.from(merged));
  };

  const toggleStar = (id: string) => {
    const current = baseThreads.find((thread) => thread.id === id);
    const nextStar = !(localStars[id] ?? current?.starred ?? false);
    setLocalStars((prev) => ({ ...prev, [id]: nextStar }));
    updateFlags.mutate({ id, starred: nextStar });
  };

  const bulkSetStar = (nextStar: boolean) => {
    const targetIds = filteredThreads
      .filter((thread) => selectedIds.includes(thread.id))
      .map((thread) => thread.id);
    if (targetIds.length === 0) return;

    targetIds.forEach((id) => {
      updateFlags.mutate({ id, starred: nextStar });
    });
    setLocalStars((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        next[id] = nextStar;
      });
      return next;
    });
  };

  const bulkMoveToFolder = async (folder: "trash" | "spam") => {
    const targetIds = selectedIds.filter((id) =>
      filteredThreads.some((thread) => thread.id === id),
    );
    if (targetIds.length === 0) return;

    // Optimistically hide from the current view.
    setLocalStatus((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        // Mark as read so it also disappears from the unread filter.
        next[id] = "read";
      });
      return next;
    });
    setSelectedIds([]);

    const apiTargets = filteredThreads.filter(
      (thread) => targetIds.includes(thread.id) && thread.source === "api",
    );
    await Promise.allSettled(
      apiTargets.map((thread) =>
        updateFlags.mutateAsync({ id: thread.id, folder }),
      ),
    );
    void messagesQuery.refetch();
  };

  // Gmail-style restore: used by Spam / Trash / All Mail views to move a
  // message back into the inbox. The server handler clears any residual
  // `archived` status so un-archiving just works.
  const bulkRestoreToInbox = async () => {
    const targetIds = selectedIds.filter((id) =>
      filteredThreads.some((thread) => thread.id === id),
    );
    if (targetIds.length === 0) return;

    setLocalStatus((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        next[id] = "read";
      });
      return next;
    });
    setSelectedIds([]);

    const apiTargets = filteredThreads.filter(
      (thread) => targetIds.includes(thread.id) && thread.source === "api",
    );
    await Promise.allSettled(
      apiTargets.map((thread) =>
        updateFlags.mutateAsync({ id: thread.id, folder: "inbox" }),
      ),
    );
    void messagesQuery.refetch();
  };

  // Permanent delete (irreversible). Surfaced from the trash view's
  // toolbar — anywhere else, the move-to-trash flow is the right path
  // because it leaves the message recoverable.
  //
  // Server contract: DELETE /messages/{id} drops this owner's
  // message_index row, then GC's the encrypted blob iff no peer row
  // still holds the same storage_ref. So a self-to-self message has
  // its blob GC'd immediately; a cross-user message keeps the blob
  // until the counterparty also deletes their copy.
  const bulkDeleteForever = async () => {
    const targetIds = selectedIds.filter((id) =>
      filteredThreads.some((thread) => thread.id === id),
    );
    if (targetIds.length === 0) return;

    const proceed = window.confirm(
      t("inbox.deleteForeverConfirm", { count: targetIds.length }),
    );
    if (!proceed) return;

    // Optimistically remove from the visible list — use localStatus
    // because the trash view filters by folder, but a hard remove
    // would require its own state. Marking as a sentinel "archived"
    // is fine here because the row is about to disappear server-side
    // anyway and the next refetch will drop it.
    setLocalStatus((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        next[id] = "archived";
      });
      return next;
    });
    setSelectedIds([]);

    const apiTargets = filteredThreads.filter(
      (thread) => targetIds.includes(thread.id) && thread.source === "api",
    );
    const results = await Promise.allSettled(
      apiTargets.map((thread) => deleteMessage.mutateAsync(thread.id)),
    );
    const anyFailed = results.some((r) => r.status === "rejected");
    if (anyFailed) {
      window.alert(t("inbox.deleteForeverFailed"));
    }
    void messagesQuery.refetch();
  };

  const bulkUpdateStatus = async (nextStatus: "read" | "archived") => {
    const targetIds = selectedIds.filter((id) => filteredThreads.some((thread) => thread.id === id));
    if (targetIds.length === 0) {
      return;
    }

    setLocalStatus((prev) => {
      const next = { ...prev };
      targetIds.forEach((id) => {
        next[id] = nextStatus;
      });
      return next;
    });
    setSelectedIds([]);

    const apiTargets = filteredThreads.filter(
      (thread) => targetIds.includes(thread.id) && thread.source === "api",
    );
    if (apiTargets.length === 0) {
      return;
    }

    await Promise.allSettled(
      apiTargets.map((thread) => updateStatus.mutateAsync({ id: thread.id, status: nextStatus })),
    );
    void messagesQuery.refetch();
  };

  const activeBody =
    activeThread?.source === "api"
      ? contentQuery.data?.encrypted_content ?? (contentQuery.isLoading ? t("inbox.bodyLoading") : t("inbox.bodyFailed"))
      : activeThread?.body ?? "";
  const activeEncryptedKey = activeThread?.source === "api" ? contentQuery.data?.encrypted_key : undefined;

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!activeThread) {
        if (!cancelled) setActiveBodyText("");
        return;
      }
      const decrypted = await decryptEnvelopeText(activeBody, activeEncryptedKey, activeThread.recipientDid);
      if (!cancelled) setActiveBodyText(decrypted === ENCRYPTED_PLACEHOLDER ? t("inbox.encryptedPlaceholder") : decrypted);
    })();
    return () => {
      cancelled = true;
    };
  }, [activeThread, activeBody, activeEncryptedKey]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (!activeThread || activeThread.source !== "api") return;
      if (!activeEncryptedKey || !activeThread.encryptedSubject) return;

      const decryptedSubject = await decryptEnvelopeText(
        activeThread.encryptedSubject,
        activeEncryptedKey,
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
  }, [activeThread, activeEncryptedKey]);

  useEffect(() => {
    const unresolved = filteredThreads.filter((thread) => !subjectTextById[thread.id] && thread.source !== "api");
    if (unresolved.length === 0) return;

    let cancelled = false;
    void (async () => {
      const pairs = await Promise.all(
        unresolved.map(async (thread) => {
          const text = await decryptEnvelopeText(thread.subject, undefined, thread.recipientDid);
          return [thread.id, text] as const;
        }),
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
  }, [filteredThreads, subjectTextById]);

  useEffect(() => {
    setSelectedIds((prev) => {
      const visibleSet = new Set(filteredThreads.map((thread) => thread.id));
      const next = prev.filter((id) => visibleSet.has(id));
      return next.length === prev.length ? prev : next;
    });
  }, [filteredThreads]);

  // Resolve "does this browser keystore hold the recipient's X25519
  // private key" per distinct recipient DID. The answer drives the
  // Daemon-isolated badge in the list without per-row async renders —
  // result lands in a map, subsequent paints are synchronous.
  useEffect(() => {
    const dids = Array.from(
      new Set(
        filteredThreads
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
  }, [filteredThreads, keyPresenceByDid]);

  // Gmail-style inline preview: for every visible API-sourced thread
  // whose recipient key lives in this browser, fetch
  // `/messages/:id/content`, decrypt the subject + body, and cache
  // both into `subjectTextById` + `previewTextById`. Runs with
  // bounded concurrency so a 50-row inbox doesn't open 50 parallel
  // fetches, and seeds the TanStack cache via `setQueryData` so the
  // reader-pane's `useMessageContentQuery` reuses the body the
  // moment the user clicks in (no double-fetch, no re-decrypt).
  //
  // Skips threads where:
  //   - the content is already cached (`previewTextById[id] !== undefined`)
  //   - the thread is non-API (mock / design-time)
  //   - the recipient key is known-missing (Isolated mode daemon-isolated;
  //     list renders the "Daemon 管理" badge for those rows anyway)
  useEffect(() => {
    const pending = filteredThreads.filter((thread) => {
      if (thread.source !== "api") return false;
      if (previewTextById[thread.id] !== undefined) return false;
      if (!thread.recipientDid) return false;
      if (keyPresenceByDid[thread.recipientDid] === false) return false;
      return true;
    });
    if (pending.length === 0) return;

    let cancelled = false;
    const queue = [...pending];

    const worker = async () => {
      while (!cancelled) {
        const thread = queue.shift();
        if (!thread) return;

        let content: MessageContentResponse | null = null;
        try {
          // Seed the TanStack cache so the reader-pane's
          // `useMessageContentQuery(activeId)` finds the body
          // already resolved when the user clicks in.
          content = await queryClient.fetchQuery<MessageContentResponse>({
            queryKey: apiQueryKeys.messageContent(thread.id),
            queryFn: () => defaultApiClient.getMessageContent(thread.id),
            staleTime: 30_000,
          });
        } catch {
          // Network / 404 / auth — leave the row's placeholder
          // alone. Mark as placeholder so we don't retry every
          // filter change; a manual refresh re-attempts.
          if (!cancelled) {
            setPreviewTextById((prev) =>
              prev[thread.id] === undefined
                ? { ...prev, [thread.id]: ENCRYPTED_PLACEHOLDER }
                : prev,
            );
          }
          continue;
        }
        if (cancelled || !content) return;

        // `encryptedSubject` is `string | undefined` on ThreadView so
        // the decrypt call needs a non-undefined argument. An empty
        // string is the correct fallback: the decrypt helper short-
        // circuits on `parseEncryptedPayload() → null` and returns
        // the input verbatim, which we then ignore via the
        // ENCRYPTED_PLACEHOLDER check below.
        const subjectCipher = thread.encryptedSubject ?? "";
        const [subjectResult, bodyResult] = await Promise.all([
          decryptEnvelopeText(
            subjectCipher,
            content.encrypted_key,
            thread.recipientDid ?? undefined,
          ),
          decryptEnvelopeText(
            content.encrypted_content,
            content.encrypted_key,
            thread.recipientDid ?? undefined,
          ),
        ]);
        if (cancelled) return;

        setSubjectTextById((prev) =>
          subjectResult !== ENCRYPTED_PLACEHOLDER
            ? { ...prev, [thread.id]: subjectResult }
            : prev,
        );
        setPreviewTextById((prev) => ({
          ...prev,
          [thread.id]:
            bodyResult === ENCRYPTED_PLACEHOLDER
              ? ENCRYPTED_PLACEHOLDER
              : previewSnippet(bodyResult),
        }));
      }
    };

    const workers = Array.from({ length: PREVIEW_DECRYPT_CONCURRENCY }, worker);
    void Promise.all(workers);

    return () => {
      cancelled = true;
    };
  }, [filteredThreads, keyPresenceByDid, previewTextById, queryClient]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const raw = window.localStorage.getItem(DASHBOARD_UI_PREFS_KEY);
    if (!raw) return;
    try {
      const parsed = JSON.parse(raw) as Partial<DashboardUiPrefs>;
      if (parsed.filter && filterTabs.some((tab) => tab.key === parsed.filter)) {
        setFilter(parsed.filter);
      }
      if (typeof parsed.searchQuery === "string") {
        setSearchQuery(parsed.searchQuery);
      }
      if (typeof parsed.threadWidth === "number") {
        setThreadWidth(Math.max(200, Math.min(800, parsed.threadWidth)));
      }
    } catch {
      window.localStorage.removeItem(DASHBOARD_UI_PREFS_KEY);
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const payload: DashboardUiPrefs = {
      filter,
      searchQuery,
      threadWidth,
    };
    window.localStorage.setItem(DASHBOARD_UI_PREFS_KEY, JSON.stringify(payload));
  }, [filter, searchQuery, threadWidth]);

  return (
    <AppShell
      title={view.title}
      activePath={view.activePath}
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
      <section className={`mail-toolbar mobile-${mobileView}`}>
        <div className="toolbar-group">
          <label className="check-wrap" title={t("inbox.selectAll")}>
            <input type="checkbox" checked={allVisibleSelected} onChange={toggleSelectAll} aria-label={t("inbox.selectAll")} />
          </label>

          <div className="toolbar-divider" aria-hidden="true" />

          <button
            className="toolbar-icon-btn"
            type="button"
            disabled={selectedCount === 0 || updateStatus.isPending}
            onClick={() => void bulkUpdateStatus("read")}
            title={t("inbox.markRead")}
            aria-label={t("inbox.markRead")}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
              <polyline points="22,6 12,13 2,6" />
            </svg>
          </button>

          {/* Gmail-parity: the send-to-{archive,trash,spam} actions make
              sense everywhere EXCEPT when the user is already viewing the
              destination folder. Hide them in spam/trash so the toolbar
              doesn't offer "move to trash" from the trash view itself. */}
          {viewKey !== "spam" && viewKey !== "trash" ? (
            <>
              <button
                className="toolbar-icon-btn"
                type="button"
                disabled={selectedCount === 0 || updateStatus.isPending}
                onClick={() => void bulkUpdateStatus("archived")}
                title={t("inbox.archive")}
                aria-label={t("inbox.archive")}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="21 8 21 21 3 21 3 8" />
                  <rect x="1" y="3" width="22" height="5" />
                  <line x1="10" y1="12" x2="14" y2="12" />
                </svg>
              </button>
              <button
                className="toolbar-icon-btn"
                type="button"
                disabled={selectedCount === 0 || updateFlags.isPending}
                onClick={() => void bulkMoveToFolder("trash")}
                title={t("inbox.moveToTrash")}
                aria-label={t("inbox.moveToTrash")}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="3 6 5 6 21 6" />
                  <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                  <path d="M10 11v6" />
                  <path d="M14 11v6" />
                  <path d="M9 6V4a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v2" />
                </svg>
              </button>
              <button
                className="toolbar-icon-btn"
                type="button"
                disabled={selectedCount === 0 || updateFlags.isPending}
                onClick={() => void bulkMoveToFolder("spam")}
                title={t("inbox.reportSpam")}
                aria-label={t("inbox.reportSpam")}
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="12" y1="8" x2="12" y2="12" />
                  <line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
              </button>
            </>
          ) : null}

          {/* Restore button — shown in spam (as "Not Spam"), trash
              (as "Move to Inbox"), and All Mail. */}
          {viewKey === "spam" || viewKey === "trash" || viewKey === "all" ? (
            <button
              className="toolbar-icon-btn"
              type="button"
              disabled={selectedCount === 0 || updateFlags.isPending}
              onClick={() => void bulkRestoreToInbox()}
              title={viewKey === "spam" ? t("inbox.notSpam") : t("inbox.moveToInbox")}
              aria-label={viewKey === "spam" ? t("inbox.notSpam") : t("inbox.moveToInbox")}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
              </svg>
            </button>
          ) : null}

          {/* Trash-only: permanent delete. Confirmation lives in
              bulkDeleteForever, not here, so the icon stays the same
              shape as the other toolbar icons (consistent visual
              language) and the destructive nature is communicated
              by the confirm dialog + the `is-danger` styling. */}
          {viewKey === "trash" ? (
            <button
              className="toolbar-icon-btn is-danger"
              type="button"
              disabled={selectedCount === 0 || deleteMessage.isPending}
              onClick={() => void bulkDeleteForever()}
              title={t("inbox.deleteForever")}
              aria-label={t("inbox.deleteForever")}
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                <line x1="9" y1="11" x2="15" y2="17" />
                <line x1="15" y1="11" x2="9" y2="17" />
              </svg>
            </button>
          ) : null}

          <div className="toolbar-divider" aria-hidden="true" />

          <button
            className="toolbar-icon-btn"
            type="button"
            disabled={selectedCount === 0}
            onClick={() => bulkSetStar(true)}
            title={t("inbox.addStar")}
            aria-label={t("inbox.addStar")}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
            </svg>
          </button>
          <button
            className="toolbar-icon-btn"
            type="button"
            disabled={selectedCount === 0}
            onClick={() => bulkSetStar(false)}
            title={t("inbox.removeStar")}
            aria-label={t("inbox.removeStar")}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
              <line x1="3" y1="3" x2="21" y2="21" />
            </svg>
          </button>

          {selectedCount > 0 ? (
            <span className="toolbar-selection-count">
              {t("inbox.selectedCount", { count: selectedCount })}
            </span>
          ) : null}

          <div className="filter-tabs" role="tablist" aria-label="フィルター">
            {filterTabs.map((tab) => {
              const className = "filter-tab" + (filter === tab.key ? " active" : "");
              return (
                <button
                  key={tab.key}
                  className={className}
                  type="button"
                  onClick={() => setFilter(tab.key)}
                  role="tab"
                  aria-selected={filter === tab.key}
                >
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="toolbar-group">
          <span className="toolbar-pagination-label">
            {t("inbox.pageOf", { page, totalPages })} · {t("inbox.totalCount", { count: messagesQuery.data?.total ?? baseThreads.length })}
          </span>
          <button
            className="toolbar-icon-btn"
            type="button"
            onClick={goToPreviousPage}
            disabled={!hasPrevPage}
            data-testid="pagination-prev"
            title={t("inbox.prev")}
            aria-label={t("inbox.prev")}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="15 18 9 12 15 6" />
            </svg>
          </button>
          <button
            className="toolbar-icon-btn"
            type="button"
            onClick={goToNextPage}
            disabled={!hasNextPage}
            data-testid="pagination-next"
            title={t("inbox.next")}
            aria-label={t("inbox.next")}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="9 18 15 12 9 6" />
            </svg>
          </button>
        </div>
      </section>

      <section className={`mail-layout mobile-${mobileView}`} style={layoutStyle}>
        <aside className="thread-list">
          {messagesQuery.isLoading ? (
            <div className="empty-state">{t("inbox.loading")}</div>
          ) : filteredThreads.length === 0 ? (
            <div className="empty-state">{view.emptyMessage}</div>
          ) : (
            filteredThreads.map((thread) => {
              const className = "thread-item" + (activeThread?.id === thread.id ? " active" : "") + (thread.status === "unread" ? " unread" : "");

              // Resolve the subject + preview nodes up front. Keeping
              // this outside the JSX lets the Mode-A branch, the
              // pre-decrypt state, and the normal "decrypted" state
              // all feed into the same 3-row layout below without the
              // outer markup having to conditionalise.
              const keyKnownMissing = thread.recipientDid
                ? keyPresenceByDid[thread.recipientDid] === false
                : false;

              let subjectNode: React.ReactNode;
              let previewNode: React.ReactNode;
              if (keyKnownMissing) {
                // Isolated mode (Daemon-isolated) — this browser has no X25519
                // private key for the recipient DID, so we can't
                // decrypt. Render the same "Daemon 管理" pill + helper
                // copy the pre-redesign list used, just split across
                // the two rows instead of jamming them into one span.
                subjectNode = (
                  <span
                    data-state="unavailable_on_this_device"
                    style={{
                      display: "inline-flex",
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
                  </span>
                );
                previewNode = t("inbox.unavailableOnThisDevicePreview");
              } else {
                // Four preview outcomes from the bulk-decrypt effect:
                //   - `undefined`            — not yet decrypted → fall
                //     back to the static "body hidden" placeholder
                //     (which is thread.preview's default value); no
                //     layout jump before the effect reaches this row.
                //   - `""`                   — body was genuinely empty.
                //   - `ENCRYPTED_PLACEHOLDER` — decrypt failed even
                //     though we had the key (corruption, rotation).
                //   - any other string       — the snippet itself.
                const resolvedPreview = previewTextById[thread.id];
                subjectNode = subjectTextById[thread.id] ?? thread.subject;
                if (resolvedPreview === undefined) {
                  previewNode = thread.preview;
                } else if (resolvedPreview === ENCRYPTED_PLACEHOLDER) {
                  previewNode = t("inbox.previewUnavailable");
                } else if (resolvedPreview.length === 0) {
                  previewNode = t("inbox.previewEmpty");
                } else {
                  previewNode = resolvedPreview;
                }
              }

              return (
                <article className={className} key={thread.id} onClick={() => handleOpenThread(thread.id)}>
                  <div className="thread-actions">
                    <input
                      className="thread-check"
                      type="checkbox"
                      checked={selectedIds.includes(thread.id)}
                      onChange={(event) => {
                        event.stopPropagation();
                        toggleSelect(thread.id);
                      }}
                    />
                  </div>
                  <div className="thread-body">
                    {/* Row 1: sender on the left, time on the right. */}
                    <div className="thread-row-top">
                      <p className="thread-sender" title={thread.sender}>
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
                    {/* Row 2: subject (or Mode-A pill). Block-level so
                        `text-overflow: ellipsis` kicks in on narrow
                        panes without fighting a flex row above. */}
                    <span className="thread-subject">{subjectNode}</span>
                    {/* Row 3: body preview on the left, star on the
                        right. Star moved out of the actions column so
                        it sits visually anchored to the preview line,
                        matching Gmail's layout. */}
                    <div className="thread-row-bottom">
                      <span className="thread-preview">{previewNode}</span>
                      <button
                        className={"star-btn" + (thread.starred ? " starred" : "")}
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          toggleStar(thread.id);
                        }}
                        aria-label={t("inbox.starLabel")}
                      >
                        <svg width="18" height="18" viewBox="0 0 24 24" fill={thread.starred ? "currentColor" : "none"} stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </article>
              );
            })
          )}
        </aside>

        <div className="mail-resizer" onMouseDown={startResizeThread} />

        <article className="reader-pane">
          {activeThread ? (
            <>
              <div className="mobile-reader-header">
                <button
                  type="button"
                  className="mobile-back-btn"
                  onClick={() => setMobileView("list")}
                  aria-label={t("nav.back")}
                >
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="19" y1="12" x2="5" y2="12" />
                    <polyline points="12 19 5 12 12 5" />
                  </svg>
                </button>
              </div>
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
                    {t("inbox.addToContacts")}
                  </button>
                ) : null}
              </footer>
            </>
          ) : viewKey === "inbox" && agentCount === 0 ? (
            // First-time user, no agents yet → show the Welcome
            // card instead of the bare "no body" placeholder. Gated
            // to the inbox view so other folders (sent/trash/etc)
            // keep the minimal empty state they've always had.
            <WelcomeNoAgents
              t={t}
              onCreateAgent={() => router.push("/settings/agents/new")}
              onOpenHelp={() => router.push("/help")}
            />
          ) : viewKey === "inbox"
            && agentCount !== null
            && agentCount > 0
            && totalMessages === 0
            && firstAgentAid ? (
            // Agents set up, but no messages have landed yet →
            // surface the AID with copy + test-send affordances so
            // the user can kick the tires without waiting on a
            // third party to send them something.
            <WelcomeNoMessages
              aid={firstAgentAid}
              t={t}
              onSelfSend={() =>
                router.push(
                  `/compose?to=${encodeURIComponent(firstAgentAid)}`,
                )
              }
              onManageAgents={() => router.push("/settings/agents")}
            />
          ) : (
            <div className="empty-state">{t("inbox.noBody")}</div>
          )}
        </article>

        {messagesQuery.error ? (
          <div className="inbox-fetch-error" role="alert">
            {t("inbox.fetchError")}
          </div>
        ) : null}
      </section>
    </AppShell>
  );
}
