"use client";

// One conversation as chat bubbles (docs/35 §2 "会話"): requests as inline
// cards, AI drafts inline, and a composer at the bottom.

import Link from "next/link";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import type { A2AProtocolType } from "@nexusinbox/core/a2a";
import { parseProtocolBody, type A2AProtocolBlock } from "../protocol/parseProtocolBody";
import { ProtocolMessageRouter } from "../protocol/ProtocolMessageRouter";
import { sendProtocolReply } from "../protocol/sendProtocolReply";
import {
  AttachmentList,
  BlockSenderPanel,
  MessageUnavailableCard,
  summariseReply,
  type BlockStatus,
} from "../ConversationThread";
import type { A2ARespondPayload } from "../../../lib/protocol/a2aReply";
import {
  queryKeys as apiQueryKeys,
  useAgentDraftsQuery,
  useDeleteAgentDraftMutation,
  useReviewKeysQuery,
  useSendAgentDraftMutation,
  useSendMessageMutation,
  useUpdateMessageStatusMutation,
} from "../../../lib/api/hooks";
import { defaultApiClient } from "../../../lib/api/client";
import type {
  Agent,
  AgentDraft,
  MessageContentResponse,
  MessageIndexEntry,
} from "../../../lib/api/types";
import {
  decryptEnvelopeText,
  encryptEnvelopeText,
  ENCRYPTED_PLACEHOLDER,
  generateContentKey,
} from "../../../lib/crypto/envelope";
import {
  isValidX25519PublicKeyB64Url,
  wrapContentKeyForRecipient,
  wrapContentKeyForSender,
} from "../../../lib/crypto/keywrap";
import {
  findThisBrowsersReviewKey,
  openDraft,
  senderCopyForDraft,
  type OpenedDraft,
} from "../../../lib/crypto/review-key";
import { signEnvelopePayload } from "../../../lib/crypto/signature";
import {
  getSigningPrivateKey,
  hasSigningPrivateKeyMaterial,
} from "../../../lib/crypto/signing-keyring";
import {
  avatarColorIndex,
  avatarInitial,
  type Conversation,
} from "../../../lib/inbox/conversations";
import { decryptMessageBody, type ViewerKey } from "../../../lib/inbox/decrypt-message";
import { formatThreadExport, threadExportFileName } from "../../../lib/inbox/thread-export";
import { useTranslation, type Locale } from "../../../lib/i18n";

// Same bound as the list's preview decrypt: the X25519 unwrap hits
// IndexedDB, so more in parallel only adds in-flight fetches.
const DECRYPT_CONCURRENCY = 4;

/** Round face: initial on a colour from the DID, with a small 🤖. */
export function Avatar({ did, name, small }: { did: string; name: string; small?: boolean }) {
  return (
    <span
      className={`dm-av dm-c${avatarColorIndex(did)}${small ? " sm" : ""}`}
      aria-hidden="true"
    >
      {avatarInitial(name)}
      <span className="dm-bot">🤖</span>
    </span>
  );
}

type Rendered = {
  state: "loading" | "readable" | "no_key" | "error";
  text: string;
  subject: string;
  protocol: A2AProtocolBlock | null;
  key: ViewerKey | null;
};

const LOADING: Rendered = { state: "loading", text: "", subject: "", protocol: null, key: null };

function dayLabel(iso: string, locale: Locale): string {
  return new Date(iso).toLocaleDateString(locale === "ja" ? "ja-JP" : "en-US", {
    month: "long",
    day: "numeric",
    weekday: "short",
  });
}

function timeLabel(iso: string, locale: Locale): string {
  return new Date(iso).toLocaleTimeString(locale === "ja" ? "ja-JP" : "en-GB", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ConversationView({
  conversation,
  name,
  subLine,
  isContact,
  archiveView,
  agents,
  nameFor,
  onBack,
  onArchived,
}: {
  conversation: Conversation;
  name: string;
  subLine: string | null;
  isContact: boolean;
  archiveView: boolean;
  agents: Agent[];
  /** Display name for any DID in this conversation (for the saved text). */
  nameFor: (did: string, serverLabel: string | null) => string;
  onBack: () => void;
  onArchived: () => void;
}) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const updateStatus = useUpdateMessageStatusMutation();
  const sendMessage = useSendMessageMutation();
  const threadRef = useRef<HTMLDivElement>(null);

  const [rendered, setRendered] = useState<Record<string, Rendered>>({});
  const [menuOpen, setMenuOpen] = useState(false);
  const [blockOpen, setBlockOpen] = useState(false);
  const [blockStatus, setBlockStatus] = useState<BlockStatus | null>(null);
  const [archiveError, setArchiveError] = useState(false);

  const messages = conversation.messages;

  // Mark the counterpart's unread messages read once the conversation is open.
  const markedRef = useRef(new Set<string>());
  useEffect(() => {
    for (const m of messages) {
      if (m.mine || m.entry.status !== "unread" || markedRef.current.has(m.entry.id)) continue;
      markedRef.current.add(m.entry.id);
      updateStatus.mutate({ id: m.entry.id, status: "read" });
    }
  }, [messages]);

  // Fetch and decrypt every message not done yet, a few at a time. A ref
  // tracks what is done, so a re-run (new message, status change) neither
  // repeats finished work nor drops messages a cancelled run left behind.
  const doneRef = useRef(new Set<string>());
  useEffect(() => {
    const queue = messages.filter((m) => !doneRef.current.has(m.entry.id));
    if (queue.length === 0) return;
    let cancelled = false;
    const worker = async () => {
      while (!cancelled) {
        const m = queue.shift();
        if (!m) return;
        let result: Rendered;
        try {
          const content = await queryClient.fetchQuery<MessageContentResponse>({
            queryKey: apiQueryKeys.messageContent(m.entry.id),
            queryFn: () => defaultApiClient.getMessageContent(m.entry.id),
            staleTime: 30_000,
          });
          const body = await decryptMessageBody(content, m.entry, m.mine, conversation.ownDids);
          if (body.state === "readable" && body.key) {
            const parsed = parseProtocolBody(body.text, content.content_type ?? null);
            let subject = "";
            if (m.entry.subject_encrypted) {
              const s = await decryptEnvelopeText(
                m.entry.subject_encrypted,
                body.key.encryptedKey,
                body.key.did,
              );
              subject = s === ENCRYPTED_PLACEHOLDER ? "" : s;
            }
            result = {
              state: "readable",
              text: parsed?.body ?? body.text,
              subject,
              protocol: parsed?.protocol ?? null,
              key: body.key,
            };
          } else {
            result = { ...LOADING, state: body.state === "readable" ? "error" : body.state };
          }
        } catch {
          result = { ...LOADING, state: "error" };
        }
        if (cancelled) return;
        doneRef.current.add(m.entry.id);
        setRendered((prev) => ({ ...prev, [m.entry.id]: result }));
      }
    };
    void Promise.all(Array.from({ length: DECRYPT_CONCURRENCY }, worker));
    return () => {
      cancelled = true;
    };
  }, [messages, conversation.ownDids, queryClient]);

  // Keep the newest message in view while bodies load, unless the person
  // scrolled up to read.
  const stickToBottom = useRef(true);
  useEffect(() => {
    const el = threadRef.current;
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, [messages.length, rendered]);

  // My replies the auto-reply sent, by their message id.
  const autoReplyIds = useMemo(
    () =>
      new Set(
        messages
          .map((m) => m.entry.auto_reply_message_id)
          .filter((id): id is string => Boolean(id)),
      ),
    [messages],
  );

  async function handleProtocolRespond(
    entry: MessageIndexEntry,
    protocolType: A2AProtocolType,
    originalProtocolId: string,
    subjectText: string,
    reply: A2ARespondPayload,
  ): Promise<void> {
    const replySubject = subjectText.startsWith("Re:")
      ? subjectText
      : `Re: ${subjectText || t("common.noSubject")}`;
    await sendProtocolReply({
      protocolType,
      reply,
      threadId: entry.thread_id ?? entry.id,
      originalProtocolId,
      subject: replySubject,
      bodySummary: summariseReply(reply, t),
      viewerAgentDid: entry.recipient_did,
      proposerDid: entry.sender_did,
      senderEncryptionKey: conversation.ownAgent?.encryption_key,
      sendMessage: sendMessage.mutateAsync,
    });
  }

  const handleArchive = async () => {
    setMenuOpen(false);
    setArchiveError(false);
    const results = await Promise.allSettled(
      messages.map((m) => updateStatus.mutateAsync({ id: m.entry.id, status: "archived" })),
    );
    if (results.some((r) => r.status === "rejected")) {
      setArchiveError(true);
      return;
    }
    onArchived();
  };

  // Save what this browser decrypted as a text file, so people can keep a
  // conversation past the server's 90-day retention (docs/28 §5 P2-7).
  const handleSave = () => {
    setMenuOpen(false);
    const savedAt = new Date();
    const firstSubject = messages.map((m) => rendered[m.entry.id]?.subject).find(Boolean);
    const text = formatThreadExport({
      subject: firstSubject || name,
      savedAt,
      notDecryptedNote: t("inbox.exportNotDecrypted"),
      messages: messages.map(({ entry }) => {
        const r = rendered[entry.id];
        const readable = r?.state === "readable";
        return {
          senderLabel: nameFor(entry.sender_did, entry.sender_label),
          senderDid: entry.sender_did,
          recipientLabel: nameFor(entry.recipient_did, entry.recipient_label),
          recipientDid: entry.recipient_did,
          createdAt: entry.created_at,
          subject: r?.subject ?? "",
          body: readable ? r.text : null,
          protocol: readable ? r.protocol : null,
        };
      }),
    });
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = threadExportFileName(savedAt);
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  const latestReceived = conversation.latestReceived;
  let lastDay = "";
  // A subject is shown when it changes, not on every reply.
  let lastSubject = "";
  const bareSubject = (subject: string) => subject.replace(/^(re:\s*)+/i, "").trim();

  return (
    <div className="dm-conv">
      <header className="dm-conv-head">
        <button type="button" className="dm-icon-btn dm-back" onClick={onBack} aria-label={t("messages.back")}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <line x1="19" y1="12" x2="5" y2="12" />
            <polyline points="12 19 5 12 12 5" />
          </svg>
        </button>
        <Avatar did={conversation.counterpartDid} name={name} small />
        <div className="dm-conv-who">
          <h2 title={name}>{name}</h2>
          {subLine ? <div className="dm-sub">{subLine}</div> : null}
        </div>
        <div className="dm-menu-wrap">
          <button
            type="button"
            className="dm-icon-btn"
            aria-label={t("messages.more")}
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((v) => !v)}
            data-testid="conversation-menu"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <circle cx="5" cy="12" r="2" />
              <circle cx="12" cy="12" r="2" />
              <circle cx="19" cy="12" r="2" />
            </svg>
          </button>
          {menuOpen ? (
            <>
              <button
                type="button"
                className="dm-menu-backdrop"
                aria-label={t("nav.closeMenu")}
                onClick={() => setMenuOpen(false)}
              />
              <div className="dm-menu" role="menu">
                {!archiveView ? (
                  <button type="button" role="menuitem" onClick={() => void handleArchive()}>
                    {t("messages.archive")}
                  </button>
                ) : null}
                {!isContact ? (
                  <Link
                    role="menuitem"
                    href={`/contacts?add=${encodeURIComponent(conversation.counterpartDid)}`}
                    data-testid="conversation-add-contact"
                  >
                    {t("messages.addContact")}
                  </Link>
                ) : null}
                {latestReceived ? (
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      setMenuOpen(false);
                      setBlockStatus(null);
                      setBlockOpen(true);
                    }}
                    data-testid="conversation-block-sender"
                  >
                    {t("messages.block")}
                  </button>
                ) : null}
                <button
                  type="button"
                  role="menuitem"
                  onClick={handleSave}
                  title={t("inbox.saveThreadTooltip")}
                  data-testid="conversation-save"
                >
                  {t("messages.save")}
                </button>
              </div>
            </>
          ) : null}
        </div>
      </header>

      <div
        className="dm-thread"
        ref={threadRef}
        onScroll={(event) => {
          const el = event.currentTarget;
          stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
        }}
      >
        {blockOpen && latestReceived ? (
          <BlockSenderPanel
            messageId={latestReceived.id}
            onClose={() => setBlockOpen(false)}
            onResult={setBlockStatus}
          />
        ) : null}
        {blockStatus && !blockOpen ? (
          <p className={"dm-status" + (blockStatus.kind === "error" ? " error" : "")} role="status">
            {blockStatus.text}
          </p>
        ) : null}
        {archiveError ? (
          <p className="dm-status error" role="alert">
            {t("messages.archiveFailed")}
          </p>
        ) : null}

        <div className="dm-sys">{t("messages.encryptedNotice")}</div>

        {messages.map(({ entry, mine }) => {
          const r = rendered[entry.id] ?? LOADING;
          const day = dayLabel(entry.created_at, locale);
          const showDay = day !== lastDay;
          lastDay = day;
          const isAutoReply = mine && autoReplyIds.has(entry.id);
          const time = timeLabel(entry.created_at, locale);
          const subject = r.protocol ? "" : bareSubject(r.subject);
          const showSubject = subject !== "" && subject !== lastSubject;
          if (subject) lastSubject = subject;

          let body: React.ReactNode;
          if (r.state === "loading") {
            body = <div className="dm-bubble muted">{t("messages.loadingBody")}</div>;
          } else if (r.state === "readable" && r.protocol) {
            const protocol = r.protocol;
            body = (
              <div className="dm-card">
                <ProtocolMessageRouter
                  protocol={protocol}
                  bodyText={r.text}
                  context={{
                    // My own requests are never answerable from my side.
                    folder: mine ? "sent" : entry.folder,
                    threadId: entry.thread_id ?? null,
                    originalProtocolId: protocol.id,
                  }}
                  onRespond={
                    mine
                      ? undefined
                      : (reply) =>
                          handleProtocolRespond(entry, protocol.type, protocol.id, r.subject, reply)
                  }
                />
              </div>
            );
          } else if (r.state === "readable") {
            body = <div className="dm-bubble">{r.text}</div>;
          } else if (mine) {
            body = <div className="dm-bubble muted">{t("messages.mineLocked")}</div>;
          } else {
            const content = queryClient.getQueryData<MessageContentResponse>(
              apiQueryKeys.messageContent(entry.id),
            );
            body = (
              <MessageUnavailableCard
                state={r.state === "no_key" ? "unavailable_on_this_device" : "decrypt_failed"}
                messageId={entry.id}
                recipientDid={entry.recipient_did}
                encryptedContent={content?.encrypted_content ?? ""}
                encryptedKey={content?.encrypted_key ?? ""}
                subjectEncrypted={entry.subject_encrypted ?? ""}
              />
            );
          }

          return (
            <div key={entry.id} className="dm-item">
              {showDay ? <div className="dm-sys">{day}</div> : null}
              <div className={"dm-msg" + (mine ? " mine" : "")} data-testid="dm-message">
                {mine ? null : <Avatar did={conversation.counterpartDid} name={name} small />}
                <div className="dm-msg-body">
                  {showSubject ? <div className="dm-subject">{r.subject}</div> : null}
                  {body}
                  {r.state === "readable" && r.key ? (
                    <AttachmentList
                      messageId={entry.id}
                      recipientDid={r.key.did}
                      encryptedKey={r.key.encryptedKey}
                    />
                  ) : null}
                  <div className="dm-meta">
                    {isAutoReply ? `${t("messages.autoReplyMark")} · ` : ""}
                    {time}
                  </div>
                </div>
              </div>
            </div>
          );
        })}

        <ConversationDrafts conversation={conversation} agents={agents} />
      </div>

      <Composer conversation={conversation} />
    </div>
  );
}

/** AI drafts for this pair, inline as dashed cards (docs/33 §9, docs/35 §2). */
function ConversationDrafts({
  conversation,
  agents,
}: {
  conversation: Conversation;
  agents: Agent[];
}) {
  const { t } = useTranslation();
  const draftsQuery = useAgentDraftsQuery();
  const keysQuery = useReviewKeysQuery();
  const sendDraft = useSendAgentDraftMutation();
  const deleteDraft = useDeleteAgentDraftMutation();
  const [opened, setOpened] = useState<Record<string, OpenedDraft | null>>({});
  const [keyId, setKeyId] = useState<string | null | undefined>(undefined);
  const [status, setStatus] = useState("");

  const ownAid = conversation.ownAgent?.aid;
  const drafts = useMemo(
    () =>
      (draftsQuery.data?.drafts ?? []).filter(
        (d) =>
          (d.aid === ownAid || conversation.ownDids.includes(d.sender_did)) &&
          d.recipient_did === conversation.counterpartDid,
      ),
    [draftsQuery.data, ownAid, conversation.ownDids, conversation.counterpartDid],
  );
  const keys = keysQuery.data?.review_keys;

  useEffect(() => {
    if (drafts.length === 0 || !keys) return;
    let cancelled = false;
    findThisBrowsersReviewKey(keys).then((key) => {
      if (!cancelled) setKeyId(key?.id ?? null);
    });
    return () => {
      cancelled = true;
    };
  }, [drafts.length, keys]);

  useEffect(() => {
    if (!keyId) return;
    const missing = drafts.filter((d) => !(d.id in opened));
    if (missing.length === 0) return;
    let cancelled = false;
    Promise.all(missing.map(async (d) => [d.id, await openDraft(d, keyId)] as const)).then(
      (pairs) => {
        if (!cancelled) setOpened((prev) => ({ ...prev, ...Object.fromEntries(pairs) }));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [drafts, keyId, opened]);

  if (drafts.length === 0) return null;

  if (keyId === null) {
    return (
      <div className="dm-msg mine">
        <div className="dm-draft">
          <p>{t("messages.draftNoKey")}</p>
          <Link href="/pending" className="dm-link">
            {t("messages.draftSetUp")}
          </Link>
        </div>
      </div>
    );
  }

  const handleSend = async (draft: AgentDraft) => {
    setStatus("");
    try {
      const senderEncryptedKey = await senderCopyForDraft(draft, opened[draft.id], agents);
      await sendDraft.mutateAsync({ id: draft.id, senderEncryptedKey });
    } catch {
      setStatus(t("agentDrafts.sendFailed"));
    }
  };

  const handleDiscard = async (draft: AgentDraft) => {
    setStatus("");
    try {
      await deleteDraft.mutateAsync(draft.id);
    } catch {
      setStatus(t("agentDrafts.discardFailed"));
    }
  };

  return (
    <>
      {drafts.map((draft) => {
        const plain = opened[draft.id];
        return (
          <div key={draft.id} className="dm-msg mine" data-testid="dm-draft">
            <div className="dm-draft">
              <h4>
                {draft.via
                  ? t("messages.draftTitleVia", { via: draft.via })
                  : t("messages.draftTitle")}
              </h4>
              {plain === undefined ? (
                <p className="dm-muted">{t("messages.loadingBody")}</p>
              ) : plain ? (
                <>
                  {plain.subject ? <div className="dm-subject">{plain.subject}</div> : null}
                  <p className="dm-draft-body">{plain.body}</p>
                </>
              ) : (
                <p className="dm-muted">{t("agentDrafts.unreadableBody")}</p>
              )}
              <div className="dm-btns">
                <button
                  type="button"
                  className="dm-btn accent"
                  onClick={() => void handleSend(draft)}
                  disabled={!plain || sendDraft.isPending}
                >
                  {t("messages.draftSend")}
                </button>
                <button
                  type="button"
                  className="dm-btn"
                  onClick={() => void handleDiscard(draft)}
                  disabled={deleteDraft.isPending}
                >
                  {t("messages.draftDiscard")}
                </button>
              </div>
              <p className="dm-muted">{t("messages.draftNote")}</p>
            </div>
          </div>
        );
      })}
      {status ? (
        <p className="dm-status error" role="alert">
          {status}
        </p>
      ) : null}
    </>
  );
}

/**
 * Plain-text reply from the conversation's own agent. Only for agents whose
 * signing key is in this browser; subject and attachments stay on /compose.
 */
function Composer({ conversation }: { conversation: Conversation }) {
  const { t } = useTranslation();
  const sendMessage = useSendMessageMutation();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(false);
  // undefined: still checking; null: no signing key here.
  const [senderDid, setSenderDid] = useState<string | null | undefined>(undefined);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const { ownDid, ownDids, ownAgent, counterpartDid, threadId, latest, latestReceived } =
    conversation;

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      for (const did of Array.from(new Set([ownDid, ...ownDids]))) {
        if (await hasSigningPrivateKeyMaterial(did)) {
          if (!cancelled) setSenderDid(did);
          return;
        }
      }
      if (!cancelled) setSenderDid(null);
    })();
    return () => {
      cancelled = true;
    };
  }, [ownDid, ownDids]);

  // Grow with the text, up to the CSS max-height.
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = el.scrollHeight + "px";
  }, [text]);

  const composeHref = latestReceived
    ? `/compose?reply=${encodeURIComponent(latestReceived.id)}`
    : `/compose?to=${encodeURIComponent(counterpartDid)}`;

  const send = async () => {
    const body = text.trim();
    if (!body || !senderDid || sending) return;
    setSending(true);
    setError(false);
    try {
      const resolved = await defaultApiClient.resolveRecipient(counterpartDid);
      const recipientEncryptionKey = resolved.encryption_public_key;
      if (!recipientEncryptionKey || !isValidX25519PublicKeyB64Url(recipientEncryptionKey)) {
        throw new Error("recipient has no usable encryption key");
      }
      const signingPrivateKey = await getSigningPrivateKey(senderDid);
      if (!signingPrivateKey) throw new Error("signing key missing");
      const contentKey = generateContentKey();
      const encryptedSubject = await encryptEnvelopeText("", { contentKey });
      const encryptedBody = await encryptEnvelopeText(body, { contentKey });
      const wrapped = await wrapContentKeyForRecipient(contentKey, recipientEncryptionKey);
      const senderEncryptedKey = await wrapContentKeyForSender(contentKey, ownAgent?.encryption_key);
      const signature = await signEnvelopePayload({
        signingPrivateKey,
        senderDid,
        recipientDid: resolved.did,
        subjectEncrypted: encryptedSubject.serialized,
        encryptedContent: encryptedBody.serialized,
        encryptedKey: wrapped.wrappedKey,
        nonce: encryptedBody.nonce,
      });
      await sendMessage.mutateAsync({
        senderDid,
        recipientDid: resolved.did,
        subjectEncrypted: encryptedSubject.serialized,
        encryptedContent: encryptedBody.serialized,
        encryptedKey: wrapped.wrappedKey,
        nonce: encryptedBody.nonce,
        signature,
        threadId: threadId ?? latest.entry.id,
        senderEncryptedKey,
      });
      setText("");
    } catch {
      setError(true);
    } finally {
      setSending(false);
    }
  };

  if (senderDid === undefined) return <div className="dm-composer" />;

  if (senderDid === null) {
    return (
      <div className="dm-composer note">
        <p>{t("messages.composerOnComputer")}</p>
      </div>
    );
  }

  return (
    <form
      className="dm-composer"
      onSubmit={(event) => {
        event.preventDefault();
        void send();
      }}
    >
      <div className="dm-composer-row">
        <textarea
          ref={textareaRef}
          rows={1}
          value={text}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={(event) => {
            // Ctrl/Cmd+Enter sends; Enter alone makes a new line.
            if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
              event.preventDefault();
              void send();
            }
          }}
          placeholder={t("messages.composerPlaceholder")}
          aria-label={t("messages.composerPlaceholder")}
          disabled={sending}
          data-testid="dm-composer-input"
        />
        <button
          type="submit"
          className="dm-send"
          disabled={sending || text.trim().length === 0}
          aria-label={t("messages.send")}
          data-testid="dm-composer-send"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <line x1="12" y1="19" x2="12" y2="5" />
            <polyline points="5 12 12 5 19 12" />
          </svg>
        </button>
      </div>
      <div className="dm-composer-foot">
        {error ? (
          <span className="dm-error" role="alert">
            {t("messages.sendFailed")}
          </span>
        ) : null}
        <Link href={composeHref} className="dm-link">
          {t("messages.composeMore")}
        </Link>
      </div>
    </form>
  );
}
