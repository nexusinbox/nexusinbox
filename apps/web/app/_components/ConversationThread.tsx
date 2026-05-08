"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
// Use the browser-safe subpath export — the main `@nexusinbox/core`
// entry pulls in node:crypto / node:net via the Node API client, which
// webpack can't bundle for the Next.js browser build.
import { deriveMessageState, type MessageVisibilityState } from "@nexusinbox/core/visibility";
import { parseProtocolBody, type A2AProtocolBlock } from "./protocol/parseProtocolBody";
import { ProtocolMessageRouter } from "./protocol/ProtocolMessageRouter";
import { sendProtocolReply } from "./protocol/sendProtocolReply";
import type { A2ARespondPayload } from "../../lib/protocol/a2aReply";
import type { A2AProtocolType } from "@nexusinbox/core/a2a";
import {
  useBlockFromMessageMutation,
  useContactsQuery,
  useMessageAttachmentsQuery,
  useMessageContentQuery,
  useMessagesQuery,
  useSendMessageMutation,
} from "../../lib/api/hooks";
import { ApiError, defaultApiClient } from "../../lib/api/client";
import type { BlockLevel } from "../../lib/api/types";
import {
  decryptEnvelopeText,
  decryptEnvelopeTextWithContentKey,
  decryptEnvelopeTextWithState,
  ENCRYPTED_PLACEHOLDER,
} from "../../lib/crypto/envelope";
import { BridgeClient } from "../../lib/bridge/client";
import {
  loadBridgeSessionNonce,
  loadBridgeToken,
} from "../../lib/bridge/token-store";
import { unwrapContentKeyWithRecipientPrivateKey } from "../../lib/crypto/keywrap";
import {
  getRecipientPrivateKey,
  hasRecipientPrivateKey,
} from "../../lib/crypto/recipient-keyring";
import {
  decryptAttachment,
  decodeAttachmentKey,
  sha256OfBytes,
} from "../../lib/crypto/attachment";
import { indexContactsByDid, resolveParticipantLabel } from "../../lib/api/labels";
import { useTranslation } from "../../lib/i18n";
import type {
  AttachmentMetadataPlain,
  MessageContentResponse,
  MessageIndexEntry,
} from "../../lib/api/types";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

type ConversationThreadProps = {
  // The message the user clicked on. The component uses it as the
  // seed, discovers the thread_id, and renders every message in
  // that thread (or just this one if it's a standalone message).
  rootMessageId: string;
};

function summariseReply(
  reply: A2ARespondPayload,
  t: (key: string, params?: Record<string, string | number>) => string,
): string {
  switch (reply.action) {
    case "accept":
      if ("selected_candidate" in reply && reply.selected_candidate) {
        return t("a2a.acceptedAt", {
          time: `${reply.selected_candidate.start} – ${reply.selected_candidate.end}`,
        });
      }
      // task_delegation accept — no candidate to echo.
      return t("a2a.taskAcceptedSummary");
    case "decline":
      return t("a2a.declinedBadge");
    case "counter":
      return t("a2a.counterBadge");
    case "complete":
      return t("a2a.taskCompletedSummary");
  }
}

type RenderableMessage = {
  entry: MessageIndexEntry;
  bodyText: string;
  subjectText: string;
  /**
   * Visibility state for this message — split out so the UI can render
   * the explanatory card (`unavailable_on_this_device` /
   * `decrypt_failed`) instead of a perpetual decrypting placeholder
   * the user can't distinguish from genuine loading. See
   * docs/21_message_visibility_ux_for_mcp_modes.md §4.
   */
  state: MessageVisibilityState;
  /**
   * Parsed A2A protocol block if the envelope's content_type declared
   * an A2A payload and the body parsed successfully. `null` for
   * plain-text messages or when parsing failed — in either case the
   * markdown renderer handles `bodyText` as before. See docs/24 for
   * the protocol design.
   */
  protocol: A2AProtocolBlock | null;
};

// A Gmail-style stacked conversation view. Each message in the
// thread gets its own header (sender label + time) and body panel,
// oldest first. Bodies and subjects are decrypted client side.
export function ConversationThread({ rootMessageId }: ConversationThreadProps) {
  const { t } = useTranslation();
  const rootContent = useMessageContentQuery(rootMessageId);
  const threadId = rootContent.data?.thread_id ?? null;

  const threadListQuery = useMessagesQuery({
    agentDid: "all",
    status: "all",
    threadId: threadId ?? undefined,
    perPage: 100,
  });

  const contactsQuery = useContactsQuery();
  const contactsByDid = useMemo(
    () => indexContactsByDid(contactsQuery.data?.contacts),
    [contactsQuery.data],
  );

  // A2A protocol replies (Accept / Decline on a schedule_negotiation
  // propose) go through the same send pipeline as a compose message.
  // We fan out to `sendProtocolReply` so ConversationThread itself
  // only owns the per-message glue (sender / recipient DIDs, thread
  // inheritance) — the envelope build lives in the helper.
  const sendMessageMutation = useSendMessageMutation();
  async function handleProtocolRespond(
    entry: MessageIndexEntry,
    rootId: string,
    protocolType: A2AProtocolType,
    originalProtocolId: string,
    subjectText: string,
    reply: A2ARespondPayload,
  ): Promise<void> {
    const replySubject = subjectText.startsWith("Re:")
      ? subjectText
      : `Re: ${subjectText || t("common.noSubject")}`;
    const bodySummary = summariseReply(reply, t);
    await sendProtocolReply({
      protocolType,
      reply,
      // Inherit the envelope-level thread id so the reply lands in
      // the same conversation view. Fall back to the root message
      // id so an untraced original still produces a sane thread.
      threadId: entry.thread_id ?? rootId,
      originalProtocolId,
      subject: replySubject,
      bodySummary,
      viewerAgentDid: entry.recipient_did,
      proposerDid: entry.sender_did,
      sendMessage: sendMessageMutation.mutateAsync,
    });
  }

  // Per-message "Block this sender" panel — closed by default. We
  // key the open-state by message_id so only one panel is expanded
  // at a time across the whole thread. The mutation hook
  // invalidates `/blocks` on success so /settings/blocks reflects
  // the new row immediately.
  const [blockOpenFor, setBlockOpenFor] = useState<string | null>(null);
  const [blockStatus, setBlockStatus] = useState<
    { kind: "success" | "error"; text: string } | null
  >(null);
  const blockMutation = useBlockFromMessageMutation();

  async function confirmAndBlock(messageId: string, level: BlockLevel) {
    const confirmKey =
      level === "l1_did"
        ? "inbox.blockConfirmL1"
        : level === "l2_identity"
          ? "inbox.blockConfirmL2"
          : "inbox.blockConfirmL3";
    if (typeof window !== "undefined" && !window.confirm(t(confirmKey))) {
      return;
    }
    try {
      await blockMutation.mutateAsync({ messageId, payload: { level } });
      const successKey =
        level === "l1_did"
          ? "inbox.blockSuccessL1"
          : level === "l2_identity"
            ? "inbox.blockSuccessL2"
            : "inbox.blockSuccessL3";
      setBlockStatus({ kind: "success", text: t(successKey) });
      setBlockOpenFor(null);
    } catch (err) {
      // 422 is the documented "sender not registered" case — only
      // possible at L2/L3, and means the sender has no row in our
      // users table so world_id_hash can't be resolved. Surface the
      // L1-fallback hint directly instead of a generic error.
      if (err instanceof ApiError && err.status === 422) {
        setBlockStatus({
          kind: "error",
          text: t("inbox.blockFailSenderNotRegistered"),
        });
      } else {
        setBlockStatus({ kind: "error", text: t("inbox.blockFailGeneric") });
      }
    }
  }
  // DIDs that already have a contact entry, so we can hide the
  // "add to contacts" button for them and prevent duplicate work.
  const knownContactDids = useMemo(() => {
    const dids = contactsQuery.data?.contacts?.map((c) => c.did) ?? [];
    return new Set(dids);
  }, [contactsQuery.data]);

  // If the root message has no thread, fall back to showing just it
  // so the component works for standalone messages too.
  const members: MessageIndexEntry[] = useMemo(() => {
    if (threadId && threadListQuery.data?.messages) {
      // Backend returns DESC; flip to chronological order.
      return [...threadListQuery.data.messages].sort(
        (a, b) => a.created_at.localeCompare(b.created_at),
      );
    }
    return [];
  }, [threadId, threadListQuery.data]);

  // Imperatively fetch content for every member we don't already
  // have (the root is covered by useMessageContentQuery).
  const [contents, setContents] = useState<Record<string, MessageContentResponse>>({});
  useEffect(() => {
    if (members.length === 0) return;
    const missing = members.filter(
      (m) => m.id !== rootMessageId && !contents[m.id],
    );
    if (missing.length === 0) return;
    let cancelled = false;
    void (async () => {
      const pairs = await Promise.all(
        missing.map(async (m) => {
          try {
            const data = await defaultApiClient.getMessageContent(m.id);
            return [m.id, data] as const;
          } catch {
            return null;
          }
        }),
      );
      if (cancelled) return;
      setContents((prev) => {
        const next = { ...prev };
        for (const pair of pairs) {
          if (pair) next[pair[0]] = pair[1];
        }
        return next;
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [members, rootMessageId, contents]);

  // Decrypt body + subject for every message that has content loaded.
  const [rendered, setRendered] = useState<RenderableMessage[]>([]);
  useEffect(() => {
    let cancelled = false;
    const list: MessageIndexEntry[] =
      members.length > 0
        ? members
        : rootContent.data
          ? [
              {
                id: rootMessageId,
                sender_did: rootContent.data.sender_did ?? "",
                sender_label: null,
                recipient_did: rootContent.data.recipient_did ?? "",
                recipient_label: null,
                thread_id: rootContent.data.thread_id ?? null,
                subject_encrypted: rootContent.data.subject_encrypted ?? "",
                status: "read",
                priority: "normal",
                ai_category: null,
                created_at: new Date().toISOString(),
                trust_score: 0,
                folder: "inbox",
                starred: false,
              },
            ]
          : [];

    void (async () => {
      const next: RenderableMessage[] = [];
      for (const entry of list) {
        const content =
          entry.id === rootMessageId ? rootContent.data : contents[entry.id];
        if (!content) continue;

        // Run the rich-state decrypt for body, then run the same for
        // subject if present. Body outcome is the authoritative signal
        // because subject is optional and we don't want an empty
        // subject to look like a decrypt failure.
        const bodyResult = await decryptEnvelopeTextWithState(
          content.encrypted_content,
          content.encrypted_key,
          entry.recipient_did,
        );
        const hasKey = await hasRecipientPrivateKey(entry.recipient_did);
        const outcome =
          bodyResult.state === "readable" || bodyResult.state === "passthrough"
            ? "ok"
            : bodyResult.state;
        // Without a backend `key_holder` hint yet (docs/21 §7, phase 2
        // backend work), default to `unknown`. `deriveMessageState`
        // then falls back to Mode-B behaviour so existing Mode-B
        // credentials continue to render identically; only the
        // no-local-key path surfaces the Daemon-isolated UX — which is
        // exactly the Isolated mode case we want to cover today.
        const state = deriveMessageState({
          recipientKeyHolder: "unknown",
          localHasPrivateKey: hasKey,
          decryptOutcome: outcome,
        });

        let subjectText: string;
        if (state === "readable") {
          subjectText = entry.subject_encrypted
            ? await decryptEnvelopeText(
                entry.subject_encrypted,
                content.encrypted_key,
                entry.recipient_did,
              )
            : "";
          if (subjectText === ENCRYPTED_PLACEHOLDER) subjectText = "";
        } else if (state === "unavailable_on_this_device") {
          subjectText = t("inbox.unavailableOnThisDeviceSubject");
        } else if (state === "decrypt_failed") {
          subjectText = t("inbox.decryptFailedSubject");
        } else {
          // state === "decrypting"
          subjectText = t("inbox.decryptingSubject");
        }

        // Parse the decrypted body as an A2A payload when the envelope's
        // content_type advertises one. For legacy text/plain bodies this
        // is a no-op fallback. See docs/24 §2 for the dispatch contract.
        const contentType = content.content_type ?? null;
        const parsedBody =
          state === "readable"
            ? parseProtocolBody(bodyResult.text, contentType)
            : null;
        const bodyText =
          state === "readable"
            ? (parsedBody?.body ?? bodyResult.text)
            : state === "unavailable_on_this_device"
              ? t("inbox.unavailableOnThisDeviceCardBody")
              : state === "decrypt_failed"
                ? t("inbox.decryptFailedCardBody")
                : t("inbox.bodyLoading");
        const protocol = parsedBody?.protocol ?? null;

        next.push({ entry, bodyText, subjectText, state, protocol });
      }
      if (!cancelled) setRendered(next);
    })();

    return () => {
      cancelled = true;
    };
  }, [members, contents, rootContent.data, rootMessageId, t]);

  if (rootContent.isLoading) {
    return <div className="empty-state">{t("inbox.loading")}</div>;
  }
  if (rendered.length === 0) {
    return <div className="empty-state">{t("inbox.loading")}</div>;
  }

  const threadSubject = rendered[0]?.subjectText ?? t("common.noSubject");

  return (
    <div className="conversation-thread">
      <header className="conversation-head">
        <h2 className="reader-subject">{threadSubject}</h2>
        <p className="item-sub">{t("common.items", { count: rendered.length })}</p>
      </header>
      <div className="conversation-list">
        {rendered.map(({ entry, bodyText, subjectText, state, protocol }, index) => {
          const senderLabel = resolveParticipantLabel(
            entry.sender_did,
            entry.sender_label,
            contactsByDid,
          );
          const time = new Date(entry.created_at).toLocaleString("ja-JP", {
            hour: "2-digit",
            minute: "2-digit",
            month: "numeric",
            day: "numeric",
          });
          const isLatest = index === rendered.length - 1;
          return (
            <article
              key={entry.id}
              className={
                "conversation-message" + (isLatest ? " latest" : "")
              }
            >
              <header className="conversation-message-head">
                <div className="reader-avatar">
                  {(senderLabel[0] ?? "?").toUpperCase()}
                </div>
                <div className="reader-meta-text">
                  <h3 title={entry.sender_did}>{senderLabel}</h3>
                  <p>
                    {subjectText !== threadSubject ? subjectText + " · " : ""}
                    {time}
                  </p>
                </div>
                {entry.sender_did && !knownContactDids.has(entry.sender_did) ? (
                  <Link
                    href={`/contacts?add=${encodeURIComponent(entry.sender_did)}`}
                    className="conversation-add-contact"
                    aria-label={t("inbox.addToContacts")}
                    title={t("inbox.addToContacts")}
                    data-testid="conversation-add-contact"
                  >
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                      <circle cx="9" cy="7" r="4" />
                      <line x1="19" y1="8" x2="19" y2="14" />
                      <line x1="22" y1="11" x2="16" y2="11" />
                    </svg>
                  </Link>
                ) : null}
                {entry.sender_did ? (
                  <button
                    type="button"
                    className="conversation-add-contact"
                    aria-label={t("inbox.blockSender")}
                    title={t("inbox.blockSender")}
                    aria-expanded={blockOpenFor === entry.id}
                    data-testid="conversation-block-sender"
                    onClick={() => {
                      setBlockOpenFor((prev) =>
                        prev === entry.id ? null : entry.id,
                      );
                      setBlockStatus(null);
                    }}
                    style={{
                      background: "transparent",
                      border: "none",
                      padding: 4,
                      cursor: "pointer",
                      color: "inherit",
                    }}
                  >
                    {/* Shield-with-slash icon — signals "block" without
                        using a scary trash-style glyph that would imply
                        deletion. */}
                    <svg
                      width="18"
                      height="18"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      aria-hidden="true"
                    >
                      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      <line x1="5" y1="5" x2="19" y2="19" />
                    </svg>
                  </button>
                ) : null}
              </header>
              {blockOpenFor === entry.id ? (
                <div
                  className="conversation-block-panel"
                  role="dialog"
                  aria-label={t("inbox.blockPanelTitle")}
                >
                  <div>
                    <p
                      className="item-title"
                      style={{ margin: 0, fontSize: 13, fontWeight: 700 }}
                    >
                      {t("inbox.blockPanelTitle")}
                    </p>
                    <p
                      className="item-sub"
                      style={{ margin: "4px 0 0 0", fontSize: 12 }}
                    >
                      {t("inbox.blockPanelDesc")}
                    </p>
                  </div>
                  {(
                    [
                      ["l1_did", "blockLevelL1", "blockLevelL1Desc"],
                      ["l2_identity", "blockLevelL2", "blockLevelL2Desc"],
                      ["l3_stealth", "blockLevelL3", "blockLevelL3Desc"],
                    ] as const
                  ).map(([lvl, labelKey, descKey]) => (
                    <button
                      key={lvl}
                      type="button"
                      className="btn-premium secondary"
                      onClick={() => void confirmAndBlock(entry.id, lvl)}
                      disabled={blockMutation.isPending}
                      style={{
                        flexDirection: "column",
                        alignItems: "flex-start",
                        gap: 2,
                        padding: "10px 12px",
                        textAlign: "left",
                        borderColor: "rgba(220, 38, 38, 0.2)",
                        color: "#b91c1c",
                      }}
                    >
                      <span style={{ fontSize: 12, fontWeight: 700 }}>
                        {t("inbox." + labelKey)}
                      </span>
                      <span
                        className="item-sub"
                        style={{ margin: 0, fontSize: 11, color: "inherit", opacity: 0.8 }}
                      >
                        {t("inbox." + descKey)}
                      </span>
                    </button>
                  ))}
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 8,
                      marginTop: 4,
                    }}
                  >
                    <button
                      type="button"
                      className="btn-premium outline"
                      onClick={() => setBlockOpenFor(null)}
                      disabled={blockMutation.isPending}
                      style={{ fontSize: 12, padding: "6px 12px" }}
                    >
                      {t("inbox.blockCancel")}
                    </button>
                    {blockMutation.isPending ? (
                      <span className="item-sub" style={{ fontSize: 11 }}>
                        {t("inbox.blockBusy")}
                      </span>
                    ) : null}
                  </div>
                </div>
              ) : null}
              {blockStatus && blockOpenFor === null ? (
                // Surface the last status only briefly after the
                // panel closes — the full record also lives in
                // /settings/blocks so we don't need a persistent
                // banner here.
                <p
                  className="item-sub"
                  role="status"
                  style={{
                    margin: "4px 0 8px 0",
                    fontSize: 12,
                    color: blockStatus.kind === "success" ? "#188038" : "#c5221f",
                  }}
                >
                  {blockStatus.text}
                </p>
              ) : null}
              {state === "readable" ? (
                protocol ? (
                  <ProtocolMessageRouter
                    protocol={protocol}
                    bodyText={bodyText}
                    context={{
                      folder: entry.folder,
                      threadId: entry.thread_id ?? null,
                      originalProtocolId: protocol.id,
                    }}
                    onRespond={(reply) =>
                      handleProtocolRespond(
                        entry,
                        rootMessageId,
                        protocol.type,
                        protocol.id,
                        subjectText,
                        reply,
                      )
                    }
                  />
                ) : (
                  <div className="conversation-message-body">
                    {bodyText.split("\n").map((line, lineIndex) => (
                      <p key={entry.id + "-l-" + lineIndex}>{line || " "}</p>
                    ))}
                  </div>
                )
              ) : state === "decrypting" ? (
                <div className="conversation-message-body">
                  <p className="item-sub">{bodyText}</p>
                </div>
              ) : (
                <MessageUnavailableCard
                  state={state}
                  messageId={entry.id}
                  recipientDid={entry.recipient_did}
                  encryptedContent={
                    (entry.id === rootMessageId
                      ? rootContent.data?.encrypted_content
                      : contents[entry.id]?.encrypted_content) ?? ""
                  }
                  encryptedKey={
                    (entry.id === rootMessageId
                      ? rootContent.data?.encrypted_key
                      : contents[entry.id]?.encrypted_key) ?? ""
                  }
                  subjectEncrypted={entry.subject_encrypted ?? ""}
                />
              )}
              {state === "readable" ? (
                <AttachmentList
                  messageId={entry.id}
                  recipientDid={entry.recipient_did}
                  encryptedKey={
                    entry.id === rootMessageId
                      ? rootContent.data?.encrypted_key ?? ""
                      : contents[entry.id]?.encrypted_key ?? ""
                  }
                />
              ) : null}
            </article>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MessageUnavailableCard: shown for `unavailable_on_this_device` and
// `decrypt_failed` states instead of an infinite "decrypting" line.
// docs/21 §3.2 — tell the user *why* the message can't be displayed
// here and point at the MCP runtime (Claude Desktop etc.) as the read
// path. The message_id and recipient DID are exposed with copy buttons
// so users can feed them into a runtime / bug report without fighting
// the browser's selection.
// ---------------------------------------------------------------------------

function MessageUnavailableCard({
  state,
  messageId,
  recipientDid,
  encryptedContent,
  encryptedKey,
  subjectEncrypted,
}: {
  state: MessageVisibilityState;
  messageId: string;
  recipientDid: string;
  /** Full ciphertext fields — needed only for the bridged-restore
   * path; ignored otherwise. */
  encryptedContent: string;
  encryptedKey: string;
  subjectEncrypted: string;
}) {
  const { t } = useTranslation();

  const isDaemon = state === "unavailable_on_this_device";
  const title = isDaemon
    ? t("inbox.unavailableOnThisDeviceCardTitle")
    : t("inbox.decryptFailedCardTitle");
  const body = isDaemon
    ? t("inbox.unavailableOnThisDeviceCardBody")
    : t("inbox.decryptFailedCardBody");

  return (
    <div
      className="message-unavailable-card"
      role="note"
      aria-live="polite"
      data-state={state}
    >
      <h4>
        {isDaemon ? (
          <span className="unavailable-badge">
            {t("inbox.unavailableOnThisDeviceBadge")}
          </span>
        ) : null}
        {title}
      </h4>
      <p className="item-sub" style={{ margin: "0 0 16px 0", fontSize: "0.9rem" }}>
        {body}
      </p>

      {isDaemon ? (
        <div className="action-row">
          <OpenInRuntimeButton
            messageId={messageId}
            recipientDid={recipientDid}
          />
          <BridgedRestoreButton
            recipientDid={recipientDid}
            encryptedContent={encryptedContent}
            encryptedKey={encryptedKey}
            subjectEncrypted={subjectEncrypted}
          />
        </div>
      ) : null}

      <div className="copy-group">
        <CopyValueButton
          value={messageId}
          label={t("inbox.copyMessageId")}
          copiedLabel={t("inbox.copied")}
        />
        {recipientDid ? (
          <CopyValueButton
            value={recipientDid}
            label={t("inbox.copyAgentDid")}
            copiedLabel={t("inbox.copied")}
          />
        ) : null}
        {isDaemon ? (
          <Link
            href="/help#help-modes"
            className="btn-premium outline"
            style={{ marginLeft: "auto", padding: "4px 10px", fontSize: "11px" }}
          >
            {t("inbox.seeModesHelp")}
          </Link>
        ) : null}
      </div>
    </div>
  );
}

/**
 * Primary CTA on the Daemon-isolated explanatory card. Instead of a
 * noisy modal, we build a ready-to-run runtime prompt (message_id +
 * agent DID injected) and copy it to the clipboard — the user pastes
 * it into Claude Desktop / any MCP runtime and gets the plaintext
 * without manually reconstructing a tool call. docs/21 §3.2 / §4.3.
 */
function OpenInRuntimeButton({
  messageId,
  recipientDid,
}: {
  messageId: string;
  recipientDid: string;
}) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn-premium primary"
      onClick={() => {
        const prompt = t("inbox.openInRuntimePromptTemplate", {
          messageId,
          recipientDid: recipientDid || "(unknown)",
        });
        if (typeof navigator !== "undefined" && navigator.clipboard) {
          void navigator.clipboard.writeText(prompt).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2500);
          });
        }
      }}
      aria-live="polite"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <rect x="9" y="9" width="13" height="13" rx="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      <span>
        {copied ? t("inbox.openInRuntimePromptCopied") : t("inbox.openInRuntimeAction")}
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// BridgedRestoreButton: optional daemon-backed decrypt for this one
// message. Off-by-default; only renders if the user has stored a
// bridge token for this recipient. Still gated by an explicit click
// (docs/22 §2 invariant: no silent / automatic decryption). Plaintext
// appears in a collapsible panel with a short TTL and auto-clears on
// route change / tab blur / timeout. See docs/22 §4.4 / §6.
// ---------------------------------------------------------------------------

/** How long the bridged plaintext stays rendered before we auto-clear
 * the state. docs/22 §2 invariant 4 — treat the result as ephemeral. */
const BRIDGED_PLAINTEXT_TTL_MS = 5 * 60 * 1000;

type BridgedPlaintext = {
  subject: string;
  body: string;
  expiresAt: number;
};

function BridgedRestoreButton({
  recipientDid,
  encryptedContent,
  encryptedKey,
  subjectEncrypted,
}: {
  recipientDid: string;
  encryptedContent: string;
  encryptedKey: string;
  subjectEncrypted: string;
}) {
  const { t } = useTranslation();

  // DID → aid resolution happens once: we key the bridge token by aid
  // so it survives DID rotation. React Query caches via the default
  // API client elsewhere, so the extra call is effectively free on
  // repeat renders inside the same session.
  const [aid, setAid] = useState<string | null>(null);
  const [tokenPresent, setTokenPresent] = useState<boolean | null>(null);
  const [plaintext, setPlaintext] = useState<BridgedPlaintext | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    if (!recipientDid) {
      setAid(null);
      setTokenPresent(false);
      return;
    }
    void defaultApiClient
      .resolveRecipient(recipientDid)
      .then(async (resolved) => {
        if (cancelled) return;
        setAid(resolved.aid);
        // loadBridgeToken is async now (3c.5 AES-GCM unwrap). Run
        // after the aid state set so the panel shows the aid even
        // while the bearer is still decrypting.
        const stored = await loadBridgeToken(resolved.aid);
        if (!cancelled) setTokenPresent(stored !== null);
      })
      .catch(() => {
        if (!cancelled) {
          setAid(null);
          setTokenPresent(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [recipientDid]);

  // Ephemeral-plaintext lifecycle — any of {TTL, route change, tab
  // blur} clears the state so the decrypted body doesn't linger in
  // React memory beyond the user's current attention.
  useEffect(() => {
    if (!plaintext) return;
    const msLeft = plaintext.expiresAt - Date.now();
    const timer = setTimeout(() => setPlaintext(null), Math.max(0, msLeft));
    const onVisibility = () => {
      if (document.visibilityState === "hidden") setPlaintext(null);
    };
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [plaintext]);

  if (!aid || tokenPresent !== true) {
    // Render nothing until we've confirmed a token exists. Keeps the
    // card quiet on the common path where the user hasn't opted into
    // bridged restore. The runtime CTA still stays visible.
    return null;
  }

  async function runRestore() {
    if (!aid) return;
    const stored = await loadBridgeToken(aid);
    if (!stored) {
      setError(t("inbox.bridgedRestoreNoToken"));
      return;
    }
    // Phase 3c.2 session nonce — lives in sessionStorage so a fresh
    // tab won't have it even though the token is in localStorage.
    // Surface "missing" here instead of the generic unauthorised
    // flow so the UI can tell the user to re-pair in this tab.
    const sessionNonce = loadBridgeSessionNonce(aid);
    const confirmMessage = t("inbox.bridgedRestoreConfirm");
    if (typeof window !== "undefined" && !window.confirm(confirmMessage)) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const client = new BridgeClient({
        baseUrl: stored.base_url,
        token: stored.token,
        sessionNonce,
      });
      const result = await client.unwrap(encryptedKey);
      if (result.kind !== "ok") {
        // The daemon returns 401 for both "missing/wrong token" and
        // "missing/wrong nonce"; if we had a token but no nonce the
        // UI can spare the user a confusing "token invalid" message
        // and tell them to re-pair this tab.
        if (result.kind === "unauthorized" && !sessionNonce) {
          setError(t("inbox.bridgedRestoreErrorSessionMissing"));
        } else {
          setError(mapBridgeError(result.kind, t));
        }
        return;
      }
      const bodyRes = await decryptEnvelopeTextWithContentKey(
        encryptedContent,
        result.content_key,
      );
      const subjectRes = subjectEncrypted
        ? await decryptEnvelopeTextWithContentKey(
            subjectEncrypted,
            result.content_key,
          )
        : { state: "readable" as const, text: "" };
      if (bodyRes.state !== "readable") {
        setError(t("inbox.bridgedRestoreDecryptFailed"));
        return;
      }
      setPlaintext({
        subject: subjectRes.state === "readable" ? subjectRes.text : "",
        body: bodyRes.text,
        expiresAt: Date.now() + BRIDGED_PLAINTEXT_TTL_MS,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10, width: "100%" }}>
      <div className="action-row">
        <button
          type="button"
          className="btn-premium secondary"
          onClick={() => void runRestore()}
          disabled={busy}
          style={{ cursor: busy ? "progress" : "pointer" }}
          aria-label={t("inbox.bridgedRestoreAction")}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          {busy
            ? t("inbox.bridgedRestoreBusy")
            : plaintext
              ? t("inbox.bridgedRestoreAgain")
              : t("inbox.bridgedRestoreAction")}
        </button>
        {plaintext ? (
          <button
            type="button"
            className="btn-premium outline"
            onClick={() => setPlaintext(null)}
          >
            {t("inbox.bridgedRestoreClear")}
          </button>
        ) : null}
      </div>
      {error ? (
        <p
          className="item-sub"
          role="alert"
          style={{ margin: 0, color: "#c5221f", fontSize: 12 }}
        >
          {error}
        </p>
      ) : null}
      {plaintext ? (
        <div
          data-testid="bridged-plaintext"
          style={{
            marginTop: 4,
            padding: "10px 12px",
            borderRadius: 8,
            border: "1px dashed rgba(66, 133, 244, 0.35)",
            background: "rgba(66, 133, 244, 0.04)",
            fontSize: 13,
          }}
        >
          {plaintext.subject ? (
            <p style={{ margin: "0 0 6px 0", fontWeight: 600 }}>
              {plaintext.subject}
            </p>
          ) : null}
          {plaintext.body.split("\n").map((line, i) => (
            <p key={"bl-" + i} style={{ margin: "2px 0" }}>
              {line || "\u00A0"}
            </p>
          ))}
          <p
            className="item-sub"
            style={{ margin: "8px 0 0 0", fontSize: 11, color: "#5f6368" }}
          >
            {t("inbox.bridgedRestoreTtlHint")}
          </p>
        </div>
      ) : null}
    </div>
  );
}

function mapBridgeError(
  kind:
    | "offline"
    | "unauthorized"
    | "forbidden_origin"
    | "bad_request"
    | "rate_limited"
    | "daemon_error",
  t: (key: string, vars?: Record<string, string | number>) => string,
): string {
  switch (kind) {
    case "offline":
      return t("inbox.bridgedRestoreErrorOffline");
    case "unauthorized":
      return t("inbox.bridgedRestoreErrorUnauthorized");
    case "forbidden_origin":
      return t("inbox.bridgedRestoreErrorForbiddenOrigin");
    case "bad_request":
      return t("inbox.bridgedRestoreErrorBadRequest");
    case "rate_limited":
      return t("inbox.bridgedRestoreErrorRateLimited");
    case "daemon_error":
    default:
      return t("inbox.bridgedRestoreErrorDaemon");
  }
}

function CopyValueButton({
  value,
  label,
  copiedLabel,
}: {
  value: string;
  label: string;
  copiedLabel: string;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn-premium secondary"
      onClick={() => {
        // Use the modern Clipboard API; fall back silently if the
        // browser blocks it (no-op is better than a popup in an
        // already-broken state).
        if (typeof navigator === "undefined" || !navigator.clipboard) return;
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1600);
        });
      }}
      style={{ padding: "4px 10px", fontSize: "11px" }}
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
      <span>
        {copied ? copiedLabel : label}
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// AttachmentList: per-message attachment chips.
//
// Decryption flow (matches docs/17 §11.2):
//   1. Fetch the attachment summary list.
//   2. For each row, decrypt `metadata_encrypted` using the same content key
//      path the body used (wrapped key → unwrap via recipient private key).
//   3. On click: request a short-lived presigned GET URL, fetch the
//      encrypted blob, decrypt locally, verify SHA-256, offer as download.
//
// The server never sees the filename, MIME, content key, or plaintext bytes.
// ---------------------------------------------------------------------------

type DecryptedAttachment = {
  attachment_id: string;
  ciphertext_size_bytes: number;
  metadata: AttachmentMetadataPlain | null;
  error?: string;
};

function AttachmentList({
  messageId,
  recipientDid,
  encryptedKey,
}: {
  messageId: string;
  recipientDid: string;
  encryptedKey: string;
}) {
  const { t } = useTranslation();
  const query = useMessageAttachmentsQuery(messageId);
  const [decrypted, setDecrypted] = useState<DecryptedAttachment[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [statusById, setStatusById] = useState<Record<string, string>>({});

  useEffect(() => {
    const rows = query.data?.attachments;
    if (!rows || rows.length === 0) {
      setDecrypted([]);
      return;
    }
    let cancelled = false;
    void (async () => {
      const result: DecryptedAttachment[] = [];
      for (const row of rows) {
        const text = await decryptEnvelopeText(
          row.metadata_encrypted,
          encryptedKey,
          recipientDid,
        );
        if (text === ENCRYPTED_PLACEHOLDER) {
          result.push({
            attachment_id: row.attachment_id,
            ciphertext_size_bytes: row.ciphertext_size_bytes,
            metadata: null,
            error: t("inbox.attachmentDecryptFailed"),
          });
          continue;
        }
        try {
          const parsed = JSON.parse(text) as AttachmentMetadataPlain;
          result.push({
            attachment_id: row.attachment_id,
            ciphertext_size_bytes: row.ciphertext_size_bytes,
            metadata: parsed,
          });
        } catch {
          result.push({
            attachment_id: row.attachment_id,
            ciphertext_size_bytes: row.ciphertext_size_bytes,
            metadata: null,
            error: t("inbox.attachmentDecryptFailed"),
          });
        }
      }
      if (!cancelled) setDecrypted(result);
    })();
    return () => {
      cancelled = true;
    };
  }, [query.data, encryptedKey, recipientDid, t]);

  const handleDownload = async (att: DecryptedAttachment) => {
    if (!att.metadata) return;
    setBusyId(att.attachment_id);
    setStatusById((prev) => ({
      ...prev,
      [att.attachment_id]: t("inbox.attachmentDownloading"),
    }));
    try {
      // Find the wrap that matches a DID we can unwrap (either recipient or
      // sender — whichever private key we have locally).
      let rawKeyStr: string | null = null;
      for (const entry of att.metadata.attachment_key_wraps) {
        const privateKey = await getRecipientPrivateKey(entry.recipient_did);
        if (!privateKey) continue;
        try {
          rawKeyStr = await unwrapContentKeyWithRecipientPrivateKey(
            entry.wrapped_key,
            privateKey,
          );
          break;
        } catch {
          continue;
        }
      }
      if (!rawKeyStr) {
        throw new Error("no-unwrappable-key");
      }
      const rawKey = decodeAttachmentKey(rawKeyStr);

      // Get a short-lived presigned GET URL and fetch the opaque ciphertext.
      const urlResp = await defaultApiClient.getAttachmentDownloadUrl(
        messageId,
        att.attachment_id,
      );
      const blobResp = await fetch(urlResp.download_url);
      if (!blobResp.ok) throw new Error("download-failed");
      const ciphertext = await blobResp.arrayBuffer();

      // Decrypt locally and verify integrity.
      const plaintext = await decryptAttachment(
        ciphertext,
        rawKey,
        att.metadata.cipher_nonce,
      );
      const digest = await sha256OfBytes(plaintext);
      if (digest !== att.metadata.sha256_plaintext) {
        throw new Error("integrity-failed");
      }

      // Trigger a download.
      const blob = new Blob([plaintext], { type: att.metadata.mime });
      const href = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = href;
      a.download = att.metadata.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(href);

      setStatusById((prev) => {
        const next = { ...prev };
        delete next[att.attachment_id];
        return next;
      });
    } catch (err) {
      const msg =
        err instanceof Error && err.message === "integrity-failed"
          ? t("inbox.attachmentIntegrityFailed")
          : t("inbox.attachmentDecryptFailed");
      setStatusById((prev) => ({ ...prev, [att.attachment_id]: msg }));
    } finally {
      setBusyId(null);
    }
  };

  if (!query.data || decrypted.length === 0) return null;

  return (
    <div className="attachment-list">
      {decrypted.map((att) => {
        const status = statusById[att.attachment_id];
        if (!att.metadata) {
          return (
            <div key={att.attachment_id} className="attachment-chip error">
              {att.error ?? t("inbox.attachmentDecryptFailed")}
            </div>
          );
        }
        return (
          <button
            key={att.attachment_id}
            type="button"
            className="attachment-chip"
            onClick={() => handleDownload(att)}
            disabled={busyId === att.attachment_id}
            title={att.metadata.filename}
          >
            <span className="attachment-chip-icon" aria-hidden>
              📎
            </span>
            <span className="attachment-chip-name">
              {att.metadata.filename}
            </span>
            <span className="attachment-chip-size">
              {formatBytes(att.metadata.plaintext_size_bytes)}
            </span>
            {status ? (
              <span className="attachment-chip-status">{status}</span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
