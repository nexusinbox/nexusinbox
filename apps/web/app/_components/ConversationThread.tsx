"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
// Use the browser-safe subpath export — the main `@nexusinbox/core`
// entry pulls in node:crypto / node:net via the Node API client, which
// webpack can't bundle for the Next.js browser build.
import { type MessageVisibilityState } from "@nexusinbox/core/visibility";
import type { A2ARespondPayload } from "../../lib/protocol/a2aReply";
import {
  useBlockFromMessageMutation,
  useMessageAttachmentsQuery,
} from "../../lib/api/hooks";
import { ApiError, defaultApiClient } from "../../lib/api/client";
import type { BlockLevel } from "../../lib/api/types";
import { decryptEnvelopeText, ENCRYPTED_PLACEHOLDER } from "../../lib/crypto/envelope";
import { unwrapContentKeyWithRecipientPrivateKey } from "../../lib/crypto/keywrap";
import { getRecipientPrivateKey } from "../../lib/crypto/recipient-keyring";
import {
  decryptAttachment,
  decodeAttachmentKey,
  readCiphertextWithLimit,
  sha256OfBytes,
} from "../../lib/crypto/attachment";
import { useTranslation } from "../../lib/i18n";
import type { AttachmentMetadataPlain } from "../../lib/api/types";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

export function summariseReply(
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

export type BlockStatus = { kind: "success" | "error"; text: string };

// ---------------------------------------------------------------------------
// BlockSenderPanel: pick a block level for the sender of one received
// message. The server resolves the target from the message, so nobody types
// an id. The mutation hook invalidates `/blocks` on success so
// /settings/blocks reflects the new row immediately.
// ---------------------------------------------------------------------------

export function BlockSenderPanel({
  messageId,
  onClose,
  onResult,
}: {
  messageId: string;
  onClose: () => void;
  onResult: (status: BlockStatus) => void;
}) {
  const { t } = useTranslation();
  const blockMutation = useBlockFromMessageMutation();

  async function confirmAndBlock(level: BlockLevel) {
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
      onResult({ kind: "success", text: t(successKey) });
      onClose();
    } catch (err) {
      // 422 is the documented "sender not registered" case — only
      // possible at L2/L3, and means the sender has no row in our
      // users table so world_id_hash can't be resolved. Surface the
      // L1-fallback hint directly instead of a generic error.
      if (err instanceof ApiError && err.status === 422) {
        onResult({ kind: "error", text: t("inbox.blockFailSenderNotRegistered") });
      } else {
        onResult({ kind: "error", text: t("inbox.blockFailGeneric") });
      }
    }
  }

  return (
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
          onClick={() => void confirmAndBlock(lvl)}
          disabled={blockMutation.isPending}
          style={{
            flexDirection: "column",
            alignItems: "flex-start",
            gap: 2,
            padding: "10px 12px",
            textAlign: "left",
            borderColor: "rgba(220, 38, 38, 0.2)",
            color: "var(--danger)",
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
          onClick={onClose}
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

export function MessageUnavailableCard({
  state,
  messageId,
  recipientDid,
}: {
  state: MessageVisibilityState;
  messageId: string;
  recipientDid: string;
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

export function AttachmentList({
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
      // Never read more than the size the server verified at upload time.
      const ciphertext = await readCiphertextWithLimit(blobResp, att.ciphertext_size_bytes);

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
