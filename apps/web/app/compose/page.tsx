"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ChangeEvent, FormEvent, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "../_components/AppShell";
import { RefreshIconButton } from "../_components/RefreshIconButton";
import {
  useAgentsQuery,
  useContactsQuery,
  useMessageContentQuery,
  useSendMessageMutation,
} from "../../lib/api/hooks";
import {
  decryptEnvelopeText,
  encryptEnvelopeText,
  generateContentKey,
  ENCRYPTED_PLACEHOLDER,
} from "../../lib/crypto/envelope";
import { isValidEd25519PublicKeyB64Url, signEnvelopePayload } from "../../lib/crypto/signature";
import { isValidX25519PublicKeyB64Url, wrapContentKeyForRecipient } from "../../lib/crypto/keywrap";
import {
  encryptAttachment,
  generateAttachmentKey,
  encodeAttachmentKey,
  sha256OfBytes,
} from "../../lib/crypto/attachment";
import { getSigningPrivateKey, hasSigningPrivateKeyMaterial } from "../../lib/crypto/signing-keyring";
import { defaultApiClient } from "../../lib/api/client";
import type {
  AttachmentMetadataPlain,
  OutboundAttachmentRef,
  RecipientResolutionResponse,
} from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";
import { getLLMKey } from "../../lib/llm/llmAuth";
import {
  AnthropicDraftError,
  generateReplyDraft,
  type DraftTone,
} from "../../lib/llm/anthropicDraft";
import { parseA2APayload, type A2AProtocolBlock } from "@nexusinbox/core/a2a";

// Per-file cap (5 MiB) matches the server-side
// ATTACHMENT_MAX_CIPHERTEXT_BYTES. Cumulative cap per message (25 MiB)
// matches server-side ATTACHMENT_MAX_CUMULATIVE_BYTES.
const MAX_ATTACHMENT_PER_FILE_BYTES = 5 * 1024 * 1024;
const MAX_ATTACHMENT_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_ATTACHMENT_COUNT = 5;

type AttachmentStatus = "ready" | "uploading" | "uploaded" | "failed";

type AttachmentDraft = {
  id: string;
  /** Raw bytes of the plaintext file. Held in memory until submit. */
  bytes: ArrayBuffer;
  name: string;
  size: number;
  mime: string;
  status: AttachmentStatus;
  /** Server-issued attachment_id once the intent has been created. */
  remoteId?: string;
};

type StatusKind = "info" | "error" | "success";
type StatusState = { kind: StatusKind; message: string } | null;

function formatBytes(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function isAidIdentifier(value: string): boolean {
  return value.startsWith("aid:ai:");
}

async function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (!(result instanceof ArrayBuffer)) {
        reject(new Error("unexpected reader result"));
        return;
      }
      resolve(result);
    };
    reader.onerror = () => reject(reader.error ?? new Error("file read failed"));
    reader.readAsArrayBuffer(file);
  });
}

export default function ComposePage() {
  return (
    <Suspense fallback={null}>
      <ComposePageInner />
    </Suspense>
  );
}

function ComposePageInner() {
  const { t } = useTranslation();
  const router = useRouter();
  const searchParams = useSearchParams();
  const replyToId = searchParams?.get("reply") ?? null;
  const forwardFromId = searchParams?.get("forward") ?? null;
  const aiDraft = searchParams?.get("ai") === "1";
  const composeMode: "new" | "reply" | "forward" = replyToId
    ? "reply"
    : forwardFromId
      ? "forward"
      : "new";

  const agentsQuery = useAgentsQuery();
  const contactsQuery = useContactsQuery();
  const sendMessage = useSendMessageMutation();
  // When replying, pull the original message content so we can prefill
  // the reply's recipient (original sender) and subject (with "Re: ").
  // Forwards intentionally start with an empty recipient — the user
  // picks a new destination.
  const originalMessageQuery = useMessageContentQuery(
    composeMode === "reply" ? replyToId : null,
  );

  const apiAgents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const contacts = useMemo(
    () => contactsQuery.data?.contacts ?? [],
    [contactsQuery.data],
  );
  // Build the recipient picker options: every known agent + every
  // contact whose DID is not already covered by an agent entry, so
  // the user can pick from either list without duplicates.
  const recipientOptions = useMemo(() => {
    const seen = new Set<string>();
    const options: Array<{ did: string; label: string }> = [];
    for (const agent of apiAgents) {
      if (seen.has(agent.did)) continue;
      seen.add(agent.did);
      options.push({ did: agent.did, label: agent.label });
    }
    for (const contact of contacts) {
      if (seen.has(contact.did)) continue;
      seen.add(contact.did);
      const label = contact.agent_label
        ? `${contact.person_name}(${contact.agent_label})`
        : contact.person_name;
      options.push({ did: contact.did, label });
    }
    return options;
  }, [apiAgents, contacts]);

  const [senderDid, setSenderDid] = useState<string>("");
  const [recipientDid, setRecipientDid] = useState<string>("");
  // Compose-time hint: auto-resolve the recipient on valid
  // aid / did:key inputs and surface the aggregate key_holder the API
  // returns (docs/21 §4.4). `null` means "no resolved recipient yet"
  // — the UI shows no hint in that case, so typing a half-formed
  // address doesn't flash warnings.
  const [recipientMode, setRecipientMode] = useState<
    "web_keystore" | "signer_daemon" | "unknown" | null
  >(null);
  // For replies we fill in "Re: <original subject>" asynchronously
  // once the original message is fetched and its subject decrypted.
  // Forwards still get the plain "Fwd: " seed.
  const [subject, setSubject] = useState<string>(() => {
    if (composeMode === "forward") return "Fwd: ";
    return "";
  });
  const [replyPrefillApplied, setReplyPrefillApplied] = useState<boolean>(false);
  const [body, setBody] = useState<string>(() => "");
  // Phase 4.5 (docs/25f) — AI draft state. `idle` means nothing
  // happened, `no_key` means we wanted to draft but the user hasn't
  // configured the API key, `done` means the body was prefilled.
  const [aiDraftStatus, setAiDraftStatus] = useState<
    "idle" | "no_key" | "generating" | "done" | "error"
  >("idle");
  const [aiDraftError, setAiDraftError] = useState<string | null>(null);
  const [bodyEdited, setBodyEdited] = useState<boolean>(false);
  const [aiDraftAttempted, setAiDraftAttempted] = useState<boolean>(false);
  // Phase 4.6 — currently-applied tone, used both for the toolbar
  // highlight and the next regenerate call. "default" means no
  // explicit tone hint (system prompt unchanged from 4.5).
  const [aiDraftTone, setAiDraftTone] = useState<DraftTone | "default">(
    "default",
  );
  const [attachments, setAttachments] = useState<AttachmentDraft[]>([]);
  const [status, setStatus] = useState<StatusState>(null);
  const [hasSenderPrivateKey, setHasSenderPrivateKey] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Prefill reply recipient + subject from the original message.
  // Runs once per reply target so user edits aren't clobbered.
  useEffect(() => {
    if (composeMode !== "reply") return;
    if (replyPrefillApplied) return;
    const data = originalMessageQuery.data;
    if (!data) return;

    let cancelled = false;
    void (async () => {
      const originalSender = data.sender_did ?? "";
      const originalRecipient = data.recipient_did;
      if (originalSender) {
        setRecipientDid((current) => (current ? current : originalSender));
      }

      if (data.subject_encrypted) {
        const decrypted = await decryptEnvelopeText(
          data.subject_encrypted,
          data.encrypted_key,
          originalRecipient,
        );
        if (cancelled) return;
        // Fallback to "Re: " if decryption failed (e.g. missing key).
        const base =
          decrypted && decrypted !== ENCRYPTED_PLACEHOLDER
            ? decrypted
            : "";
        const prefix = base.startsWith("Re:") ? "" : "Re: ";
        setSubject((current) => (current ? current : prefix + base));
      } else {
        setSubject((current) => (current ? current : "Re: "));
      }

      setReplyPrefillApplied(true);
    })();

    return () => {
      cancelled = true;
    };
  }, [composeMode, originalMessageQuery.data, replyPrefillApplied]);

  // Phase 4.5 + 4.6 (docs/25f) — generate or regenerate the AI
  // draft. Called once on initial navigation (effect below) and
  // again from the toolbar buttons. Caller is responsible for
  // gating regeneration on bodyEdited via a confirm dialog.
  const runDraftGeneration = useCallback(
    async (tone: DraftTone | "default") => {
      if (composeMode !== "reply") return;
      const data = originalMessageQuery.data;
      if (!data) return;

      const llmKey = await getLLMKey();
      if (!llmKey) {
        setAiDraftStatus("no_key");
        return;
      }

      setAiDraftStatus("generating");
      setAiDraftError(null);

      const plaintext = await decryptEnvelopeText(
        data.encrypted_content,
        data.encrypted_key,
        data.recipient_did,
      );
      const isReadable =
        plaintext && plaintext !== ENCRYPTED_PLACEHOLDER ? plaintext : "";
      let subjectText: string | undefined;
      if (data.subject_encrypted) {
        const decryptedSubject = await decryptEnvelopeText(
          data.subject_encrypted,
          data.encrypted_key,
          data.recipient_did,
        );
        if (decryptedSubject && decryptedSubject !== ENCRYPTED_PLACEHOLDER) {
          subjectText = decryptedSubject;
        }
      }

      let protocolBlock: A2AProtocolBlock | null = null;
      let bodyForPrompt = isReadable;
      const parsed = parseA2APayload(isReadable, data.content_type ?? null);
      if (parsed.protocol) {
        protocolBlock = parsed.protocol;
        bodyForPrompt = parsed.body;
      }

      try {
        const draft = await generateReplyDraft({
          incomingBody: bodyForPrompt,
          incomingSubject: subjectText,
          protocolBlock,
          apiKey: llmKey.api_key,
          model: llmKey.model,
          tone: tone === "default" ? undefined : tone,
        });
        setBody(draft);
        // Regeneration replaces whatever was in the textarea, so
        // bodyEdited resets — the next regenerate doesn't need a
        // confirm until the user starts editing again.
        setBodyEdited(false);
        setAiDraftTone(tone);
        setAiDraftStatus("done");
      } catch (e) {
        const code = e instanceof AnthropicDraftError ? e.code : "api_error";
        setAiDraftStatus("error");
        setAiDraftError(code);
      }
    },
    [composeMode, originalMessageQuery.data],
  );

  // Phase 4.5 — first-render trigger. Runs at most once per page
  // load; subsequent edits / tone changes go through the toolbar.
  useEffect(() => {
    if (!aiDraft || composeMode !== "reply") return;
    if (aiDraftAttempted) return;
    if (bodyEdited) return;
    if (!originalMessageQuery.data) return;
    setAiDraftAttempted(true);
    void runDraftGeneration("default");
  }, [
    aiDraft,
    composeMode,
    originalMessageQuery.data,
    aiDraftAttempted,
    bodyEdited,
    runDraftGeneration,
  ]);

  // Default to the first available sender when the agent list arrives.
  useEffect(() => {
    if (apiAgents.length === 0) {
      setSenderDid("");
      return;
    }
    setSenderDid((current) => {
      if (current && apiAgents.some((agent) => agent.did === current)) return current;
      return apiAgents[0].did;
    });
  }, [apiAgents]);

  useEffect(() => {
    let cancelled = false;
    if (!senderDid) {
      setHasSenderPrivateKey(false);
      return;
    }
    void hasSigningPrivateKeyMaterial(senderDid).then((result) => {
      if (!cancelled) {
        setHasSenderPrivateKey(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [senderDid]);

  // Debounced recipient lookup — feeds the compose-time Mode hint
  // (docs/21 §4.4). Only fires for inputs that plausibly look like
  // an `aid:ai:` or `did:key:` address so we don't spam the API
  // while the user is mid-type.
  useEffect(() => {
    const input = recipientDid.trim();
    if (!input || (!isAidIdentifier(input) && !input.startsWith("did:key:"))) {
      setRecipientMode(null);
      return;
    }
    let cancelled = false;
    const handle = setTimeout(() => {
      void defaultApiClient
        .resolveRecipient(input)
        .then((resolved) => {
          if (cancelled) return;
          setRecipientMode(resolved.key_holder ?? "unknown");
        })
        .catch(() => {
          // 404 / malformed input — clear the hint rather than
          // surfacing an error; the submit path has its own
          // validation. Unknown recipients shouldn't flash a warning.
          if (!cancelled) setRecipientMode(null);
        });
    }, 350);
    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [recipientDid]);

  const selectedSender = useMemo(
    () => apiAgents.find((agent) => agent.did === senderDid),
    [apiAgents, senderDid],
  );
  const selectedRecipient = useMemo(
    () => apiAgents.find((agent) => agent.did === recipientDid),
    [apiAgents, recipientDid],
  );

  const attachmentsTotalSize = useMemo(
    () => attachments.reduce((sum, attachment) => sum + attachment.size, 0),
    [attachments],
  );

  // Derive a single validation message so we can both enable the
  // submit button and surface the reason when disabled.
  const readinessMessage = useMemo(() => {
    if (apiAgents.length === 0) {
      return t("compose.validationNoAgent");
    }
    if (!senderDid) {
      return t("compose.validationSelectFrom");
    }
    if (!selectedSender?.public_key) {
      return t("compose.validationNoSigningKey");
    }
    if (!isValidEd25519PublicKeyB64Url(selectedSender.public_key)) {
      return t("compose.validationBrokenKey");
    }
    if (!hasSenderPrivateKey) {
      return t("compose.validationNoPrivateKey");
    }
    if (!recipientDid.trim()) {
      return t("compose.validationEnterTo");
    }
    if (!isAidIdentifier(recipientDid) && !selectedRecipient) {
      return t("compose.validationToNotFound");
    }
    if (!isAidIdentifier(recipientDid) && !selectedRecipient?.encryption_key) {
      return t("compose.validationNoEncKey");
    }
    if (
      !isAidIdentifier(recipientDid) &&
      selectedRecipient?.encryption_key &&
      !isValidX25519PublicKeyB64Url(selectedRecipient.encryption_key)
    ) {
      return t("compose.validationBadEncKey");
    }
    if (!subject.trim()) {
      return t("compose.validationSubject");
    }
    if (!body.trim()) {
      return t("compose.validationBody");
    }
    if (attachmentsTotalSize > MAX_ATTACHMENT_TOTAL_BYTES) {
      return t("compose.validationAttachSize", { max: formatBytes(MAX_ATTACHMENT_TOTAL_BYTES) });
    }
    if (attachments.some((a) => a.status === "uploading")) {
      return t("compose.statusUploadingAttachments");
    }
    return "";
  }, [
    apiAgents.length,
    senderDid,
    selectedSender,
    recipientDid,
    selectedRecipient,
    subject,
    body,
    attachmentsTotalSize,
    hasSenderPrivateKey,
    t,
  ]);

  const canSubmit = readinessMessage === "" && !sendMessage.isPending;

  const handleFilesChosen = async (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files ?? []);
    event.target.value = ""; // allow re-picking the same file
    if (files.length === 0) return;

    if (attachments.length + files.length > MAX_ATTACHMENT_COUNT) {
      setStatus({
        kind: "error",
        message: t("compose.validationAttachCount", { max: MAX_ATTACHMENT_COUNT }),
      });
      return;
    }

    const addedAttachments: AttachmentDraft[] = [];
    let runningTotal = attachmentsTotalSize;
    for (const file of files) {
      if (file.size > MAX_ATTACHMENT_PER_FILE_BYTES) {
        setStatus({
          kind: "error",
          message: t("compose.validationAttachPerFile", {
            filename: file.name,
            max: formatBytes(MAX_ATTACHMENT_PER_FILE_BYTES),
          }),
        });
        continue;
      }
      if (runningTotal + file.size > MAX_ATTACHMENT_TOTAL_BYTES) {
        setStatus({
          kind: "error",
          message: t("compose.validationAttachMax", { max: formatBytes(MAX_ATTACHMENT_TOTAL_BYTES) }),
        });
        break;
      }
      runningTotal += file.size;
      try {
        const bytes = await readFileAsArrayBuffer(file);
        addedAttachments.push({
          id: crypto.randomUUID(),
          bytes,
          name: file.name,
          size: file.size,
          mime: file.type || "application/octet-stream",
          status: "ready",
        });
      } catch {
        setStatus({
          kind: "error",
          message: t("compose.validationAttachRead", { filename: file.name }),
        });
      }
    }
    if (addedAttachments.length > 0) {
      setAttachments((prev) => prev.concat(addedAttachments));
    }
  };

  const removeAttachment = (id: string) => {
    setAttachments((prev) => prev.filter((attachment) => attachment.id !== id));
  };

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (readinessMessage) {
      setStatus({ kind: "error", message: readinessMessage });
      return;
    }

    const senderEncryptionKey = selectedSender?.encryption_key;
    if (!senderEncryptionKey) {
      setStatus({ kind: "error", message: t("compose.validationNoEncKey") });
      return;
    }

    setStatus({ kind: "info", message: t("compose.statusEncrypting") });

    // Keep track of intents we create so we can best-effort cleanup on failure.
    const createdIntentIds: string[] = [];

    try {
      let resolvedRecipient: RecipientResolutionResponse | null = null;
      const recipientInput = recipientDid.trim();
      if (isAidIdentifier(recipientInput)) {
        setStatus({ kind: "info", message: t("compose.statusResolvingRecipient") });
        resolvedRecipient = await defaultApiClient.resolveRecipient(recipientInput);
      }
      const recipientAddress = resolvedRecipient?.did ?? recipientInput;
      const recipientEncryptionKey =
        resolvedRecipient?.encryption_public_key ?? selectedRecipient?.encryption_key;
      if (!recipientEncryptionKey) {
        setStatus({ kind: "error", message: t("compose.validationNoEncKey") });
        return;
      }
      if (!isValidX25519PublicKeyB64Url(recipientEncryptionKey)) {
        setStatus({ kind: "error", message: t("compose.validationBadEncKey") });
        return;
      }

      setStatus({ kind: "info", message: t("compose.statusEncrypting") });

      const contentKey = generateContentKey();
      const encryptedSubject = await encryptEnvelopeText(subject, { contentKey });
      const encryptedBody = await encryptEnvelopeText(body, { contentKey });
      const wrapped = await wrapContentKeyForRecipient(contentKey, recipientEncryptionKey);
      const encryptedKey = wrapped.wrappedKey;

      // Attachment upload pipeline (E2E per docs/17):
      //   encrypt locally → presigned PUT to R2 → complete → build encrypted
      //   metadata using the message content key.
      const outboundAttachments: OutboundAttachmentRef[] = [];
      if (attachments.length > 0) {
        setStatus({ kind: "info", message: t("compose.statusUploadingAttachments") });

        for (const att of attachments) {
          setAttachments((prev) =>
            prev.map((a) => (a.id === att.id ? { ...a, status: "uploading" } : a)),
          );

          // 1. Generate per-attachment AES-GCM key and encrypt bytes.
          const rawAttachmentKey = generateAttachmentKey();
          const { ciphertext, nonceB64Url } = await encryptAttachment(
            att.bytes,
            rawAttachmentKey,
          );
          const sha256Plain = await sha256OfBytes(att.bytes);

          // 2. Request a presigned PUT URL from the API.
          const intent = await defaultApiClient.createAttachmentIntent({
            sender_did: senderDid,
            ciphertext_size_bytes: ciphertext.byteLength,
          });
          createdIntentIds.push(intent.attachment_id);

          // 3. Direct PUT to R2 with the exact required headers.
          const putResp = await fetch(intent.upload_url, {
            method: "PUT",
            headers: intent.required_headers,
            body: new Blob([ciphertext.buffer as ArrayBuffer]),
          });
          if (!putResp.ok) {
            throw new Error(`R2 upload failed: ${putResp.status}`);
          }

          // 4. Tell the API to verify the object and mark it uploaded.
          await defaultApiClient.completeAttachment(
            intent.attachment_id,
            ciphertext.byteLength,
          );

          // 5. Wrap the attachment content key for BOTH recipient and sender
          //    so the sender can re-read their own sent file.
          const attachmentKeyStr = encodeAttachmentKey(rawAttachmentKey);
          const recipientWrap = await wrapContentKeyForRecipient(
            attachmentKeyStr,
            recipientEncryptionKey,
          );
          const senderWrap = await wrapContentKeyForRecipient(
            attachmentKeyStr,
            senderEncryptionKey,
          );

          const metadataPlain: AttachmentMetadataPlain = {
            filename: att.name,
            mime: att.mime,
            plaintext_size_bytes: att.size,
            cipher_algorithm: "aes-gcm-256",
            cipher_nonce: nonceB64Url,
            attachment_key_wraps: [
              { recipient_did: recipientAddress, wrapped_key: recipientWrap.wrappedKey },
              { recipient_did: senderDid, wrapped_key: senderWrap.wrappedKey },
            ],
            sha256_plaintext: sha256Plain,
          };

          const encryptedMeta = await encryptEnvelopeText(
            JSON.stringify(metadataPlain),
            { contentKey },
          );

          outboundAttachments.push({
            attachment_id: intent.attachment_id,
            metadata_encrypted: encryptedMeta.serialized,
            metadata_nonce: encryptedMeta.nonce,
          });

          setAttachments((prev) =>
            prev.map((a) =>
              a.id === att.id
                ? { ...a, status: "uploaded", remoteId: intent.attachment_id }
                : a,
            ),
          );
        }
      }

      const signingPrivateKey = await getSigningPrivateKey(senderDid);
      if (!signingPrivateKey) {
        setStatus({
          kind: "error",
          message: t("compose.statusKeyLoadFailed"),
        });
        return;
      }
      const signature = await signEnvelopePayload({
        signingPrivateKey,
        senderDid,
        recipientDid: recipientAddress,
        subjectEncrypted: encryptedSubject.serialized,
        encryptedContent: encryptedBody.serialized,
        encryptedKey,
        nonce: encryptedBody.nonce,
      });
      setStatus({ kind: "info", message: t("compose.statusSending") });

      // Propagate the original thread so back-and-forth replies
      // group together in the conversation view. If the original
      // already belongs to a thread, inherit it; otherwise adopt
      // the original message id as the thread root. The original
      // message itself stays unchanged but any follow-up replies
      // all share this id.
      const threadId =
        composeMode === "reply" && replyToId
          ? originalMessageQuery.data?.thread_id || replyToId
          : undefined;

      await sendMessage.mutateAsync({
        senderDid,
        recipientDid: recipientInput,
        subjectEncrypted: encryptedSubject.serialized,
        encryptedContent: encryptedBody.serialized,
        encryptedKey,
        nonce: encryptedBody.nonce,
        signature,
        threadId,
        attachments: outboundAttachments,
      });
      setStatus({ kind: "success", message: t("compose.statusSent") });
      // Only wipe the body/attachments so the user can tweak &
      // resend, or start a fresh message.
      setBody("");
      setAttachments([]);
    } catch (err) {
      // Mark any in-flight attachment as failed for UI feedback.
      setAttachments((prev) =>
        prev.map((a) =>
          a.status === "uploading" ? { ...a, status: "failed" } : a,
        ),
      );
      // Best-effort cleanup of dangling intents so R2 doesn't fill with orphans.
      for (const id of createdIntentIds) {
        void defaultApiClient.deleteAttachment(id).catch(() => {});
      }
      setStatus({
        kind: "error",
        message:
          err instanceof Error && err.message.includes("R2")
            ? t("compose.statusAttachmentUploadFailed")
            : t("compose.statusSendFailed"),
      });
    }
  };

  const headerLabel =
    composeMode === "reply"
      ? aiDraft
        ? t("compose.aiDraftEdit")
        : t("compose.replyMessage")
      : composeMode === "forward"
        ? t("compose.forwardMessage")
        : t("compose.newMessage");

  const pageStatus: StatusState =
    status ??
    (readinessMessage
      ? { kind: "info", message: readinessMessage }
      : {
          kind: "info",
          message: t("compose.infoE2E"),
        });

  return (
    <AppShell
      title={t("compose.title")}
      activePath="/compose"
      rightAction={
        <RefreshIconButton
          onClick={() => agentsQuery.refetch()}
          label={t("compose.refreshAgents")}
        />
      }
    >
      <div className="compose-scroll">
      <section className="compose-frame">
        <header className="compose-head">
          <span>{headerLabel}</span>
          <span className="badge ok">{t("compose.e2eBadge")}</span>
          <Link
            href="/compose/propose"
            className="compose-head-link"
            data-testid="compose-propose-link"
          >
            {t("a2a.proposeComposeLink")} →
          </Link>
        </header>

        {(replyToId || forwardFromId) && (
          <div className="compose-context" data-testid="compose-context-banner">
            {t("compose.originalId")}<code>{replyToId ?? forwardFromId}</code>
          </div>
        )}

        <div className="compose-body">
          <form className="form-grid" onSubmit={handleSubmit}>
            <div className="field">
              <label className="field-label" htmlFor="compose-sender">
                {t("compose.fromLabel")}
              </label>
              <select
                id="compose-sender"
                className="select"
                value={senderDid}
                onChange={(event) => setSenderDid(event.target.value)}
                disabled={apiAgents.length === 0}
              >
                {apiAgents.length === 0 ? (
                  <option value="">{t("compose.fromEmpty")}</option>
                ) : null}
                {apiAgents.map((agent) => (
                  <option value={agent.did} key={agent.did}>
                    {agent.label} — {agent.did}
                  </option>
                ))}
              </select>
              {selectedSender ? (
                <p className="field-help">
                  {t("compose.fromHelp")}
                </p>
              ) : null}
            </div>

            <div className="field">
              <label className="field-label" htmlFor="compose-recipient">
                {t("compose.toLabel")}
              </label>
              <input
                id="compose-recipient"
                className="input"
                value={recipientDid}
                onChange={(event) => setRecipientDid(event.target.value)}
                placeholder={t("compose.toPlaceholder")}
                list="compose-recipient-options"
                autoComplete="off"
              />
              <datalist id="compose-recipient-options">
                {recipientOptions.map((option) => (
                  <option value={option.did} key={"rcpt-" + option.did}>
                    {option.label}
                  </option>
                ))}
              </datalist>
              <p className="field-help">
                {t("compose.toHelp")}
              </p>
              {recipientMode === "signer_daemon" ? (
                <p
                  className="field-help"
                  role="note"
                  data-state="recipient-daemon-isolated"
                  style={{
                    marginTop: 6,
                    padding: "8px 10px",
                    borderRadius: 6,
                    fontSize: 12,
                    lineHeight: 1.45,
                    background: "rgba(66, 133, 244, 0.08)",
                    border: "1px solid rgba(66, 133, 244, 0.28)",
                    color: "#1a73e8",
                  }}
                >
                  {t("compose.recipientModeDaemonIsolatedHint")}
                </p>
              ) : recipientMode === "web_keystore" ? (
                <p
                  className="field-help"
                  data-state="recipient-standard"
                  style={{
                    marginTop: 6,
                    fontSize: 12,
                    color: "#188038",
                  }}
                >
                  {t("compose.recipientModeStandardHint")}
                </p>
              ) : null}
            </div>

            <div className="field">
              <label className="field-label" htmlFor="compose-subject">
                {t("compose.subjectLabel")}
              </label>
              <input
                id="compose-subject"
                className="input"
                value={subject}
                onChange={(event) => setSubject(event.target.value)}
                placeholder={t("compose.subjectPlaceholder")}
              />
            </div>

            <div className="field">
              <label className="field-label" htmlFor="compose-body">
                {t("compose.bodyLabel")}
              </label>
              {aiDraft && composeMode === "reply" ? (
                <>
                  <AIDraftBanner
                    status={aiDraftStatus}
                    error={aiDraftError}
                    onOpenSettings={() => router.push("/integrations")}
                    currentTone={aiDraftTone}
                  />
                  {aiDraftStatus === "done" || aiDraftStatus === "generating" || aiDraftStatus === "error" ? (
                    <AIDraftToolbar
                      currentTone={aiDraftTone}
                      busy={aiDraftStatus === "generating"}
                      bodyEdited={bodyEdited}
                      onPick={(tone) => {
                        if (
                          bodyEdited &&
                          !window.confirm(t("compose.aiDraftRegenerateConfirm"))
                        ) {
                          return;
                        }
                        void runDraftGeneration(tone);
                      }}
                      onRegenerate={() => {
                        if (
                          bodyEdited &&
                          !window.confirm(t("compose.aiDraftRegenerateConfirm"))
                        ) {
                          return;
                        }
                        void runDraftGeneration(aiDraftTone);
                      }}
                    />
                  ) : null}
                </>
              ) : null}
              <textarea
                id="compose-body"
                className="textarea"
                value={body}
                onChange={(event) => {
                  setBody(event.target.value);
                  setBodyEdited(true);
                }}
                placeholder={t("compose.bodyPlaceholder")}
              />
            </div>

            <div className="field">
              <span className="field-label">{t("compose.attachLabel")}</span>
              <div className="field-row">
                <button
                  type="button"
                  className="file-picker-btn"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
                  </svg>
                  {t("compose.attachSelect")}
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden-file-input"
                  multiple
                  onChange={handleFilesChosen}
                />
                <span className="field-help">
                  {t("compose.attachSize", { size: formatBytes(attachmentsTotalSize), max: formatBytes(MAX_ATTACHMENT_TOTAL_BYTES) })}
                </span>
              </div>
              {attachments.length > 0 ? (
                <ul className="attachment-list">
                  {attachments.map((attachment) => (
                    <li className="attachment-item" key={attachment.id}>
                      <span className="attachment-name">{attachment.name}</span>
                      <span className="attachment-size">
                        {formatBytes(attachment.size)}
                      </span>
                      <button
                        type="button"
                        className="attachment-remove"
                        onClick={() => removeAttachment(attachment.id)}
                        aria-label={t("compose.attachRemoveLabel", { name: attachment.name })}
                      >
                        {t("compose.attachRemove")}
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>

            {pageStatus ? (
              <div className={`form-status ${pageStatus.kind}`} role="status">
                {pageStatus.message}
              </div>
            ) : null}

            <div className="form-actions">
              <button
                className="btn"
                type="button"
                onClick={() => {
                  setBody("");
                  setAttachments([]);
                  setStatus(null);
                }}
                disabled={sendMessage.isPending}
              >
                {t("compose.clearBody")}
              </button>
              <button className="btn primary" type="submit" disabled={!canSubmit}>
                {sendMessage.isPending ? t("compose.sending") : t("compose.sendBtn")}
              </button>
            </div>
          </form>
        </div>
      </section>
      </div>
    </AppShell>
  );
}

// Phase 4.5 (docs/25f) — banner shown above the compose body when
// the user opened compose via ?ai=1 (the Reader pane's "AI Draft
// Approve" entry point). Conveys two things: where the draft came
// from, and the security ask — *please review before sending*.
function AIDraftBanner({
  status,
  error,
  onOpenSettings,
  currentTone,
}: {
  status: "idle" | "no_key" | "generating" | "done" | "error";
  error: string | null;
  onOpenSettings: () => void;
  currentTone?: DraftTone | "default";
}) {
  const { t } = useTranslation();
  if (status === "idle") return null;

  let bg = "rgba(66, 133, 244, 0.08)";
  let border = "rgba(66, 133, 244, 0.28)";
  let color = "#1a73e8";
  let text = "";

  if (status === "no_key") {
    bg = "rgba(251, 188, 5, 0.1)";
    border = "rgba(251, 188, 5, 0.4)";
    color = "#b06000";
    text = t("compose.aiDraftNoKey");
  } else if (status === "generating") {
    text = t("compose.aiDraftGenerating");
  } else if (status === "done") {
    bg = "rgba(15, 157, 88, 0.08)";
    border = "rgba(15, 157, 88, 0.3)";
    color = "#0f9d58";
    const toneLabel =
      currentTone && currentTone !== "default"
        ? t(`compose.aiDraftTone.${currentTone}`)
        : null;
    text = toneLabel
      ? t("compose.aiDraftDoneWithTone", { tone: toneLabel })
      : t("compose.aiDraftDone");
  } else if (status === "error") {
    bg = "rgba(217, 48, 37, 0.08)";
    border = "rgba(217, 48, 37, 0.3)";
    color = "#d93025";
    const errorKey = error ? `compose.aiDraftError.${error}` : "compose.aiDraftError.api_error";
    text = t(errorKey);
  }

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        marginBottom: 8,
        padding: "8px 12px",
        borderRadius: 6,
        background: bg,
        border: `1px solid ${border}`,
        color,
        fontSize: 12,
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        flexWrap: "wrap",
      }}
      data-testid="compose-ai-draft-banner"
    >
      <div style={{ flex: 1, minWidth: 200 }}>
        <strong style={{ display: "block", marginBottom: 2 }}>
          {t("compose.aiDraftLabel")}
        </strong>
        <span>{text}</span>
        {status === "done" ? (
          <span style={{ display: "block", marginTop: 4, color: "#5f6368" }}>
            {t("compose.aiDraftReviewWarning")}
          </span>
        ) : null}
      </div>
      {status === "no_key" ? (
        <button
          type="button"
          className="btn"
          onClick={onOpenSettings}
          style={{ fontSize: 12 }}
        >
          {t("compose.aiDraftOpenSettings")}
        </button>
      ) : null}
    </div>
  );
}

// Phase 4.6 — tone toggle + Regenerate buttons. Sits between the
// banner and the textarea. Each button represents a distinct API
// call so the user is in control of when costs are incurred.
function AIDraftToolbar({
  currentTone,
  busy,
  bodyEdited,
  onPick,
  onRegenerate,
}: {
  currentTone: DraftTone | "default";
  busy: boolean;
  bodyEdited: boolean;
  onPick: (tone: DraftTone | "default") => void;
  onRegenerate: () => void;
}) {
  const { t } = useTranslation();
  const tones: Array<DraftTone | "default"> = [
    "default",
    "formal",
    "casual",
    "brief",
    "detailed",
  ];

  return (
    <div
      data-testid="compose-ai-draft-toolbar"
      style={{
        display: "flex",
        gap: 6,
        marginBottom: 8,
        flexWrap: "wrap",
        alignItems: "center",
      }}
    >
      <span style={{ fontSize: 12, color: "#5f6368", marginRight: 4 }}>
        {t("compose.aiDraftTone.label")}
      </span>
      {tones.map((tone) => {
        const selected = tone === currentTone;
        return (
          <button
            key={tone}
            type="button"
            disabled={busy}
            onClick={() => onPick(tone)}
            data-testid={`compose-ai-draft-tone-${tone}`}
            data-selected={selected}
            style={{
              padding: "4px 10px",
              borderRadius: 999,
              fontSize: 12,
              border: selected
                ? "1px solid #1a73e8"
                : "1px solid rgba(60,64,67,0.2)",
              background: selected ? "rgba(26,115,232,0.08)" : "transparent",
              color: selected ? "#1a73e8" : "#3c4043",
              cursor: busy ? "not-allowed" : "pointer",
              fontWeight: selected ? 600 : 400,
            }}
          >
            {t(`compose.aiDraftTone.${tone}`)}
          </button>
        );
      })}
      <button
        type="button"
        disabled={busy}
        onClick={onRegenerate}
        data-testid="compose-ai-draft-regenerate"
        style={{
          padding: "4px 10px",
          borderRadius: 999,
          fontSize: 12,
          border: "1px solid rgba(60,64,67,0.2)",
          background: "transparent",
          color: "#3c4043",
          cursor: busy ? "not-allowed" : "pointer",
          marginLeft: "auto",
        }}
      >
        ↻ {t("compose.aiDraftRegenerate")}
      </button>
      {bodyEdited ? (
        <span
          style={{ fontSize: 11, color: "#b06000" }}
          data-testid="compose-ai-draft-toolbar-edited-hint"
        >
          {t("compose.aiDraftEditedHint")}
        </span>
      ) : null}
    </div>
  );
}
