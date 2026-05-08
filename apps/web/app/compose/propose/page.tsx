"use client";

// Compose a new `schedule_negotiation` propose (docs/24). This is
// the outbound counterpart to the ScheduleNegotiationCard — the
// card shows propose messages in the inbox, this page creates one
// from scratch. Kept as a separate route (`/compose/propose`) so
// the plain compose page doesn't grow a mode switch; the two
// flows share helpers via lib/protocol/* but don't share a form.
//
// A2A envelope build happens client-side (same reason as
// sendProtocolReply — the main @nexusinbox/core entry isn't
// browser-safe; we inline the Web Crypto path).

import Link from "next/link";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { AppShell } from "../../_components/AppShell";
import {
  A2A_CONTENT_TYPE,
  assertValidScheduleNegotiationPayload,
  uuidv7,
  type A2AMessagePayload,
  type A2AProtocolBlock,
  type ScheduleProposePayload,
} from "@nexusinbox/core/a2a";
import { defaultApiClient } from "../../../lib/api/client";
import {
  useAgentsQuery,
  useContactsQuery,
  useSendMessageMutation,
} from "../../../lib/api/hooks";
import {
  encryptEnvelopeText,
  generateContentKey,
} from "../../../lib/crypto/envelope";
import { wrapContentKeyForRecipient } from "../../../lib/crypto/keywrap";
import { signEnvelopePayload } from "../../../lib/crypto/signature";
import { getSigningPrivateKey, hasSigningPrivateKeyMaterial } from "../../../lib/crypto/signing-keyring";
import {
  CANDIDATE_MAX_COUNT,
  toIsoWithLocalOffset,
  validateCandidateRows,
  type CandidateRow,
} from "../../../lib/protocol/candidateInput";
import { useTranslation } from "../../../lib/i18n";
import type { RecipientResolutionResponse } from "../../../lib/api/types";

function isAidIdentifier(value: string): boolean {
  return value.startsWith("aid:ai:");
}

type StatusState = { kind: "info" | "error" | "success"; message: string } | null;

export default function ProposePage() {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const contactsQuery = useContactsQuery();
  const sendMessage = useSendMessageMutation();

  const apiAgents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const contacts = useMemo(() => contactsQuery.data?.contacts ?? [], [contactsQuery.data]);

  const recipientOptions = useMemo(() => {
    const seen = new Set<string>();
    const opts: Array<{ did: string; label: string }> = [];
    for (const a of apiAgents) {
      if (!seen.has(a.did)) {
        seen.add(a.did);
        opts.push({ did: a.did, label: a.label });
      }
    }
    for (const c of contacts) {
      if (!seen.has(c.did)) {
        seen.add(c.did);
        const label = c.agent_label ? `${c.person_name}(${c.agent_label})` : c.person_name;
        opts.push({ did: c.did, label });
      }
    }
    return opts;
  }, [apiAgents, contacts]);

  const [senderDid, setSenderDid] = useState("");
  const [recipientDid, setRecipientDid] = useState("");
  const [eventTitle, setEventTitle] = useState("");
  const [rows, setRows] = useState<CandidateRow[]>([{ start: "", end: "" }]);
  const [deadline, setDeadline] = useState("");
  const [note, setNote] = useState("");
  const [hasSenderKey, setHasSenderKey] = useState(false);
  const [status, setStatus] = useState<StatusState>(null);
  const [pending, setPending] = useState(false);

  // Default sender to the first agent once the list loads.
  useEffect(() => {
    if (apiAgents.length === 0) {
      setSenderDid("");
      return;
    }
    setSenderDid((current) => {
      if (current && apiAgents.some((a) => a.did === current)) return current;
      return apiAgents[0].did;
    });
  }, [apiAgents]);

  // Load the local signing key for the selected sender. Disables
  // submit when the key isn't on this device (Isolated mode / no-local-key
  // — same rule as compose page).
  useEffect(() => {
    if (!senderDid) {
      setHasSenderKey(false);
      return;
    }
    let cancelled = false;
    void hasSigningPrivateKeyMaterial(senderDid).then((ok) => {
      if (!cancelled) setHasSenderKey(ok);
    });
    return () => {
      cancelled = true;
    };
  }, [senderDid]);

  const addRow = () => {
    if (rows.length >= CANDIDATE_MAX_COUNT) return;
    setRows((prev) => [...prev, { start: "", end: "" }]);
  };
  const removeRow = (idx: number) =>
    setRows((prev) => (prev.length <= 1 ? prev : prev.filter((_, i) => i !== idx)));
  const updateRow = (idx: number, field: "start" | "end", value: string) =>
    setRows((prev) => prev.map((r, i) => (i === idx ? { ...r, [field]: value } : r)));

  const submitDisabled = pending || !senderDid || !hasSenderKey || !recipientDid.trim() || !eventTitle.trim();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setStatus(null);

    const candidateResult = validateCandidateRows(rows, t);
    if (!candidateResult.ok) {
      setStatus({ kind: "error", message: candidateResult.error });
      return;
    }

    let responseDeadline: string | undefined;
    if (deadline) {
      const iso = toIsoWithLocalOffset(deadline);
      if (!iso) {
        setStatus({ kind: "error", message: t("a2a.proposeValidationDeadline") });
        return;
      }
      responseDeadline = iso;
    }

    const proposePayload: ScheduleProposePayload = {
      event_title: eventTitle.trim(),
      candidates: candidateResult.candidates,
      required_participants: [],
      ...(responseDeadline ? { response_deadline: responseDeadline } : {}),
    };

    try {
      assertValidScheduleNegotiationPayload("propose", proposePayload);
    } catch (err) {
      setStatus({
        kind: "error",
        message: err instanceof Error ? err.message : t("a2a.proposeValidationGeneric"),
      });
      return;
    }

    setPending(true);
    try {
      setStatus({ kind: "info", message: t("a2a.proposeStatusEncrypting") });
      const recipientInput = recipientDid.trim();
      let resolved: RecipientResolutionResponse | null = null;
      if (isAidIdentifier(recipientInput) || recipientInput.startsWith("did:key:")) {
        resolved = await defaultApiClient.resolveRecipient(recipientInput);
      }
      const recipientAddress = resolved?.did ?? recipientInput;
      const recipientEncKey =
        resolved?.encryption_public_key ??
        apiAgents.find((a) => a.did === recipientInput)?.encryption_key;
      if (!recipientEncKey) {
        setStatus({ kind: "error", message: t("a2a.proposeValidationNoEncKey") });
        setPending(false);
        return;
      }

      const signingPrivateKey = await getSigningPrivateKey(senderDid);
      if (!signingPrivateKey) {
        setStatus({ kind: "error", message: t("a2a.proposeKeyMissing") });
        setPending(false);
        return;
      }

      const protocolBlock: A2AProtocolBlock = {
        id: uuidv7(),
        type: "schedule_negotiation",
        action: "propose",
        reply_to: null,
        payload: proposePayload,
      };
      const a2aPayload: A2AMessagePayload = {
        v: 1,
        body: note.trim() || eventTitle.trim(),
        protocol: protocolBlock,
      };
      const serialised = JSON.stringify(a2aPayload);

      const contentKey = generateContentKey();
      const encSubject = await encryptEnvelopeText(eventTitle.trim(), { contentKey });
      const encBody = await encryptEnvelopeText(serialised, { contentKey });
      const wrapped = await wrapContentKeyForRecipient(contentKey, recipientEncKey);
      const signature = await signEnvelopePayload({
        signingPrivateKey,
        senderDid,
        recipientDid: recipientAddress,
        subjectEncrypted: encSubject.serialized,
        encryptedContent: encBody.serialized,
        encryptedKey: wrapped.wrappedKey,
        nonce: encBody.nonce,
      });

      setStatus({ kind: "info", message: t("a2a.proposeStatusSending") });
      await sendMessage.mutateAsync({
        senderDid,
        recipientDid: recipientAddress,
        subjectEncrypted: encSubject.serialized,
        encryptedContent: encBody.serialized,
        encryptedKey: wrapped.wrappedKey,
        nonce: encBody.nonce,
        signature,
        // New thread — server assigns the id.
        threadId: null,
        contentType: A2A_CONTENT_TYPE,
      });

      setStatus({ kind: "success", message: t("a2a.proposeStatusSent") });
      // Reset interactive fields but keep sender/recipient so users
      // can quickly propose again to the same contact.
      setEventTitle("");
      setNote("");
      setDeadline("");
      setRows([{ start: "", end: "" }]);
    } catch (err) {
      setStatus({
        kind: "error",
        message: err instanceof Error ? err.message : t("a2a.sendFailed"),
      });
    } finally {
      setPending(false);
    }
  }

  return (
    <AppShell title={t("a2a.proposePageTitle")} activePath="/compose">
      <div className="compose-scroll">
        <section className="compose-frame">
          <header className="compose-head">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <span>{t("a2a.proposePageTitle")}</span>
              <span className="item-sub">
                {t("a2a.proposePageSubtitle")}
              </span>
            </div>
            <Link
              href="/compose"
              className="compose-head-link"
              data-testid="propose-back-link"
            >
              ← {t("a2a.proposeBackToCompose")}
            </Link>
          </header>

          <div className="compose-body">
            <form onSubmit={(e) => void onSubmit(e)} className="form-grid">
              <div className="field">
                <label className="field-label" htmlFor="propose-sender">
                  {t("compose.fromLabel")}
                </label>
                <select
                  id="propose-sender"
                  className="select"
                  value={senderDid}
                  onChange={(e) => setSenderDid(e.target.value)}
                  disabled={pending || apiAgents.length === 0}
                  data-testid="propose-sender"
                >
                  {apiAgents.map((a) => (
                    <option key={a.did} value={a.did}>
                      {a.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="propose-recipient">
                  {t("compose.toLabel")}
                </label>
                <input
                  id="propose-recipient"
                  className="input"
                  list="propose-recipient-options"
                  type="text"
                  value={recipientDid}
                  onChange={(e) => setRecipientDid(e.target.value)}
                  placeholder="aid:ai:… or did:key:…"
                  disabled={pending}
                  required
                  data-testid="propose-recipient"
                />
                <datalist id="propose-recipient-options">
                  {recipientOptions.map((o) => (
                    <option key={o.did} value={o.did}>
                      {o.label}
                    </option>
                  ))}
                </datalist>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="propose-event-title">
                  {t("a2a.proposeFieldEventTitle")}
                </label>
                <input
                  id="propose-event-title"
                  className="input"
                  type="text"
                  value={eventTitle}
                  onChange={(e) => setEventTitle(e.target.value)}
                  disabled={pending}
                  required
                  data-testid="propose-event-title"
                />
              </div>

              <div className="field">
                <label className="field-label">{t("a2a.proposeFieldCandidates")}</label>
                <div style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                  padding: '20px',
                  background: 'rgba(0,0,0,0.015)',
                  borderRadius: '12px',
                  border: '1px solid var(--line)'
                }}>
                  {rows.map((row, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-end', gap: '12px' }}>
                      <div className="field" style={{ flex: 1 }}>
                        <label className="field-label" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {t("a2a.counterFieldStart")}
                        </label>
                        <input
                          className="input"
                          type="datetime-local"
                          required
                          value={row.start}
                          disabled={pending}
                          onChange={(e) => updateRow(idx, "start", e.target.value)}
                          data-testid={`propose-start-${idx}`}
                        />
                      </div>
                      <div className="field" style={{ flex: 1 }}>
                        <label className="field-label" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {t("a2a.counterFieldEnd")}
                        </label>
                        <input
                          className="input"
                          type="datetime-local"
                          required
                          value={row.end}
                          disabled={pending}
                          onChange={(e) => updateRow(idx, "end", e.target.value)}
                          data-testid={`propose-end-${idx}`}
                        />
                      </div>
                      {rows.length > 1 && (
                        <button
                          type="button"
                          className="btn"
                          style={{ minWidth: '40px', padding: 0, justifyContent: 'center', height: '44px', borderRadius: '10px' }}
                          disabled={pending}
                          onClick={() => removeRow(idx)}
                          aria-label={t("a2a.counterRemoveCandidate")}
                          data-testid={`propose-remove-${idx}`}
                        >
                          ×
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    type="button"
                    className="btn"
                    style={{ marginTop: '4px', alignSelf: 'flex-start' }}
                    disabled={pending || rows.length >= CANDIDATE_MAX_COUNT}
                    onClick={addRow}
                    data-testid="propose-add"
                  >
                    + {t("a2a.counterAddCandidate")}
                  </button>
                </div>
              </div>

              <div className="field">
                <label className="field-label" htmlFor="propose-deadline">
                  {t("a2a.proposeFieldDeadline")}
                </label>
                <input
                  id="propose-deadline"
                  className="input"
                  type="datetime-local"
                  value={deadline}
                  disabled={pending}
                  onChange={(e) => setDeadline(e.target.value)}
                  data-testid="propose-deadline"
                />
              </div>

              <div className="field">
                <label className="field-label" htmlFor="propose-note">
                  {t("a2a.proposeFieldNote")}
                </label>
                <textarea
                  id="propose-note"
                  className="textarea"
                  rows={3}
                  value={note}
                  disabled={pending}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder={t("a2a.proposeNotePlaceholder")}
                  data-testid="propose-note"
                />
              </div>

              {status ? (
                <div style={{ marginTop: '8px' }}>
                  <span className={`badge ${status.kind === "success" ? "ok" : status.kind === "error" ? "error" : ""}`}>
                    {status.message}
                  </span>
                </div>
              ) : null}

              <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="submit"
                  className="btn-premium primary"
                  style={{ minWidth: '160px' }}
                  disabled={submitDisabled}
                  data-testid="propose-submit"
                >
                  {pending ? t("a2a.proposeStatusSending") : t("a2a.proposeSubmit")}
                </button>
              </div>
            </form>
          </div>
        </section>
      </div>
    </AppShell>
  );
}
