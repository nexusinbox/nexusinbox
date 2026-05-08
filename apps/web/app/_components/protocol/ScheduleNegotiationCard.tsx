"use client";

// Structured renderer for `schedule_negotiation` A2A messages.
// Separates the four action modes (propose / accept / decline /
// counter) and exposes Accept/Decline via callbacks.
//
// Invariants (see docs/24 §2.6):
// - `readOnly` comes from the Router and gates every action button.
// - The Card never computes "am I the recipient?" on its own.
// - `accept` / `decline` / `counter` are always read-only records,
//   regardless of readOnly — they're outcomes, not pending actions.

import { useState, type FormEvent } from "react";
import { isProposeExpired, type A2AProtocolBlock } from "@nexusinbox/core/a2a";
import type {
  ScheduleAcceptPayload,
  ScheduleCandidate,
  ScheduleCounterPayload,
  ScheduleDeclinePayload,
  ScheduleProposePayload,
} from "@nexusinbox/core/a2a";
import { useTranslation } from "../../../lib/i18n";
import type { ScheduleActionPayload } from "../../../lib/protocol/a2aReply";
import {
  CANDIDATE_MAX_COUNT,
  validateCandidateRows,
  type CandidateRow,
} from "../../../lib/protocol/candidateInput";

export type { ScheduleActionPayload };

export type ScheduleNegotiationCardProps = {
  protocol: A2AProtocolBlock;
  bodyText: string;
  /**
   * When true, disables every action button. The Router sets this
   * for sent-view, expired proposals, and non-propose actions.
   * The Card never overrides this locally — it's the single source
   * of truth for "can the user act here?".
   */
  readOnly: boolean;
  onRespond?: (reply: ScheduleActionPayload) => void | Promise<void>;
};

export function ScheduleNegotiationCard({
  protocol,
  bodyText,
  readOnly,
  onRespond,
}: ScheduleNegotiationCardProps) {
  const { t } = useTranslation();

  switch (protocol.action) {
    case "propose":
      return (
        <ProposeView
          payload={protocol.payload as ScheduleProposePayload}
          bodyText={bodyText}
          readOnly={readOnly}
          onRespond={onRespond}
          t={t}
        />
      );
    case "accept":
      return (
        <AcceptView
          payload={protocol.payload as ScheduleAcceptPayload}
          bodyText={bodyText}
          t={t}
        />
      );
    case "decline":
      return (
        <DeclineView
          payload={protocol.payload as ScheduleDeclinePayload}
          bodyText={bodyText}
          t={t}
        />
      );
    case "counter":
      return (
        <CounterView
          payload={protocol.payload as ScheduleCounterPayload}
          bodyText={bodyText}
          t={t}
        />
      );
  }
}

// ---------------------------------------------------------------------------
// Propose view — the only interactive one
// ---------------------------------------------------------------------------

type ProposeViewProps = {
  payload: ScheduleProposePayload;
  bodyText: string;
  readOnly: boolean;
  onRespond?: (reply: ScheduleActionPayload) => void | Promise<void>;
  t: ReturnType<typeof useTranslation>["t"];
};

function ProposeView({ payload, bodyText, readOnly, onRespond, t }: ProposeViewProps) {
  const [pending, setPending] = useState<
    "idle" | "accepting" | "declining" | "countering" | "done"
  >("idle");
  const [error, setError] = useState<string | null>(null);
  // Counter-proposal form is gated behind this flag so the card
  // stays compact by default — expanding only when the user
  // actually intends to send a counter.
  const [counterOpen, setCounterOpen] = useState(false);
  const expired = isProposeExpired(payload);
  const busy =
    pending === "accepting" ||
    pending === "declining" ||
    pending === "countering" ||
    pending === "done";
  const disabled = readOnly || expired || busy;

  const onAccept = async (candidate: ScheduleCandidate) => {
    if (disabled || !onRespond) return;
    if (typeof window !== "undefined" && !window.confirm(t("a2a.confirmAccept"))) return;
    setError(null);
    setPending("accepting");
    try {
      await onRespond({ action: "accept", selected_candidate: candidate });
      setPending("done");
    } catch (e) {
      setPending("idle");
      setError(e instanceof Error ? e.message : t("a2a.sendFailed"));
    }
  };

  const onDecline = async () => {
    if (disabled || !onRespond) return;
    if (typeof window !== "undefined" && !window.confirm(t("a2a.confirmDecline"))) return;
    setError(null);
    setPending("declining");
    try {
      await onRespond({ action: "decline" });
      setPending("done");
    } catch (e) {
      setPending("idle");
      setError(e instanceof Error ? e.message : t("a2a.sendFailed"));
    }
  };

  const onCounterSubmit = async (
    candidates: ScheduleCandidate[],
    reason?: string,
  ) => {
    if (disabled || !onRespond) return;
    if (typeof window !== "undefined" && !window.confirm(t("a2a.confirmCounter"))) return;
    setError(null);
    setPending("countering");
    try {
      await onRespond({ action: "counter", candidates, reason });
      setPending("done");
      setCounterOpen(false);
    } catch (e) {
      setPending("idle");
      setError(e instanceof Error ? e.message : t("a2a.sendFailed"));
    }
  };

  return (
    <section
      className="ai-protocol-card ai-protocol-card--propose"
      data-testid="schedule-propose-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.scheduleNegotiationLabel")}</span>
        <h3 className="ai-protocol-title">{payload.event_title}</h3>
        {expired ? (
          <span className="ai-protocol-badge ai-protocol-badge--expired" data-testid="schedule-expired-badge">
            {t("a2a.expired")}
          </span>
        ) : null}
      </header>

      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}

      <ul className="ai-protocol-candidates">
        {payload.candidates.map((c, idx) => (
          <li key={`${c.start}-${c.end}`} className="ai-protocol-candidate">
            <time dateTime={c.start} className="ai-protocol-candidate-time">
              {formatCandidate(c)}
            </time>
            <button
              type="button"
              className="ai-protocol-btn ai-protocol-btn--accept"
              disabled={disabled}
              onClick={() => void onAccept(c)}
              data-testid={`schedule-accept-btn-${idx}`}
            >
              {t("a2a.acceptButton")}
            </button>
          </li>
        ))}
      </ul>

      {payload.response_deadline ? (
        <p className="ai-protocol-meta" data-testid="schedule-deadline">
          {t("a2a.deadline", { time: formatTimestamp(payload.response_deadline) })}
        </p>
      ) : null}

      {payload.required_participants.length > 0 ? (
        <p className="ai-protocol-meta">
          {t("a2a.participantsAnnounced", { count: payload.required_participants.length })}
        </p>
      ) : null}

      <div className="ai-protocol-actions">
        <button
          type="button"
          className="ai-protocol-btn ai-protocol-btn--decline"
          disabled={disabled}
          onClick={() => void onDecline()}
          data-testid="schedule-decline-btn"
        >
          {t("a2a.declineButton")}
        </button>
        <button
          type="button"
          className="ai-protocol-btn ai-protocol-btn--counter"
          disabled={disabled}
          onClick={() => setCounterOpen((v) => !v)}
          aria-expanded={counterOpen}
          data-testid="schedule-counter-btn"
        >
          {counterOpen ? t("a2a.counterButtonClose") : t("a2a.counterButton")}
        </button>
      </div>

      {counterOpen ? (
        <CounterForm
          disabled={disabled}
          onSubmit={onCounterSubmit}
          onCancel={() => setCounterOpen(false)}
          t={t}
        />
      ) : null}

      {pending === "done" ? (
        <p className="ai-protocol-status ai-protocol-status--ok" data-testid="schedule-status-done">
          {t("a2a.replySent")}
        </p>
      ) : null}
      {error ? (
        <p className="ai-protocol-status ai-protocol-status--error" data-testid="schedule-status-error">
          {error}
        </p>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// CounterForm — recipient inputs alternative candidates (docs/24 §10
// original Phase 4.3 scope). Still recipient-gated (the parent
// ProposeView only mounts this when `disabled === false`), so the
// invariant that sender-view never sees action buttons is preserved.
// Emits a `counter` reply with validated candidates + optional reason.
// ---------------------------------------------------------------------------

type CounterFormProps = {
  disabled: boolean;
  onSubmit: (candidates: ScheduleCandidate[], reason?: string) => Promise<void>;
  onCancel: () => void;
  t: ReturnType<typeof useTranslation>["t"];
};

function CounterForm({ disabled, onSubmit, onCancel, t }: CounterFormProps) {
  const [rows, setRows] = useState<CandidateRow[]>([{ start: "", end: "" }]);
  const [reason, setReason] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const addRow = () => {
    if (rows.length >= CANDIDATE_MAX_COUNT) return;
    setRows((prev) => [...prev, { start: "", end: "" }]);
  };
  const removeRow = (idx: number) => {
    setRows((prev) => (prev.length <= 1 ? prev : prev.filter((_, i) => i !== idx)));
  };
  const updateRow = (idx: number, field: "start" | "end", value: string) => {
    setRows((prev) => prev.map((r, i) => (i === idx ? { ...r, [field]: value } : r)));
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const result = validateCandidateRows(rows, t);
    if (!result.ok) {
      setFormError(result.error);
      return;
    }
    await onSubmit(result.candidates, reason.trim() || undefined);
  };

  return (
    <form
      className="ai-protocol-counter-form"
      onSubmit={(e) => void handleSubmit(e)}
      data-testid="schedule-counter-form"
    >
      <h4 className="ai-protocol-counter-heading">{t("a2a.counterFormHeading")}</h4>
      <ul className="ai-protocol-counter-rows">
        {rows.map((row, idx) => (
          <li key={idx} className="ai-protocol-counter-row">
            <label>
              <span>{t("a2a.counterFieldStart")}</span>
              <input
                type="datetime-local"
                required
                value={row.start}
                disabled={disabled}
                onChange={(e) => updateRow(idx, "start", e.target.value)}
                data-testid={`schedule-counter-start-${idx}`}
              />
            </label>
            <label>
              <span>{t("a2a.counterFieldEnd")}</span>
              <input
                type="datetime-local"
                required
                value={row.end}
                disabled={disabled}
                onChange={(e) => updateRow(idx, "end", e.target.value)}
                data-testid={`schedule-counter-end-${idx}`}
              />
            </label>
            {rows.length > 1 ? (
              <button
                type="button"
                className="ai-protocol-btn ai-protocol-btn--ghost"
                disabled={disabled}
                onClick={() => removeRow(idx)}
                aria-label={t("a2a.counterRemoveCandidate")}
                data-testid={`schedule-counter-remove-${idx}`}
              >
                ×
              </button>
            ) : null}
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="ai-protocol-btn ai-protocol-btn--ghost"
        disabled={disabled || rows.length >= CANDIDATE_MAX_COUNT}
        onClick={addRow}
        data-testid="schedule-counter-add"
      >
        {t("a2a.counterAddCandidate")}
      </button>

      <label className="ai-protocol-counter-reason">
        <span>{t("a2a.counterFieldReason")}</span>
        <textarea
          rows={2}
          value={reason}
          disabled={disabled}
          onChange={(e) => setReason(e.target.value)}
          data-testid="schedule-counter-reason"
          placeholder={t("a2a.counterReasonPlaceholder")}
        />
      </label>

      {formError ? (
        <p
          className="ai-protocol-status ai-protocol-status--error"
          data-testid="schedule-counter-form-error"
          role="alert"
        >
          {formError}
        </p>
      ) : null}

      <div className="ai-protocol-counter-actions">
        <button
          type="button"
          className="ai-protocol-btn ai-protocol-btn--ghost"
          disabled={disabled}
          onClick={onCancel}
        >
          {t("a2a.counterCancel")}
        </button>
        <button
          type="submit"
          className="ai-protocol-btn ai-protocol-btn--counter"
          disabled={disabled}
          data-testid="schedule-counter-submit"
        >
          {t("a2a.counterSubmit")}
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Accept / Decline / Counter views — read-only
// ---------------------------------------------------------------------------

function AcceptView({
  payload,
  bodyText,
  t,
}: {
  payload: ScheduleAcceptPayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section
      className="ai-protocol-card ai-protocol-card--accept"
      data-testid="schedule-accept-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.scheduleNegotiationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--confirmed">
          {t("a2a.acceptedBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      <p className="ai-protocol-selected">
        {t("a2a.acceptedAt", { time: formatCandidate(payload.selected_candidate) })}
      </p>
    </section>
  );
}

function DeclineView({
  payload,
  bodyText,
  t,
}: {
  payload: ScheduleDeclinePayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section
      className="ai-protocol-card ai-protocol-card--decline"
      data-testid="schedule-decline-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.scheduleNegotiationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--declined">
          {t("a2a.declinedBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      {payload.reason ? (
        <p className="ai-protocol-reason" data-testid="schedule-decline-reason">
          {t("a2a.declineReason", { reason: payload.reason })}
        </p>
      ) : null}
    </section>
  );
}

function CounterView({
  payload,
  bodyText,
  t,
}: {
  payload: ScheduleCounterPayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section
      className="ai-protocol-card ai-protocol-card--counter"
      data-testid="schedule-counter-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.scheduleNegotiationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--counter">
          {t("a2a.counterBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      <ul className="ai-protocol-candidates ai-protocol-candidates--readonly">
        {payload.candidates.map((c) => (
          <li key={`${c.start}-${c.end}`} className="ai-protocol-candidate">
            <time dateTime={c.start}>{formatCandidate(c)}</time>
          </li>
        ))}
      </ul>
      {payload.reason ? (
        <p className="ai-protocol-reason">{t("a2a.counterReason", { reason: payload.reason })}</p>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function formatCandidate(c: ScheduleCandidate): string {
  const startLocal = formatTimestamp(c.start);
  const endLocal = formatTimestamp(c.end);
  return `${startLocal} – ${endLocal}`;
}

function formatTimestamp(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  // Locale-aware rendering keeps the offset visible at the expense
  // of strict wire-format preservation — acceptable for display.
  return new Date(ms).toLocaleString(undefined, {
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}
