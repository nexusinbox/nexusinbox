"use client";

// Structured renderer for `task_delegation` A2A messages.
// Parallels ScheduleNegotiationCard in layout and state-machine —
// the Router picks this when `protocol.type === "task_delegation"`.
//
// Invariants (docs/24 §2.6, applied per-type in canRespondToProtocol):
// - Only the recipient of a `delegate` sees Accept / Decline.
// - `accept`, `decline`, and `complete` action records are always
//   read-only outcomes; no affordance.
// - `complete` is NOT shown as an action button on the delegate
//   card for v1 — the agent (or a future Phase 4.5 UI) owns
//   reporting completion. Reporting from the Web UI arrives once
//   task state is surfaced explicitly in the inbox list.

import { useState } from "react";
import type {
  A2AProtocolBlock,
  TaskAcceptPayload,
  TaskCompletePayload,
  TaskDeclinePayload,
  TaskDelegatePayload,
} from "@nexusinbox/core/a2a";
import { useTranslation } from "../../../lib/i18n";
import type { TaskActionPayload } from "../../../lib/protocol/a2aReply";

export type TaskDelegationCardProps = {
  protocol: A2AProtocolBlock;
  bodyText: string;
  readOnly: boolean;
  onRespond?: (reply: TaskActionPayload) => void | Promise<void>;
};

export function TaskDelegationCard({
  protocol,
  bodyText,
  readOnly,
  onRespond,
}: TaskDelegationCardProps) {
  const { t } = useTranslation();

  switch (protocol.action) {
    case "delegate":
      return (
        <DelegateView
          payload={protocol.payload as TaskDelegatePayload}
          bodyText={bodyText}
          readOnly={readOnly}
          onRespond={onRespond}
          t={t}
        />
      );
    case "accept":
      return (
        <TaskAcceptView
          payload={protocol.payload as TaskAcceptPayload}
          bodyText={bodyText}
          t={t}
        />
      );
    case "decline":
      return (
        <TaskDeclineView
          payload={protocol.payload as TaskDeclinePayload}
          bodyText={bodyText}
          t={t}
        />
      );
    case "complete":
      return (
        <TaskCompleteView
          payload={protocol.payload as TaskCompletePayload}
          bodyText={bodyText}
          t={t}
        />
      );
    default:
      // propose / counter shouldn't reach here per isActionValidForType,
      // but render a stub just in case a future action slips through.
      return (
        <section className="ai-protocol-card ai-protocol-card--unknown">
          <p>{bodyText}</p>
        </section>
      );
  }
}

// ---------------------------------------------------------------------------
// Delegate view — interactive
// ---------------------------------------------------------------------------

type DelegateViewProps = {
  payload: TaskDelegatePayload;
  bodyText: string;
  readOnly: boolean;
  onRespond?: (reply: TaskActionPayload) => void | Promise<void>;
  t: ReturnType<typeof useTranslation>["t"];
};

function DelegateView({ payload, bodyText, readOnly, onRespond, t }: DelegateViewProps) {
  const [pending, setPending] = useState<"idle" | "accepting" | "declining" | "done">("idle");
  const [error, setError] = useState<string | null>(null);
  const busy = pending !== "idle";
  const disabled = readOnly || busy;

  const onAccept = async () => {
    if (disabled || !onRespond) return;
    if (typeof window !== "undefined" && !window.confirm(t("a2a.confirmAcceptTask"))) return;
    setError(null);
    setPending("accepting");
    try {
      await onRespond({ action: "accept" });
      setPending("done");
    } catch (e) {
      setPending("idle");
      setError(e instanceof Error ? e.message : t("a2a.sendFailed"));
    }
  };

  const onDecline = async () => {
    if (disabled || !onRespond) return;
    if (typeof window !== "undefined" && !window.confirm(t("a2a.confirmDeclineTask"))) return;
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

  const priorityBadge = payload.priority ? (
    <span
      className={`ai-protocol-badge ai-protocol-badge--priority ai-protocol-badge--priority-${payload.priority}`}
      data-testid="task-priority-badge"
    >
      {t(`a2a.taskPriority.${payload.priority}`)}
    </span>
  ) : null;

  return (
    <section
      className="ai-protocol-card ai-protocol-card--task-delegate"
      data-testid="task-delegate-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.taskDelegationLabel")}</span>
        <h3 className="ai-protocol-title">{payload.title}</h3>
        {priorityBadge}
      </header>

      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}

      {payload.description ? (
        <p className="ai-protocol-task-description" data-testid="task-description">
          {payload.description}
        </p>
      ) : null}

      {payload.due_date ? (
        <p className="ai-protocol-meta" data-testid="task-due-date">
          {t("a2a.taskDueDate", { time: formatTimestamp(payload.due_date) })}
        </p>
      ) : null}

      <div className="ai-protocol-actions">
        <button
          type="button"
          className="ai-protocol-btn ai-protocol-btn--accept"
          disabled={disabled}
          onClick={() => void onAccept()}
          data-testid="task-accept-btn"
        >
          {t("a2a.acceptButton")}
        </button>
        <button
          type="button"
          className="ai-protocol-btn ai-protocol-btn--decline"
          disabled={disabled}
          onClick={() => void onDecline()}
          data-testid="task-decline-btn"
        >
          {t("a2a.declineButton")}
        </button>
      </div>

      {pending === "done" ? (
        <p className="ai-protocol-status ai-protocol-status--ok" data-testid="task-status-done">
          {t("a2a.replySent")}
        </p>
      ) : null}
      {error ? (
        <p className="ai-protocol-status ai-protocol-status--error" data-testid="task-status-error">
          {error}
        </p>
      ) : null}
    </section>
  );
}

// ---------------------------------------------------------------------------
// Read-only outcome views
// ---------------------------------------------------------------------------

function TaskAcceptView({
  payload,
  bodyText,
  t,
}: {
  payload: TaskAcceptPayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section className="ai-protocol-card ai-protocol-card--accept" data-testid="task-accept-card">
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.taskDelegationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--confirmed">
          {t("a2a.taskAcceptedBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      {payload.note ? (
        <p className="ai-protocol-reason" data-testid="task-accept-note">
          {payload.note}
        </p>
      ) : null}
    </section>
  );
}

function TaskDeclineView({
  payload,
  bodyText,
  t,
}: {
  payload: TaskDeclinePayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section className="ai-protocol-card ai-protocol-card--decline" data-testid="task-decline-card">
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.taskDelegationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--declined">
          {t("a2a.declinedBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      {payload.reason ? (
        <p className="ai-protocol-reason" data-testid="task-decline-reason">
          {t("a2a.declineReason", { reason: payload.reason })}
        </p>
      ) : null}
    </section>
  );
}

function TaskCompleteView({
  payload,
  bodyText,
  t,
}: {
  payload: TaskCompletePayload;
  bodyText: string;
  t: ReturnType<typeof useTranslation>["t"];
}) {
  return (
    <section
      className="ai-protocol-card ai-protocol-card--task-complete"
      data-testid="task-complete-card"
    >
      <header className="ai-protocol-header">
        <span className="ai-protocol-kind">{t("a2a.taskDelegationLabel")}</span>
        <span className="ai-protocol-badge ai-protocol-badge--confirmed">
          {t("a2a.taskCompletedBadge")}
        </span>
      </header>
      {bodyText ? <p className="ai-protocol-body">{bodyText}</p> : null}
      {payload.result ? (
        <p className="ai-protocol-task-result" data-testid="task-complete-result">
          {t("a2a.taskCompleteResult", { result: payload.result })}
        </p>
      ) : null}
    </section>
  );
}

function formatTimestamp(iso: string): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return iso;
  return new Date(ms).toLocaleString(undefined, {
    year: "numeric",
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}
