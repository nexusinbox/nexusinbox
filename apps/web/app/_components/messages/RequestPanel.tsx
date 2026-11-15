"use client";

// 「この会話の依頼」 at the top of a conversation (docs/41 §7.3, mock
// docs/41_stage_c_conversation_mock.html): each scheduling or task request
// with where it stands, the last event that counted, and who moves next.
// The state comes from @nexusinbox/core/request-state, the same rules the
// gateway gives AI tools. Answering stays on the request's own card.

import { useState } from "react";
import {
  isFinished,
  type ConversationRequests,
  type RequestSummary,
} from "@nexusinbox/core/request-state";
import { useTranslation, type Locale } from "../../../lib/i18n";

/** Shown on the panel's tag, and in the folded list of finished ones. */
const TONE: Record<RequestSummary["state"], "you" | "them" | "ai" | "done" | "stop" | "bad" | "plain"> = {
  waiting_for_you: "you",
  waiting_for_them: "them",
  ai_started: "ai",
  ai_unknown: "stop",
  ai_replied: "ai",
  accepted: "them",
  agreed: "done",
  completed: "done",
  declined: "plain",
  expired: "stop",
  conflict: "bad",
  missing_original: "bad",
};

function when(iso: string | null, locale: Locale): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(locale === "ja" ? "ja-JP" : "en-US", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function RequestPanel({
  facts,
  incomplete,
  name,
  titleOf,
  onOpen,
}: {
  facts: ConversationRequests;
  /** Some messages of the conversation could not be read or checked yet. */
  incomplete: boolean;
  /** The other side's name. */
  name: string;
  /** The request's title (event title, task title), when its first message was read. */
  titleOf: (request: RequestSummary) => string | null;
  /** Scroll to the message a request's card is on. */
  onOpen: (messageId: string) => void;
}) {
  const { t, locale } = useTranslation();
  const [showFinished, setShowFinished] = useState(false);
  const open = facts.requests.filter((r) => !isFinished(r.state));
  const finished = facts.requests.filter((r) => isFinished(r.state));
  if (facts.requests.length === 0 && facts.unverified.length === 0) return null;

  const line = (r: RequestSummary) => {
    const vars = {
      name,
      at: when(r.last.at, locale),
      deadline: when(r.deadline, locale),
      started: when(r.ai_started_at, locale),
      start: when(r.selected?.start ?? null, locale),
      result: r.result ?? "",
    };
    const kind = r.type === "task_delegation" ? "task" : "schedule";
    // A completion report without a result ends at the time.
    const last = t(`requests.last.${r.state}.${r.last.mine ? "mine" : "theirs"}.${kind}`, vars).replace(/[:：]\s*$/, "");
    const next = t(`requests.next.${r.state}.${r.next}.${kind}`, vars);
    return { last, next, deadline: r.deadline && !isFinished(r.state) ? t("requests.deadline", vars) : "" };
  };

  const item = (r: RequestSummary) => {
    const { last, next, deadline } = line(r);
    const title = titleOf(r) ?? t(r.type === "task_delegation" ? "requests.untitledTask" : "requests.untitledSchedule");
    return (
      <div key={r.request_id} className="req-item" data-testid="request-item" data-state={r.state}>
        <div>
          <span className={`req-tag ${TONE[r.state]}`}>{t(`requests.state.${r.state}`)}</span>
          <span className="req-title">{title}</span>
        </div>
        <div className="req-last">{last}</div>
        {next ? <div className="req-next">{[next, deadline].filter(Boolean).join(" ")}</div> : null}
        {r.state === "waiting_for_you" || r.state === "conflict" || r.state === "ai_unknown" ? (
          <button type="button" className="req-open" onClick={() => onOpen(r.last.message_id)}>
            {r.state === "waiting_for_you" ? t("requests.openRequest") : t("requests.openHistory")}
          </button>
        ) : null}
      </div>
    );
  };

  return (
    <section className="req-panel" aria-label={t("requests.title")} data-testid="request-panel">
      <div className="req-panel-title">{t("requests.title")}</div>
      {incomplete ? <div className="req-note">{t("requests.incomplete")}</div> : null}
      {open.map(item)}
      {facts.unverified.length > 0 ? (
        <div className="req-item" data-testid="request-unverified" data-state="unverified">
          <div>
            <span className="req-tag bad">{t("requests.state.unverified")}</span>
            <span className="req-title">{t("requests.unverifiedTitle", { n: facts.unverified.length })}</span>
          </div>
          <div className="req-last">{t("requests.unverifiedBody")}</div>
        </div>
      ) : null}
      {finished.length > 0 ? (
        <>
          <button
            type="button"
            className="req-folded"
            aria-expanded={showFinished}
            onClick={() => setShowFinished((v) => !v)}
            data-testid="request-finished"
          >
            {showFinished ? "▾ " : "▸ "}
            {t("requests.finished", { n: finished.length })}
          </button>
          {showFinished ? finished.map(item) : null}
        </>
      ) : null}
    </section>
  );
}
