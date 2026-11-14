"use client";

// The notices above the inbox share one card (mock docs/inbox_notices_mock.html):
// colour by how serious it is, one row per agent, one 「あとで」 per card.

import { Fragment, type ReactNode } from "react";

export type NoticeTone = "danger" | "warn" | "info";

export function NoticeCard({
  tone,
  title,
  sub,
  onLater,
  laterLabel,
  testId,
  children,
}: {
  tone: NoticeTone;
  title: string;
  /** One line under the title, for the whole card. */
  sub?: string;
  /** Hides the card's notices for now; no button without it. */
  onLater?: () => void;
  laterLabel?: string;
  testId?: string;
  children?: ReactNode;
}) {
  return (
    <section
      className={`notice-card ${tone}`}
      role={tone === "info" ? "status" : "alert"}
      data-testid={testId}
    >
      <div className="notice-head">
        <span className={`notice-icon ${tone}`} aria-hidden>
          {tone === "info" ? "i" : "!"}
        </span>
        <div className="notice-title">
          <p className="notice-title-text">{title}</p>
          {sub ? <p className="notice-sub">{sub}</p> : null}
        </div>
        {onLater ? (
          <button type="button" className="notice-later" onClick={onLater}>
            {laterLabel}
          </button>
        ) : null}
      </div>
      {children}
    </section>
  );
}

/**
 * One agent (or device) in a card: its name, why, and what to do. A why given
 * in parts is joined with " · " and wraps between parts, not inside one.
 */
export function NoticeRow({ name, why, action }: { name: string; why: string | string[]; action?: ReactNode }) {
  const parts = typeof why === "string" ? [why] : why;
  return (
    <div className="notice-row">
      <span className="notice-row-name">{name}</span>
      <span className="notice-row-why">
        {parts.map((part, i) => (
          <Fragment key={i}>
            {i > 0 ? " " : null}
            {/* The dot stays with the part before it, so a line never starts with one. */}
            <span className="notice-part">{i < parts.length - 1 ? `${part} ·` : part}</span>
          </Fragment>
        ))}
      </span>
      {action ? <span className="notice-row-action">{action}</span> : null}
    </div>
  );
}
