"use client";

import Link from "next/link";
import { useTranslation } from "../lib/i18n";

/**
 * Runtime error boundary — shares the /login stage styling so unplanned
 * failures feel like part of the product instead of a browser default.
 * `reset()` comes from Next.js and re-renders the nearest route segment
 * without a full reload, which is the lightest possible recovery action.
 */
export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const { t } = useTranslation();
  return (
    <main
      className="ai-login-root"
      style={{ background: "#0a0c18", color: "#e8ecff" }}
    >
      <div className="ai-login-grid" aria-hidden="true" />
      <div className="ai-login-stars" aria-hidden="true" />

      <div className="ai-login-hud" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
      </div>

      <section className="ai-login-card" role="alertdialog" aria-labelledby="ai-error-title">
        <div className="ai-login-brand">
          <span className="dot" />
          <span>NexusInbox</span>
        </div>

        <h1 id="ai-error-title" className="ai-login-title ai-error-title">
          {t("errors.errorTitle")}
        </h1>

        <p className="ai-login-subtitle">{t("errors.errorSubtitle")}</p>

        <div className="ai-login-cta-wrap">
          <button
            className="ai-login-cta"
            type="button"
            onClick={reset}
          >
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M3 12a9 9 0 1 0 9-9" />
              <path d="M3 5v7h7" />
            </svg>
            <span>{t("errors.tryAgain")}</span>
          </button>
        </div>
        <Link className="ai-error-secondary" href="/">
          {t("errors.backToInbox")}
        </Link>
        {/* The program's own message, only for someone asking for help. */}
        <details className="ai-error-details">
          <summary>{t("errors.details")}</summary>
          <code>
            {error.message || "-"}
            {error.digest ? ` (${error.digest})` : ""}
          </code>
        </details>
      </section>
    </main>
  );
}
