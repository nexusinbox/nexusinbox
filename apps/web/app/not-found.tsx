"use client";

import Link from "next/link";
import { useTranslation } from "../lib/i18n";

/**
 * 404 — the /login stage look, with plain words: what happened and where
 * to go next (docs/error_pages_mock.html §1).
 */
export default function NotFound() {
  const { t } = useTranslation();
  return (
    <main
      className="ai-login-root"
      style={{ background: "#0a0c18", color: "#e8ecff" }}
    >
      <div className="ai-login-grid" aria-hidden="true" />
      <div className="ai-login-stars" aria-hidden="true" />

      {/* Corner glyphs only, as on /login; no words in them. */}
      <div className="ai-login-hud" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
      </div>

      <section className="ai-login-card" role="dialog" aria-labelledby="ai-notfound-title">
        <div className="ai-login-brand">
          <span className="dot" />
          <span>NexusInbox</span>
        </div>

        <h1 id="ai-notfound-title" className="ai-login-title ai-error-title">
          {t("errors.notFoundTitle")}
        </h1>

        <p className="ai-login-subtitle">{t("errors.notFoundSubtitle")}</p>

        <div className="ai-login-cta-wrap">
          <Link className="ai-login-cta" href="/">
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
              <path d="M19 12H5" />
              <path d="M12 19l-7-7 7-7" />
            </svg>
            <span>{t("errors.backToInbox")}</span>
          </Link>
        </div>
        <Link className="ai-error-secondary" href="/help">
          {t("errors.openHelp")}
        </Link>
        <p className="ai-error-code">404</p>
      </section>
    </main>
  );
}
