"use client";

import Link from "next/link";
import { useTranslation } from "../lib/i18n";

/**
 * 404 — styled to match the /login and /concept stages so every
 * pre-auth / out-of-shell page shares the same dark animated identity.
 * Uses the existing `.ai-login-*` CSS so there's no new selector to
 * maintain; only the card content differs.
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

      {/* Corner HUD glyphs, same as /login for visual continuity. */}
      <div className="ai-login-hud" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span className="tag">
          <span className="marker" />
          {t("errors.notFoundLabel")}
        </span>
      </div>

      <section className="ai-login-card" role="dialog" aria-labelledby="ai-notfound-title">
        <div className="ai-login-brand">
          <span className="dot" />
          <span>{t("errors.notFoundLabel")}</span>
        </div>

        <h1 id="ai-notfound-title" className="ai-login-title">
          <span className="glitch" data-text={t("errors.notFoundTitle1")}>
            {t("errors.notFoundTitle1")}
          </span>
          <br />
          <span className="glitch" data-text={t("errors.notFoundTitle2")}>
            {t("errors.notFoundTitle2")}
          </span>
        </h1>

        <p className="ai-login-subtitle" style={{ whiteSpace: "pre-line" }}>
          {t("errors.notFoundSubtitle")}
        </p>

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
      </section>
    </main>
  );
}
