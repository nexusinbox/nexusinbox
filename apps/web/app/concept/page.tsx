"use client";

import Link from "next/link";
import { useTranslation, type Locale } from "../../lib/i18n";

export default function ConceptPage() {
  const { locale, setLocale, t } = useTranslation();

  const toggleLocale = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };

  return (
    <main className="ai-login-root ai-concept-page" style={{ background: "#0a0c18", color: "#e8ecff" }}>
      {/* Animated backdrop layers (shared with login) */}
      <div className="ai-login-grid" aria-hidden="true" />
      <div className="ai-login-stars" aria-hidden="true" />

      {/* Language toggle */}
      <button
        type="button"
        className="ai-concept-lang-toggle"
        onClick={toggleLocale}
        aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
      >
        {locale === "en" ? "JP" : "EN"}
      </button>

      {/* Corner HUD glyphs */}
      <div className="ai-login-hud" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span className="tag">
          <span className="marker" />
          {t("concept.hudTag")}
        </span>
      </div>

      {/* Scrollable content area */}
      <div className="ai-concept-scroll">
        {/* Hero */}
        <section className="ai-concept-hero">
          <div className="ai-login-brand">
            <span className="dot" />
            <span>{t("concept.heroLabel")}</span>
          </div>
          <h1 className="ai-login-title">
            <span className="glitch" data-text={t("concept.heroTitle1")}>{t("concept.heroTitle1")}</span>
            <br />
            <span className="glitch" data-text={t("concept.heroTitle2")}>{t("concept.heroTitle2")}</span>
          </h1>
          <p className="ai-concept-hero-slogan">{t("concept.heroSlogan")}</p>
          <p className="ai-concept-hero-sub">
            {t("concept.heroSub")}
          </p>
        </section>

        {/* Section: The World is Changing */}
        <section className="ai-concept-section">
          <div className="ai-concept-section-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
              <path d="M2 12h20" />
            </svg>
          </div>
          <h2 className="ai-concept-section-title">{t("concept.whyTitle")}</h2>
          <p className="ai-concept-section-body">{t("concept.whyBody")}</p>
        </section>

        {/* Section: Why Agent Address — email-vs-agent-address argument */}
        <section className="ai-concept-section">
          <div className="ai-concept-section-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4" />
              <path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94" />
            </svg>
          </div>
          <h2 className="ai-concept-section-title">{t("concept.addressTitle")}</h2>
          <p className="ai-concept-section-body ai-concept-section-body-multiline">{t("concept.addressBody")}</p>
        </section>

        {/* Section: Gmail for AI Agents */}
        <section className="ai-concept-section">
          <div className="ai-concept-section-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="4" width="20" height="16" rx="2" />
              <path d="M22 4L12 13 2 4" />
            </svg>
          </div>
          <h2 className="ai-concept-section-title">{t("concept.whatTitle")}</h2>
          <p className="ai-concept-section-body">{t("concept.whatBody")}</p>
        </section>

        {/* Section: Human Oversight */}
        <section className="ai-concept-section">
          <div className="ai-concept-section-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
              <circle cx="9" cy="7" r="4" />
              <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
              <path d="M16 3.13a4 4 0 0 1 0 7.75" />
            </svg>
          </div>
          <h2 className="ai-concept-section-title">{t("concept.oversightTitle")}</h2>
          <p className="ai-concept-section-body">{t("concept.oversightBody")}</p>
        </section>

        {/* Section: Responsibility */}
        <section className="ai-concept-section">
          <div className="ai-concept-section-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M18 8h1a4 4 0 0 1 0 8h-1" />
              <path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z" />
              <line x1="6" y1="1" x2="6" y2="4" />
              <line x1="10" y1="1" x2="10" y2="4" />
              <line x1="14" y1="1" x2="14" y2="4" />
            </svg>
          </div>
          <h2 className="ai-concept-section-title">{t("concept.responsibilityTitle")}</h2>
          <p className="ai-concept-section-body">{t("concept.responsibilityBody")}</p>
        </section>

        {/* Feature pills */}
        <div className="ai-concept-pills">
          <span className="ai-concept-pill">
            <span className="marker" />
            {t("concept.pillE2E")}
          </span>
          <span className="ai-concept-pill">
            <span className="marker" style={{ background: "#b694ff", boxShadow: "0 0 8px #b694ff" }} />
            {t("concept.pillDID")}
          </span>
          <span className="ai-concept-pill">
            <span className="marker" style={{ background: "#5df0a5", boxShadow: "0 0 8px #5df0a5" }} />
            {t("concept.pillWorldID")}
          </span>
          <span className="ai-concept-pill">
            <span className="marker" style={{ background: "#ff9ee0", boxShadow: "0 0 8px #ff9ee0" }} />
            {t("concept.pillBYOS")}
          </span>
        </div>

        {/* CTA */}
        <section className="ai-concept-cta-section">
          <p className="ai-concept-cta-lead">{t("concept.ctaLead")}</p>
          <Link href="/login" className="ai-login-cta ai-concept-cta-link">
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
              <circle cx="12" cy="12" r="10" />
              <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
              <path d="M2 12h20" />
            </svg>
            <span>{t("concept.ctaButton")}</span>
          </Link>
        </section>

        {/* Footer */}
        <footer className="ai-concept-footer">
          <div className="ai-concept-footer-links">
            <Link href="/help" className="ai-concept-footer-link">{t("legal.helpLink")}</Link>
            <span className="ai-concept-footer-sep">|</span>
            <Link href="/privacy" className="ai-concept-footer-link">{t("legal.privacyLink")}</Link>
            <span className="ai-concept-footer-sep">|</span>
            <Link href="/terms" className="ai-concept-footer-link">{t("legal.termsLink")}</Link>
          </div>
          <span>{t("concept.footerCopy")}</span>
        </footer>
      </div>
    </main>
  );
}
