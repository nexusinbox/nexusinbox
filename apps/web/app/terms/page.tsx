"use client";

import Link from "next/link";
import { useTranslation, type Locale } from "../../lib/i18n";

export default function TermsPage() {
  const { locale, setLocale, t } = useTranslation();

  const toggleLocale = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };

  return (
    <main
      className="ai-login-root ai-concept-page"
      style={{ background: "#0a0c18", color: "#e8ecff" }}
    >
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

      <div className="ai-concept-scroll ai-legal-scroll">
        {/* Header */}
        <header className="ai-legal-header">
          <Link href="/concept" className="ai-legal-back">
            ← {t("legal.backToConcept")}
          </Link>
          <h1 className="ai-legal-title">{t("terms.title")}</h1>
          <p className="ai-legal-updated">
            {t("terms.lastUpdated")}
          </p>
        </header>

        {/* Introduction */}
        <section className="ai-legal-section">
          <p className="ai-legal-body">{t("terms.introBody")}</p>
        </section>

        {/* 1. Service overview */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.overviewTitle")}</h2>
          <p className="ai-legal-body">{t("terms.overviewBody")}</p>
        </section>

        {/* 2. Eligibility */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.eligibilityTitle")}</h2>
          <p className="ai-legal-body">{t("terms.eligibilityBody")}</p>
        </section>

        {/* 3. Account & Authentication */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.accountTitle")}</h2>
          <p className="ai-legal-body">{t("terms.accountBody")}</p>
        </section>

        {/* 4. Your content */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.contentTitle")}</h2>
          <p className="ai-legal-body">{t("terms.contentBody")}</p>
        </section>

        {/* 5. AI agent usage */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.agentUsageTitle")}</h2>
          <p className="ai-legal-body">{t("terms.agentUsageBody")}</p>
        </section>

        {/* 6. Prohibited conduct */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.prohibitedTitle")}</h2>
          <p className="ai-legal-body">{t("terms.prohibitedBody")}</p>
        </section>

        {/* 7. Service availability & modification */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.availabilityTitle")}</h2>
          <p className="ai-legal-body">{t("terms.availabilityBody")}</p>
        </section>

        {/* 8. Disclaimer of warranties */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.disclaimerTitle")}</h2>
          <p className="ai-legal-body">{t("terms.disclaimerBody")}</p>
        </section>

        {/* 9. Limitation of liability */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.liabilityTitle")}</h2>
          <p className="ai-legal-body">{t("terms.liabilityBody")}</p>
        </section>

        {/* 10. Account suspension & termination */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.terminationTitle")}</h2>
          <p className="ai-legal-body">{t("terms.terminationBody")}</p>
        </section>

        {/* 11. Governing law */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.governingTitle")}</h2>
          <p className="ai-legal-body">{t("terms.governingBody")}</p>
        </section>

        {/* 12. Changes to terms */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.changesToTermsTitle")}</h2>
          <p className="ai-legal-body">{t("terms.changesToTermsBody")}</p>
        </section>

        {/* 13. Contact */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("terms.contactTitle")}</h2>
          <p className="ai-legal-body">{t("terms.contactBody")}</p>
          <a
            href="https://docs.google.com/forms/d/e/1FAIpQLSexUwLy_n8cW99r_wf7TDCNPS2-4tEov3G9zdmZux96Jc1ffw/viewform"
            target="_blank"
            rel="noopener noreferrer"
            className="ai-legal-contact-link"
          >
            {t("terms.contactLinkLabel")} ↗
          </a>
        </section>

        {/* Footer */}
        <footer className="ai-legal-footer">
          <Link href="/help" className="ai-legal-footer-link">
            {t("legal.helpLink")}
          </Link>
          <span className="ai-legal-footer-sep">|</span>
          <Link href="/privacy" className="ai-legal-footer-link">
            {t("legal.privacyLink")}
          </Link>
          <span className="ai-legal-footer-sep">|</span>
          <Link href="/concept" className="ai-legal-footer-link">
            {t("legal.conceptLink")}
          </Link>
        </footer>
      </div>
    </main>
  );
}
