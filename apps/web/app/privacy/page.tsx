"use client";

import Link from "next/link";
import { useTranslation, type Locale } from "../../lib/i18n";

export default function PrivacyPage() {
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
          <h1 className="ai-legal-title">{t("privacy.title")}</h1>
          <p className="ai-legal-updated">
            {t("privacy.lastUpdated")}
          </p>
        </header>

        {/* Introduction */}
        <section className="ai-legal-section">
          <p className="ai-legal-body">{t("privacy.introBody")}</p>
        </section>

        {/* 1. Service provider */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.providerTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.providerBody")}</p>
        </section>

        {/* 2. Information we collect */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.collectTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.collectIntro")}</p>

          <h3 className="ai-legal-subheading">{t("privacy.collectAuthTitle")}</h3>
          <p className="ai-legal-body">{t("privacy.collectAuthBody")}</p>

          <h3 className="ai-legal-subheading">{t("privacy.collectAgentTitle")}</h3>
          <p className="ai-legal-body">{t("privacy.collectAgentBody")}</p>

          <h3 className="ai-legal-subheading">{t("privacy.collectMetaTitle")}</h3>
          <p className="ai-legal-body">{t("privacy.collectMetaBody")}</p>

          <h3 className="ai-legal-subheading">{t("privacy.collectAccessTitle")}</h3>
          <p className="ai-legal-body">{t("privacy.collectAccessBody")}</p>
        </section>

        {/* 3. What we do NOT collect */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.notCollectTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.notCollectBody")}</p>
        </section>

        {/* 4. How we use information */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.useTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.useBody")}</p>
        </section>

        {/* 5. Information sharing */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.shareTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.shareBody")}</p>
        </section>

        {/* 6. Cookies */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.cookieTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.cookieBody")}</p>
        </section>

        {/* 7. Data security */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.securityTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.securityBody")}</p>
        </section>

        {/* 7. Data retention & deletion */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.retentionTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.retentionBody")}</p>
        </section>

        {/* 8. Your rights */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.rightsTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.rightsBody")}</p>
        </section>

        {/* 10. Changes */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.changesTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.changesBody")}</p>
        </section>

        {/* 11. Contact */}
        <section className="ai-legal-section">
          <h2 className="ai-legal-heading">{t("privacy.contactTitle")}</h2>
          <p className="ai-legal-body">{t("privacy.contactBody")}</p>
          <a
            href="https://docs.google.com/forms/d/e/1FAIpQLSexUwLy_n8cW99r_wf7TDCNPS2-4tEov3G9zdmZux96Jc1ffw/viewform"
            target="_blank"
            rel="noopener noreferrer"
            className="ai-legal-contact-link"
          >
            {t("privacy.contactLinkLabel")} ↗
          </a>
        </section>

        {/* Footer */}
        <footer className="ai-legal-footer">
          <Link href="/help" className="ai-legal-footer-link">
            {t("legal.helpLink")}
          </Link>
          <span className="ai-legal-footer-sep">|</span>
          <Link href="/terms" className="ai-legal-footer-link">
            {t("legal.termsLink")}
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
