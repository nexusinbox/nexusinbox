"use client";

// Pieces shared by the help page and the developer reference.

import { Fragment, type ReactNode } from "react";
import Link from "next/link";
import { useTranslation, type Locale } from "../../lib/i18n";

// Render translation strings that may contain `**bold**` markdown spans.
// We split on `**...**` (non-greedy) so even-indexed segments are plain
// text and odd-indexed segments become <strong>. Backticks and other
// markdown markers pass through untouched — keeping the parser tiny
// because the help copy only ever uses bold for emphasis today.
export function RichText({ text }: { text: string }) {
  const parts = text.split(/\*\*(.+?)\*\*/g);
  return (
    <>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <strong key={i}>{part}</strong>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  );
}

// Lightweight public shell used when /help is visited without a session.
// Mirrors AppShell's overall look (top bar + centred main + footer) but
// drops the sidebar, the WebSocket subscriber, and the session-redirect
// monitor — none of which apply to a logged-out reader. Logged-in users
// keep the full AppShell so they can navigate back to their inbox.
export function PublicHelpShell({ children }: { children: ReactNode }) {
  const { locale, setLocale, t } = useTranslation();
  const toggleLocale = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };
  return (
    <div className="public-help-root">
      <header className="public-help-header">
        <Link href="/concept" className="public-help-brand" aria-label="NexusInbox">
          <span className="public-help-brand-mark">NEXUS</span>INBOX
        </Link>
        <div className="public-help-header-right">
          <button
            type="button"
            onClick={toggleLocale}
            className="public-help-lang"
            aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
          >
            {locale === "en" ? "JA" : "EN"}
          </button>
          <Link href="/login?next=/help" className="public-help-signin">
            {t("help.signInCta")}
          </Link>
        </div>
      </header>
      <main className="public-help-main">{children}</main>
      <footer className="public-help-footer">
        <Link href="/concept">{t("legal.conceptLink")}</Link>
        <span aria-hidden="true">·</span>
        <Link href="/privacy">{t("legal.privacyLink")}</Link>
        <span aria-hidden="true">·</span>
        <Link href="/terms">{t("legal.termsLink")}</Link>
      </footer>
    </div>
  );
}

// Shared chevron used inside every accordion summary.
export function AccordionChevron() {
  return (
    <div className="help-accordion-chevron">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="6 9 12 15 18 9"></polyline>
      </svg>
    </div>
  );
}
