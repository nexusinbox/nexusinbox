"use client";

import { useTranslation, type Locale } from "../../lib/i18n";

/**
 * Compact language toggle button for the topbar.
 * Clicking cycles between English and Japanese.
 */
export function LanguageSwitcher() {
  const { locale, setLocale } = useTranslation();

  const toggle = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };

  return (
    <button
      className="icon-btn"
      type="button"
      onClick={toggle}
      aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
      title={locale === "en" ? "日本語" : "English"}
      style={{ fontSize: 13, fontWeight: 600, minWidth: 32, letterSpacing: 0 }}
    >
      {locale === "en" ? "JP" : "EN"}
    </button>
  );
}
