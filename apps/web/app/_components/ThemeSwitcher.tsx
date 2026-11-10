"use client";

// Auto / Light / Dark under the sidebar's profile row (docs/35 §2).

import { useTranslation } from "../../lib/i18n";
import { useTheme, type ThemeChoice } from "../../lib/ui/theme";

const CHOICES: { value: ThemeChoice; key: string }[] = [
  { value: "auto", key: "topbar.themeAuto" },
  { value: "light", key: "topbar.themeLight" },
  { value: "dark", key: "topbar.themeDark" },
];

export function ThemeSwitcher() {
  const { t } = useTranslation();
  const [choice, setChoice] = useTheme();
  return (
    <div className="x-theme" role="radiogroup" aria-label={t("topbar.theme")}>
      <span className="x-theme-label">{t("topbar.theme")}</span>
      {CHOICES.map((c) => (
        <button
          key={c.value}
          type="button"
          role="radio"
          aria-checked={choice === c.value}
          className={"x-theme-opt" + (choice === c.value ? " on" : "")}
          onClick={() => setChoice(c.value)}
        >
          {t(c.key)}
        </button>
      ))}
    </div>
  );
}
