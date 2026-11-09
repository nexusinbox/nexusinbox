// Locale lookup without React, so server components (e.g. page metadata)
// can read the same locale files as the client `useTranslation()`.

import en from "./locales/en.json";
import ja from "./locales/ja.json";

export type Locale = "en" | "ja";

export const translations: Record<Locale, Record<string, unknown>> = { en, ja };

/**
 * Resolve a dot-separated key from a nested object.
 * e.g. resolve("inbox.title", { inbox: { title: "Inbox" } }) => "Inbox"
 */
export function resolve(key: string, obj: Record<string, unknown>): string | undefined {
  const parts = key.split(".");
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return typeof cur === "string" ? cur : undefined;
}

/**
 * Interpolate {variable} placeholders.
 * e.g. interpolate("Hello {name}", { name: "Alice" }) => "Hello Alice"
 */
export function interpolate(
  template: string,
  vars?: Record<string, string | number>,
): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k) =>
    vars[k] !== undefined ? String(vars[k]) : `{${k}}`,
  );
}

/** `t` for one locale: the locale's string, else English, else the key. */
export function translate(
  locale: Locale,
  key: string,
  vars?: Record<string, string | number>,
): string {
  const val = resolve(key, translations[locale]);
  if (val !== undefined) return interpolate(val, vars);
  const fallback = resolve(key, translations.en);
  if (fallback !== undefined) return interpolate(fallback, vars);
  return key;
}
