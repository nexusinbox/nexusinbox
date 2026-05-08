"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import React from "react";

import en from "./locales/en.json";
import ja from "./locales/ja.json";

// Supported locales
export type Locale = "en" | "ja";

const translations: Record<Locale, Record<string, unknown>> = { en, ja };

const STORAGE_KEY = "nexusinbox-locale";

// ----- helpers -----

/**
 * Resolve a dot-separated key from a nested object.
 * e.g. resolve("inbox.title", { inbox: { title: "Inbox" } }) => "Inbox"
 */
function resolve(key: string, obj: Record<string, unknown>): string | undefined {
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
function interpolate(
  template: string,
  vars?: Record<string, string | number>,
): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k) =>
    vars[k] !== undefined ? String(vars[k]) : `{${k}}`,
  );
}

// ----- context -----

interface I18nContextValue {
  locale: Locale;
  setLocale: (l: Locale) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue>({
  locale: "en",
  setLocale: () => {},
  t: (key) => key,
});

// ----- provider -----

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>("en");

  // Hydrate from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) as Locale | null;
      if (stored && translations[stored]) {
        setLocaleState(stored);
      }
    } catch {
      // SSR or localStorage unavailable
    }
  }, []);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // ignore
    }
  }, []);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>): string => {
      const val = resolve(key, translations[locale] as Record<string, unknown>);
      if (val !== undefined) return interpolate(val, vars);
      // Fallback to English
      const fallback = resolve(key, translations.en as Record<string, unknown>);
      if (fallback !== undefined) return interpolate(fallback, vars);
      // Return the key itself as last resort
      return key;
    },
    [locale],
  );

  return React.createElement(
    I18nContext.Provider,
    { value: { locale, setLocale, t } },
    children,
  );
}

// ----- hook -----

export function useTranslation() {
  return useContext(I18nContext);
}
