"use client";

// Light / dark (docs/35 §2). The choice lives in this browser only:
// "auto" follows the device, "light" / "dark" pin it. The resolved theme
// is written to <html data-theme>, which swaps the colour tokens in
// globals.css. theme-boot.ts sets it before first paint.

import { useCallback, useEffect, useState } from "react";
import { THEME_STORAGE_KEY } from "./theme-boot";

export type ThemeChoice = "auto" | "light" | "dark";

function readChoice(): ThemeChoice {
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    return raw === "light" || raw === "dark" ? raw : "auto";
  } catch {
    return "auto";
  }
}

function applyChoice(choice: ThemeChoice) {
  const dark =
    choice === "dark" ||
    (choice === "auto" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function useTheme(): [ThemeChoice, (next: ThemeChoice) => void] {
  // null until the stored choice is read, so the boot script's theme is
  // not overwritten on the first render.
  const [choice, setChoice] = useState<ThemeChoice | null>(null);

  useEffect(() => {
    setChoice(readChoice());
  }, []);

  useEffect(() => {
    if (choice === null) return;
    applyChoice(choice);
    if (choice !== "auto") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyChoice("auto");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [choice]);

  const update = useCallback((next: ThemeChoice) => {
    try {
      if (next === "auto") window.localStorage.removeItem(THEME_STORAGE_KEY);
      else window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Storage blocked: the choice still applies until reload.
    }
    setChoice(next);
  }, []);

  return [choice ?? "auto", update];
}
