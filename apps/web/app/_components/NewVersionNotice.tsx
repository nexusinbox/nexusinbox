"use client";

// Tell a tab that has stayed open across a deploy that a new version is
// out (docs/31 §5.5): its old code keeps running until a reload, and links
// can lead to screens that have since changed. Checks on every page,
// whenever the tab comes back into view, and every five minutes. It never
// reloads by itself: a half-written message would be lost.

import { useEffect, useState } from "react";
import { useTranslation } from "../../lib/i18n";

const LOADED_VERSION = process.env.NEXT_PUBLIC_APP_VERSION ?? "";
const CHECK_EVERY_MS = 5 * 60_000;

export function NewVersionNotice() {
  const { t } = useTranslation();
  const [outdated, setOutdated] = useState(false);

  useEffect(() => {
    if (!LOADED_VERSION || outdated) return;
    let stopped = false;
    const check = async () => {
      try {
        const response = await fetch("/app-version", { cache: "no-store" });
        if (!response.ok) return;
        const { version } = (await response.json()) as { version?: unknown };
        if (!stopped && typeof version === "string" && version && version !== LOADED_VERSION) {
          setOutdated(true);
        }
      } catch {
        // Offline or signed out: ask again later.
      }
    };
    const onVisible = () => {
      if (document.visibilityState === "visible") void check();
    };
    void check();
    document.addEventListener("visibilitychange", onVisible);
    const timer = setInterval(() => void check(), CHECK_EVERY_MS);
    return () => {
      stopped = true;
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(timer);
    };
  }, [outdated]);

  if (!outdated) return null;
  return (
    <div
      role="status"
      data-testid="new-version-notice"
      style={{
        position: "fixed",
        left: "50%",
        bottom: 16,
        transform: "translateX(-50%)",
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        gap: 12,
        flexWrap: "wrap",
        maxWidth: "calc(100vw - 32px)",
        padding: "10px 14px",
        borderRadius: 12,
        background: "var(--text)",
        color: "var(--bg)",
        boxShadow: "var(--shadow-md)",
        fontSize: "var(--fs-sm)",
      }}
    >
      <span>{t("appVersion.notice")}</span>
      <button
        type="button"
        className="btn"
        onClick={() => window.location.reload()}
        data-testid="new-version-reload"
      >
        {t("appVersion.reload")}
      </button>
    </div>
  );
}
