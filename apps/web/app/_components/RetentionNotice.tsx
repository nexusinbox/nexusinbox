"use client";

import { useEffect, useState } from "react";
import { useTranslation } from "../../lib/i18n";

const DISMISSED_KEY = "nexusinbox.retentionNotice.dismissed.v1";

/**
 * Tells the person that messages leave the server 90 days after they are
 * sent (docs/28 §4). Closing it is remembered in this browser only.
 */
export function RetentionNotice() {
  const { t } = useTranslation();
  // Hidden until storage has been read, so a dismissed notice never flashes.
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      setVisible(window.localStorage.getItem(DISMISSED_KEY) !== "1");
    } catch {
      setVisible(true);
    }
  }, []);

  if (!visible) return null;

  const dismiss = () => {
    setVisible(false);
    try {
      window.localStorage.setItem(DISMISSED_KEY, "1");
    } catch {
      // Storage unavailable: it simply shows again next time.
    }
  };

  return (
    <div
      role="note"
      data-testid="retention-notice"
      style={{
        display: "flex",
        gap: 8,
        alignItems: "flex-start",
        padding: "6px 10px",
        fontSize: 11,
        lineHeight: 1.5,
        color: "#5f6368",
        background: "rgba(251,188,4,0.12)",
        borderBottom: "1px solid rgba(60,64,67,0.12)",
      }}
    >
      <span style={{ flex: 1 }}>{t("inbox.retentionNotice")}</span>
      <button
        type="button"
        onClick={dismiss}
        aria-label={t("inbox.retentionNoticeDismiss")}
        style={{
          border: "none",
          background: "transparent",
          cursor: "pointer",
          color: "#5f6368",
          fontSize: 14,
          lineHeight: 1,
          padding: 0,
        }}
      >
        ×
      </button>
    </div>
  );
}
