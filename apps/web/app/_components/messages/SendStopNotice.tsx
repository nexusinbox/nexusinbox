"use client";

// Shown above the send button when a send stopped because the recipient's
// device list does not hold (docs/40 §12.5, mock docs/40_stage2_mock.html).
// What was typed stays; only a changed root offers to send anyway, after a
// second confirmation.

import { useState } from "react";
import type { SendStop } from "../../../lib/crypto/device-wraps";
import { useTranslation } from "../../../lib/i18n";

export function SendStopNotice({
  stop,
  name,
  onClose,
  onAccept,
}: {
  stop: SendStop;
  /** The recipient as the person knows them. */
  name?: string | null;
  onClose: () => void;
  /** Send anyway, remembering the new root (only for a changed root). */
  onAccept?: (root: string) => void;
}) {
  const { t } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const who = name?.trim() || t("sendStop.someone");
  const danger = stop.reason !== "no_device";

  let title: string;
  let body: string;
  if (stop.reason === "root_changed") {
    title = confirming ? t("sendStop.confirmTitle") : t("sendStop.changedTitle", { name: who });
    body = confirming ? t("sendStop.confirmBody") : t("sendStop.changedBody");
  } else if (stop.reason === "no_device") {
    title = t("sendStop.noDeviceTitle", { name: who });
    body = t("sendStop.noDeviceBody");
  } else if (stop.reason === "no_list") {
    // docs/40 §15.2: wait until they make a list (they do when they open
    // NexusInbox). What was typed stays.
    title = t("sendStop.noListTitle", { name: who });
    body = t("sendStop.noListBody", { name: who });
  } else {
    title = t("sendStop.blockedTitle", { name: who });
    body = `${t(`sendStop.${stop.reason}`)}${t("sendStop.blockedTail")}`;
  }

  return (
    <div
      role="alert"
      data-testid="send-stop"
      data-reason={stop.reason}
      style={{
        margin: "0 0 10px",
        padding: "12px 14px",
        borderRadius: 14,
        border: `1px solid ${danger ? "var(--danger)" : "var(--warn)"}`,
        background: danger ? "var(--danger-soft)" : "var(--warn-soft)",
        color: "var(--text)",
        textAlign: "left",
      }}
    >
      <p style={{ margin: 0, fontWeight: 700 }}>{title}</p>
      <p className="item-sub" style={{ margin: "2px 0 0" }}>
        {body}
      </p>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
        {stop.reason === "root_changed" && onAccept && stop.root ? (
          confirming ? (
            <>
              <button type="button" className="btn primary" onClick={() => setConfirming(false)}>
                {t("sendStop.cancel")}
              </button>
              <button
                type="button"
                className="btn"
                style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                onClick={() => onAccept(stop.root as string)}
                data-testid="send-stop-accept"
              >
                {t("sendStop.confirmSend")}
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn primary" onClick={onClose}>
                {t("sendStop.cancel")}
              </button>
              <button
                type="button"
                className="btn"
                style={{ borderColor: "transparent", color: "var(--text-muted)" }}
                onClick={() => setConfirming(true)}
                data-testid="send-stop-proceed"
              >
                {t("sendStop.changedProceed")}
              </button>
            </>
          )
        ) : (
          <button type="button" className="btn" onClick={onClose}>
            {t("sendStop.close")}
          </button>
        )}
      </div>
    </div>
  );
}
