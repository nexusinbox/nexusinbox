"use client";

// Shown above the send button when a send stopped because the recipient's
// device list does not hold (docs/40 §12.5, mock docs/40_stage2_mock.html).
// What was typed stays; only a changed root offers to send anyway, after a
// second confirmation.

import { useEffect, useState } from "react";
import { confirmationNumber } from "@nexusinbox/core/confirmation";
import { contactForAid } from "../../../lib/agents/peer-pins";
import type { SendStop } from "../../../lib/crypto/device-wraps";
import { useTranslation } from "../../../lib/i18n";

export function SendStopNotice({
  stop,
  name,
  ownRoot,
  onClose,
  onAccept,
}: {
  stop: SendStop;
  /** The sending agent's root, for the new confirmation number (docs/40 §16.2). */
  ownRoot?: string | null;
  /** The recipient as the person knows them. */
  name?: string | null;
  onClose: () => void;
  /** Send anyway, remembering the new root (only for a changed root). */
  onAccept?: (root: string) => void;
}) {
  const { t, locale } = useTranslation();
  const [confirming, setConfirming] = useState(false);
  const who = name?.trim() || t("sendStop.someone");
  // Checked with the confirmation number before: say so, and show the new
  // number to read aloud (docs/40 §16.2).
  const verified = stop.reason === "root_changed" ? (contactForAid(stop.aid)?.verified ?? null) : null;
  const [newNumber, setNewNumber] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    if (verified && ownRoot && stop.root) {
      void confirmationNumber(ownRoot, stop.root).then((n) => {
        if (!cancelled) setNewNumber(n);
      });
    }
    return () => {
      cancelled = true;
    };
  }, [verified?.root, ownRoot, stop.root]);
  const danger = stop.reason !== "no_device";

  let title: string;
  let body: string;
  if (stop.reason === "root_changed") {
    title = confirming ? t("sendStop.confirmTitle") : t("sendStop.changedTitle", { name: who });
    body = confirming ? t("sendStop.confirmBody") : t("sendStop.changedBody");
    if (verified && !confirming) {
      const date = new Date(verified.at).toLocaleDateString(locale === "ja" ? "ja-JP" : "en-US", {
        month: "numeric",
        day: "numeric",
      });
      body = `${body} ${t("confirm.changedVerified", { date })}`;
    }
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
      {verified && newNumber && !confirming ? (
        <div data-testid="send-stop-new-number" style={{ marginTop: 8 }}>
          <p style={{ margin: 0, fontWeight: 700 }}>{t("confirm.changedNewNumber")}</p>
          <p
            style={{
              margin: "6px 0",
              padding: "10px 12px",
              borderRadius: 12,
              background: "var(--primary-soft)",
              textAlign: "center",
              font: "700 18px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace",
              letterSpacing: 1,
            }}
          >
            {newNumber}
          </p>
          <p className="item-sub" style={{ margin: 0 }}>
            {t("confirm.changedNumberNote")}
          </p>
        </div>
      ) : null}
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
                // Checked before: the number shown above is the confirmation.
                onClick={() => (verified ? onAccept(stop.root as string) : setConfirming(true))}
                data-testid="send-stop-proceed"
              >
                {verified ? t("confirm.changedProceedVerified") : t("sendStop.changedProceed")}
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
