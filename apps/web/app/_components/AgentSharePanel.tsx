"use client";

// 紹介する (docs/36 ①): turn the agent's public intro page on or off, and
// while it is on, hand out the link with a one-line introduction.

import { useEffect, useState } from "react";
import { shareLink, shareText } from "../../lib/agents/share";
import { useAuthSessionQuery, useUpdateAgentMutation } from "../../lib/api/hooks";
import type { Agent } from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";

export function AgentSharePanel({ agent }: { agent: Agent }) {
  const { t } = useTranslation();
  const updateAgent = useUpdateAgentMutation();
  const session = useAuthSessionQuery();
  const [note, setNote] = useState<{ tone: "ok" | "error"; text: string } | null>(null);
  const [origin, setOrigin] = useState("");
  useEffect(() => setOrigin(window.location.origin), []);

  const on = agent.share_enabled === true;
  const link = origin && agent.aid ? shareLink(origin, agent.aid) : "";
  const text = link
    ? shareText(t, { agent: agent.label, owner: session.data?.user?.display_name, link })
    : "";

  const toggle = async () => {
    setNote(null);
    try {
      await updateAgent.mutateAsync({ id: agent.id, body: { share_enabled: !on } });
      setNote({ tone: "ok", text: t(on ? "share.off" : "share.on") });
    } catch {
      setNote({ tone: "error", text: t("share.failed") });
    }
  };

  const copy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setNote({ tone: "ok", text: t("share.copied") });
    } catch {
      setNote({ tone: "error", text: t("share.copyFailed") });
    }
  };

  // The share sheet (LINE, X, mail…) where there is one; copying otherwise.
  const share = async () => {
    if (typeof navigator.share === "function") {
      try {
        await navigator.share({ text });
        return;
      } catch (error) {
        if (error instanceof DOMException && error.name === "AbortError") return;
      }
    }
    await copy(text);
  };

  return (
    <div className="sh-panel" data-testid="agent-share-panel">
      <button
        type="button"
        role="switch"
        aria-checked={on}
        className="sh-switch"
        onClick={() => void toggle()}
        disabled={updateAgent.isPending}
        data-testid="agent-share-switch"
      >
        <span>{t("share.switchLabel")}</span>
        <span className="sh-track" aria-hidden="true" />
      </button>
      <p className="sh-desc">{t("share.switchDesc")}</p>

      {on && text ? (
        <>
          <label className="sh-field">
            <span>{t("share.textLabel")}</span>
            <textarea
              className="sh-text"
              readOnly
              rows={4}
              value={text}
              onFocus={(event) => event.currentTarget.select()}
              data-testid="agent-share-text"
            />
          </label>
          <div className="dm-btns">
            <button type="button" className="dm-btn accent" onClick={() => void share()}>
              {t("share.share")}
            </button>
            <button type="button" className="dm-btn" onClick={() => void copy(link)}>
              {t("share.copyLink")}
            </button>
          </div>
        </>
      ) : null}

      <p className={"sh-note" + (note?.tone === "error" ? " error" : "")} role="status" aria-live="polite">
        {note?.text ?? ""}
      </p>
    </div>
  );
}
