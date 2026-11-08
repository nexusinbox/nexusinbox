"use client";

// AI apps connected to an agent over OAuth (docs/33 §10), with a way to
// disconnect each one. Shown under the agent's 詳細.

import { useMemo, useState } from "react";
import { useDeleteOAuthGrantMutation, useOAuthGrantsQuery } from "../../lib/api/hooks";
import { formatListTimestamp } from "../../lib/format/messageTime";
import { useTranslation } from "../../lib/i18n";

export function ConnectedAIs({ aid }: { aid: string }) {
  const { t, locale } = useTranslation();
  const grantsQuery = useOAuthGrantsQuery();
  const disconnect = useDeleteOAuthGrantMutation();
  const [status, setStatus] = useState("");
  const grants = useMemo(
    () => (grantsQuery.data?.grants ?? []).filter((g) => g.aid === aid),
    [grantsQuery.data, aid],
  );

  const scopeText = (scope: string[]) =>
    scope.includes("inbox.draft") ? t("connectedAIs.readAndDraft") : t("connectedAIs.readOnly");

  return (
    <div className="panel" style={{ marginTop: 10 }} data-testid="connected-ais">
      <p className="item-title">{t("connectedAIs.title")}</p>
      {grants.length === 0 ? (
        <p className="item-sub">{t("connectedAIs.empty")}</p>
      ) : (
        grants.map((g) => (
          <div
            key={g.id}
            className="row"
            style={{
              justifyContent: "space-between",
              gap: 8,
              borderTop: "1px solid var(--line)",
              padding: "8px 0",
            }}
          >
            <div style={{ minWidth: 0 }}>
              <strong>{g.client_name}</strong>
              <p className="item-sub" style={{ margin: 0 }}>
                {scopeText(g.scope)} ·{" "}
                {t("connectedAIs.allowed", { when: formatListTimestamp(g.created_at, { locale }) })} ·{" "}
                {t("connectedAIs.lastUsed", { when: formatListTimestamp(g.last_used_at, { locale }) })}
              </p>
            </div>
            <button
              className="btn"
              type="button"
              style={{ color: "#b3261e", borderColor: "#b3261e" }}
              disabled={disconnect.isPending}
              onClick={async () => {
                setStatus("");
                try {
                  await disconnect.mutateAsync(g.id);
                  setStatus(t("connectedAIs.disconnected", { app: g.client_name }));
                } catch {
                  setStatus(t("connectedAIs.disconnectFailed"));
                }
              }}
            >
              {t("connectedAIs.disconnect")}
            </button>
          </div>
        ))
      )}
      <p className="item-sub" style={{ marginTop: 6 }}>
        {t("connectedAIs.note")}
      </p>
      {status ? <p className="item-sub">{status}</p> : null}
    </div>
  );
}
