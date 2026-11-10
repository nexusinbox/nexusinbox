"use client";

// Consent page for cloud AIs (docs/33 §10). An AI app sends the person
// here; they see which app wants which agent and what it may do (read and
// draft, never send), then allow or decline. The API checks the request
// again on both steps and returns where the browser goes next.

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { defaultApiClient } from "../../../lib/api/client";
import type { OAuthAuthorizeInfo } from "../../../lib/api/types";
import { useTranslation } from "../../../lib/i18n";

const AUTHORIZE_PARAMS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "state",
  "code_challenge",
  "code_challenge_method",
  "scope",
  "resource",
] as const;

const card: React.CSSProperties = {
  maxWidth: 480,
  margin: "48px auto",
  background: "var(--surface)",
  border: "1px solid var(--line)",
  borderRadius: 16,
  padding: "22px 24px",
};
const muted: React.CSSProperties = { color: "var(--text-muted)", fontSize: 13 };
const permRow: React.CSSProperties = {
  display: "flex",
  gap: 8,
  padding: "7px 0",
  borderTop: "1px solid var(--line)",
  fontSize: 14,
};

function Consent() {
  const { t } = useTranslation();
  const search = useSearchParams();
  const params = useMemo(() => {
    const out: Record<string, string> = {};
    for (const key of AUTHORIZE_PARAMS) {
      const value = search.get(key);
      if (value !== null) out[key] = value;
    }
    return out;
  }, [search]);
  const [info, setInfo] = useState<OAuthAuthorizeInfo | null>(null);
  const [error, setError] = useState<string>("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    defaultApiClient
      .oauthAuthorizeInfo(new URLSearchParams(params).toString())
      .then((data) => {
        if (!cancelled) setInfo(data);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [params]);

  const decide = async (approve: boolean) => {
    setBusy(true);
    try {
      const { redirect_to } = await defaultApiClient.oauthAuthorizeDecide(params, approve);
      window.location.assign(redirect_to);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  };

  if (error) {
    return (
      <div style={card} data-testid="oauth-error">
        <h1 style={{ fontSize: 18, margin: "0 0 8px" }}>{t("oauthConsent.errorTitle")}</h1>
        <p style={{ margin: "0 0 8px", fontSize: 14 }}>{t("oauthConsent.errorBody")}</p>
        <p style={muted}>{error}</p>
      </div>
    );
  }
  if (!info) {
    return (
      <div style={card}>
        <p style={muted}>{t("oauthConsent.loading")}</p>
      </div>
    );
  }

  const canDraft = info.scope.includes("inbox.draft");
  const agent = info.device_label
    ? t("oauthConsent.agentOnDevice", { agent: info.agent_label, device: info.device_label })
    : info.agent_label;

  return (
    <div style={card} data-testid="oauth-consent">
      <h1 style={{ fontSize: 19, margin: "0 0 6px" }}>
        {t("oauthConsent.title", { app: info.client_name, agent: info.agent_label })}
      </h1>
      <p style={{ ...muted, margin: "0 0 10px" }}>
        {t("oauthConsent.target", { agent })} ·{" "}
        {info.client_kind === "metadata_document"
          ? t("oauthConsent.verifiedApp", { host: new URL(info.client_id).host })
          : t("oauthConsent.selfNamedApp")}{" "}
        · {t("oauthConsent.returnsTo", { host: info.redirect_host })}
      </p>
      <div>
        <div style={{ ...permRow, borderTop: 0 }}>
          <span style={{ color: "var(--ok)", fontWeight: 700 }}>✓</span>
          {t("oauthConsent.canRead")}
        </div>
        {canDraft ? (
          <div style={permRow}>
            <span style={{ color: "var(--ok)", fontWeight: 700 }}>✓</span>
            {t("oauthConsent.canDraft")}
          </div>
        ) : null}
        <div style={permRow}>
          <span style={{ color: "var(--danger)", fontWeight: 700 }}>✕</span>
          {t("oauthConsent.cannotSend")}
        </div>
        <div style={permRow}>
          <span style={{ color: "var(--danger)", fontWeight: 700 }}>✕</span>
          {t("oauthConsent.cannotOther")}
        </div>
      </div>
      <p
        style={{
          background: "var(--warn-soft)",
          color: "var(--warn)",
          borderRadius: 10,
          padding: "8px 12px",
          fontSize: 13,
          margin: "10px 0",
        }}
      >
        {t("oauthConsent.providerSees", { app: info.client_name })}
      </p>
      <p style={{ ...muted, margin: 0 }}>{t("oauthConsent.revokeLater")}</p>
      <div className="row" style={{ gap: 8, marginTop: 14 }}>
        <button className="btn primary" type="button" disabled={busy} onClick={() => decide(true)}>
          {t("oauthConsent.allow")}
        </button>
        <button className="btn" type="button" disabled={busy} onClick={() => decide(false)}>
          {t("oauthConsent.deny")}
        </button>
      </div>
    </div>
  );
}

export default function OAuthAuthorizePage() {
  return (
    <main style={{ padding: "0 16px" }}>
      <Suspense fallback={null}>
        <Consent />
      </Suspense>
    </main>
  );
}
