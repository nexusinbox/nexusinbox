"use client";

// Shown when the API asks for a recent World ID sign-in
// (`reauthentication_required`, audit run-6, mock docs/33_reauth_mock.html):
// handing out read access to messages, or what cannot be undone.
// Signing in again comes back to this page.

import { ApiError } from "../../lib/api/client";
import { useTranslation } from "../../lib/i18n";
import { reauthLoginPath } from "../../lib/url/next-path";

/** Whether an error is the API asking for a recent sign-in. */
export function needsReauth(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403;
}

export function ReauthNotice({ reason }: { reason: "readAccess" | "readAccessReturn" | "irreversible" }) {
  const { t } = useTranslation();
  const back = typeof window === "undefined" ? "/" : window.location.pathname + window.location.search;
  return (
    <div
      role="alert"
      data-testid="reauth-notice"
      style={{ marginTop: 10, borderRadius: 12, background: "var(--warn-soft)", padding: "10px 12px" }}
    >
      <p style={{ margin: 0, fontWeight: 700 }}>{t("reauth.title")}</p>
      <p className="item-sub" style={{ margin: "2px 0 0" }}>
        {t(`reauth.${reason}`)}
      </p>
      <a className="btn primary" href={reauthLoginPath(back)} style={{ marginTop: 8, display: "inline-block" }}>
        {t("reauth.button")}
      </a>
    </div>
  );
}
