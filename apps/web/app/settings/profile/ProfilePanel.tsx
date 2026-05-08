"use client";

import { FormEvent, useEffect, useState } from "react";
import { AuthLogoutButton } from "../../_components/AuthLogoutButton";
import { useAuthSessionQuery, useUpdateProfileMutation } from "../../../lib/api/hooks";
import { useTranslation } from "../../../lib/i18n";

function formatDate(iso: string | undefined): string {
  if (!iso) return "\u2014";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("ja-JP", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ProfilePanel() {
  const { t } = useTranslation();

  function verificationLabel(level: string | undefined): string {
    switch (level) {
      case "orb":
        return t("profile.verificationOrb");
      case "dev":
        return t("profile.verificationBypass");
      default:
        // The service only accepts Orb; any other value is a legacy or
        // unexpected session token and is surfaced as "unknown" rather than
        // implying the level is a supported option.
        return level ?? t("profile.verificationUnknown");
    }
  }

  const sessionQuery = useAuthSessionQuery();
  const updateProfile = useUpdateProfileMutation();
  const user = sessionQuery.data?.user;

  const [displayName, setDisplayName] = useState("");
  const [status, setStatus] = useState<"idle" | "success" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    setDisplayName(user?.display_name ?? "");
  }, [user?.display_name, user?.id]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStatus("idle");
    setErrorMessage(null);
    const trimmed = displayName.trim();
    if (trimmed.length > 64) {
      setStatus("error");
      setErrorMessage(t("profile.validationTooLong"));
      return;
    }
    try {
      await updateProfile.mutateAsync({
        display_name: trimmed.length === 0 ? null : trimmed,
      });
      setStatus("success");
    } catch (error) {
      setStatus("error");
      setErrorMessage(error instanceof Error ? error.message : t("profile.updateFailed"));
    }
  };

  if (sessionQuery.isPending) {
    return (
      <div className="settings-container">
        <section className="settings-card">
          <p className="settings-card-desc">{t("profile.loading")}</p>
        </section>
      </div>
    );
  }

  if (!sessionQuery.data?.authenticated || !user) {
    return (
      <div className="settings-container">
        <section className="settings-card">
          <div className="settings-card-header">
            <div className="settings-card-heading">
              <h2 className="settings-card-title">{t("profile.notLoggedInTitle")}</h2>
            </div>
          </div>
          <p className="settings-card-desc">{t("profile.notLoggedInDesc")}</p>
        </section>
      </div>
    );
  }

  return (
    <div className="settings-container">
      {/* Account */}
      <section className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
              <circle cx="12" cy="7" r="4" />
            </svg>
            <h2 className="settings-card-title">{t("profile.accountTitle")}</h2>
          </div>
          <AuthLogoutButton />
        </div>
        <ul className="settings-meta-list">
          <li className="settings-meta-row" data-testid="profile-user-id">
            <span className="settings-meta-label">{t("profile.userId")}</span>
            <span className="settings-meta-value"><code>{user.id}</code></span>
          </li>
          <li className="settings-meta-row" data-testid="profile-verification">
            <span className="settings-meta-label">{t("profile.authMethod")}</span>
            <span className="settings-meta-value">{verificationLabel(user.verification_level)}</span>
          </li>
          <li className="settings-meta-row">
            <span className="settings-meta-label">{t("profile.registeredAt")}</span>
            <span className="settings-meta-value">{formatDate(user.created_at)}</span>
          </li>
        </ul>
      </section>

      {/* Display name */}
      <section className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 20h9" />
              <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" />
            </svg>
            <h2 className="settings-card-title">{t("profile.displayNameTitle")}</h2>
          </div>
        </div>
        <p className="settings-card-desc" style={{ marginBottom: 16 }}>
          {t("profile.displayNameDesc")}
        </p>
        <form onSubmit={handleSubmit} className="settings-form">
          <div className="field">
            <label htmlFor="display-name" className="field-label">
              {t("profile.displayNameLabel")}
            </label>
            <input
              id="display-name"
              type="text"
              className="input"
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              maxLength={64}
              placeholder={t("profile.displayNamePlaceholder")}
              data-testid="profile-display-name-input"
            />
          </div>
          <div className="settings-form-actions">
            <button
              type="submit"
              className="btn primary"
              disabled={updateProfile.isPending}
              data-testid="profile-save"
            >
              {updateProfile.isPending ? t("profile.saving") : t("profile.saveBtn")}
            </button>
            {status === "success" && (
              <span className="badge ok" role="status">
                {t("profile.saved")}
              </span>
            )}
            {status === "error" && (
              <span className="badge" role="alert" data-testid="profile-error">
                {errorMessage ?? t("profile.error")}
              </span>
            )}
          </div>
        </form>
      </section>

      {/* Session */}
      <section className="settings-card">
        <div className="settings-card-header">
          <div className="settings-card-heading">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <h2 className="settings-card-title">{t("profile.sessionTitle")}</h2>
          </div>
        </div>
        <p className="settings-card-desc">{t("profile.sessionDesc")}</p>
      </section>
    </div>
  );
}
