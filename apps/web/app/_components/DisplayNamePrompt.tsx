"use client";

import { FormEvent, useEffect, useState } from "react";
import { useAuthSessionQuery, useUpdateProfileMutation } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";

// On first login the user has no display_name set. We show a
// non-dismissable overlay that asks for one before the inbox is
// usable, so recipients see something friendlier than a UUID prefix.
export function DisplayNamePrompt() {
  const { t } = useTranslation();
  const sessionQuery = useAuthSessionQuery();
  const updateProfile = useUpdateProfileMutation();

  const user = sessionQuery.data?.user;
  const authenticated = sessionQuery.data?.authenticated;
  const needsName = Boolean(authenticated && user && !user.display_name);

  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!needsName) {
      setValue("");
      setError(null);
    }
  }, [needsName]);

  if (!needsName) return null;

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = value.trim();
    if (trimmed.length === 0) {
      setError(t("onboarding.validationEmpty"));
      return;
    }
    if (trimmed.length > 64) {
      setError(t("onboarding.validationTooLong"));
      return;
    }
    setError(null);
    try {
      await updateProfile.mutateAsync({ display_name: trimmed });
    } catch (err) {
      setError(err instanceof Error ? err.message : t("onboarding.saveFailed"));
    }
  };

  return (
    <div className="display-name-overlay" role="dialog" aria-modal="true">
      <div className="display-name-card">
        <h2 className="display-name-title">{t("onboarding.welcomeTitle")}</h2>
        <p className="display-name-lead">
          {t("onboarding.welcomeDesc")}
        </p>
        <form className="display-name-form" onSubmit={handleSubmit}>
          <label htmlFor="onboarding-display-name" className="field-label">
            {t("onboarding.displayNameLabel")}
          </label>
          <input
            id="onboarding-display-name"
            className="input"
            type="text"
            value={value}
            maxLength={64}
            autoFocus
            onChange={(event) => setValue(event.target.value)}
            placeholder={t("onboarding.displayNamePlaceholder")}
          />
          {error ? <p className="display-name-error">{error}</p> : null}
          <div className="form-actions" style={{ justifyContent: "flex-end" }}>
            <button
              type="submit"
              className="btn primary"
              disabled={updateProfile.isPending}
            >
              {updateProfile.isPending ? t("onboarding.saving") : t("onboarding.startBtn")}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
