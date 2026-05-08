"use client";

import { AppShell } from "../../_components/AppShell";
import { ProfilePanel } from "./ProfilePanel";
import { useTranslation } from "../../../lib/i18n";

export default function ProfilePage() {
  const { t } = useTranslation();
  return (
    <AppShell title={t("profile.title")} activePath="/settings/agents">
      <ProfilePanel />
    </AppShell>
  );
}
