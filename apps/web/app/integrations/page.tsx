"use client";

import { AppShell } from "../_components/AppShell";
import { IntegrationsPanel } from "./IntegrationsPanel";
import { useTranslation } from "../../lib/i18n";

export default function IntegrationsPage() {
  const { t } = useTranslation();
  return (
    <AppShell title={t("integrations.title")} activePath="/integrations">
      <IntegrationsPanel />
    </AppShell>
  );
}
