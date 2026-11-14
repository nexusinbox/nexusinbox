"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { AppShell } from "../../../_components/AppShell";
import { createAgentWithLocalKeys } from "../../../../lib/agents/create-agent";
import { useCreateAgentMutation } from "../../../../lib/api/hooks";
import { useTranslation } from "../../../../lib/i18n";

type Banner = { tone: "info" | "error" | "success"; text: string } | null;

export default function CreateAgentPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const createAgent = useCreateAgentMutation();
  const [label, setLabel] = useState<string>("");
  const [banner, setBanner] = useState<Banner>(null);

  const handleCreate = async () => {
    const trimmed = label.trim();
    if (!trimmed) {
      setBanner({ tone: "error", text: t("agentCreate.bannerEmpty") });
      return;
    }
    setBanner({ tone: "info", text: t("agentCreate.bannerCreating") });
    try {
      await createAgentWithLocalKeys(trimmed, createAgent.mutateAsync);
      setBanner({ tone: "success", text: t("agentCreate.bannerCreated") });
      setLabel("");
      // Give the user a beat to see the success banner before navigating.
      setTimeout(() => {
        router.push("/settings/agents");
      }, 600);
    } catch {
      setBanner({
        tone: "error",
        text: t("agentCreate.bannerFailed"),
      });
    }
  };

  return (
    <AppShell
      title={t("agentCreate.title")}
      activePath="/settings/agents/new"
      rightAction={
        <button
          className="btn"
          type="button"
          onClick={() => router.push("/settings/agents")}
        >
          {t("agentCreate.backBtn")}
        </button>
      }
    >
      <section style={{ padding: 24, maxWidth: 640 }}>
        <div className="panel">
          <p className="item-title">{t("agentCreate.nameTitle")}</p>
          <p className="item-sub" style={{ marginTop: 4 }}>
            {t("agentCreate.nameDesc")}
          </p>
          <input
            className="input"
            value={label}
            onChange={(event) => setLabel(event.target.value)}
            placeholder={t("agentCreate.namePlaceholder")}
            style={{ marginTop: 10 }}
            autoFocus
          />
          <button
            className="btn primary"
            type="button"
            onClick={handleCreate}
            disabled={createAgent.isPending}
            style={{ marginTop: 14, width: "100%", minHeight: 44 }}
          >
            {createAgent.isPending ? t("agentCreate.creating") : t("agentCreate.createBtn")}
          </button>
          {banner ? (
            <p className="item-sub" style={{ marginTop: 14 }}>
              {banner.text}
            </p>
          ) : null}
        </div>
        <p className="item-sub" style={{ margin: "12px 4px 0" }}>
          {t("agentCreate.keysNote")}
        </p>
      </section>
    </AppShell>
  );
}
