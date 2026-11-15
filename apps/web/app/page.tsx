"use client";

// ホーム (docs/41 §6): what needs the person, what the AI did, and whether
// the auto-replies run. The conversations are on /conversations; an old link
// to / that names a conversation is sent there (next.config.ts).

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "./_components/AppShell";
import { InboxAgentBar } from "./_components/InboxAgentBar";
import { DeviceUpkeep } from "./_components/home/DeviceUpkeep";
import { HomeActivity } from "./_components/home/HomeActivity";
import { HomeAttention } from "./_components/home/HomeAttention";
import { HomeStatus } from "./_components/home/HomeStatus";
import { useAgentsQuery } from "../lib/api/hooks";
import { agentOfItem, narrowAttention } from "../lib/home/attention";
import { useAttention, type Attention } from "../lib/home/use-attention";
import { useTranslation } from "../lib/i18n";

export default function HomePage() {
  const { t } = useTranslation();
  const agentsQuery = useAgentsQuery();
  const agents = useMemo(() => agentsQuery.data?.agents ?? [], [agentsQuery.data]);
  const attention = useAttention();
  const router = useRouter();
  // Someone with no agent yet starts with the first-run guide (docs/41 §5.2).
  const noAgents = agentsQuery.isSuccess && agents.length === 0;
  useEffect(() => {
    if (noAgents) router.replace("/onboarding");
  }, [noAgents, router]);
  // With two or more agents, one can be picked; "" is all of them.
  const [only, setOnly] = useState("");
  const picked = agents.find((a) => a.id === only) ?? null;
  const shownAgents = picked ? [picked] : agents;
  const shown: Attention =
    picked && attention.state === "ready"
      ? { ...attention, ...narrowAttention(attention, (item) => agentOfItem(item, agents)?.id === picked.id) }
      : attention;

  return (
    <AppShell title={t("home.title")} activePath="/">
      {/* Browser-side auto-replies run while this screen is open too. */}
      <InboxAgentBar agents={agents} quiet />
      <DeviceUpkeep agents={agents} />
      <div className="home" data-testid="home">
        {/* The page name is in the header; here, whose Home it is. */}
        <div className="home-head">
          {agents.length === 1 ? <span className="home-agent-one">{agents[0].label}</span> : null}
          {agents.length > 1 ? (
            <select
              className="home-select"
              aria-label={t("home.pickAgent")}
              value={only}
              onChange={(event) => setOnly(event.target.value)}
            >
              <option value="">{t("home.allAgents")}</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.label}
                </option>
              ))}
            </select>
          ) : null}
        </div>
        {agentsQuery.isSuccess && agents.length === 0 ? (
          <section className="home-section" data-testid="home-no-agents">
            <div className="home-box">
              <div className="home-error" style={{ background: "var(--surface-alt)" }}>
                <span className="home-error-text">
                  <b>{t("home.noAgents")}</b>
                  <br />
                  <span className="home-muted">{t("home.noAgentsSub")}</span>
                </span>
                <Link href="/onboarding" className="home-btn primary">
                  {t("home.startSetup")}
                </Link>
              </div>
            </div>
          </section>
        ) : (
          <>
            <HomeAttention attention={shown} agents={agents} />
            <HomeActivity agents={agents} only={picked} />
            {agents.length > 0 ? <HomeStatus agents={shownAgents} /> : null}
          </>
        )}
      </div>
    </AppShell>
  );
}
