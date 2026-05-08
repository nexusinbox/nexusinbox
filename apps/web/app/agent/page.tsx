"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAgentsQuery } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";

// "By Agent" entry point: auto-routes to the first agent's inbox.
// A switcher dropdown in that page's header lets the user change agents
// without returning here. When no agents exist, render an empty state
// with a CTA rather than loop the redirect.
//
// Note on the redirect flash: the warm-cache path avoids this page
// entirely — `AppShell` rewrites the sidebar "エージェント別" href to
// `/agent/{firstDid}` once it knows the first agent. We only land here
// on cold-cache first-paint or when the sidebar link is bookmarked
// literally. In those cases we return `null` (not a visible
// "リダイレクト中..." card) so the blank frame before `router.replace`
// fires looks intentional rather than like a broken redirect loop.
export default function AgentIndexPage() {
  const { t } = useTranslation();
  const router = useRouter();
  const agentsQuery = useAgentsQuery();

  useEffect(() => {
    if (agentsQuery.isPending) return;
    const firstDid = agentsQuery.data?.agents?.[0]?.did;
    if (firstDid) {
      router.replace(`/agent/${encodeURIComponent(firstDid)}`);
    }
  }, [agentsQuery.isPending, agentsQuery.data?.agents, router]);

  if (agentsQuery.isPending) {
    // No visible placeholder — the sidebar already has the nav item
    // highlighted, so an empty main pane reads as "loading" without
    // an explicit copy that could flicker into view for one frame.
    return null;
  }

  if (agentsQuery.isError) {
    return <div className="card">{t("agentView.error")}</div>;
  }

  const agents = agentsQuery.data?.agents ?? [];

  if (agents.length === 0) {
    return (
      <div className="card" style={{ padding: 24 }}>
        <h2 style={{ marginTop: 0 }}>{t("agentView.emptyTitle")}</h2>
        <p className="item-sub" style={{ marginTop: 8 }}>
          {t("agentView.emptyDesc")}
        </p>
        <div style={{ marginTop: 16 }}>
          <Link className="btn btn-primary" href="/settings/agents">
            {t("agentView.createBtn")}
          </Link>
        </div>
      </div>
    );
  }

  // Query resolved, agents ≥ 1 → the useEffect above is about to
  // fire `router.replace`. Render nothing for the in-between frame
  // instead of the old "リダイレクト中..." card so the user never
  // sees a transition placeholder.
  return null;
}
