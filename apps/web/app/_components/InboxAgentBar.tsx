"use client";

// The inbox's "where do automatic replies run" line (docs/34 §3 step 3).
// Also starts the browser-side auto-reply for each agent whose keys live
// in this browser, so replies go out while the inbox is open. With more
// than one browser, only the one chosen for it runs them (docs/40 §17.6).

import { useEffect, useState } from "react";
import type { Agent } from "../../lib/api/types";
import { localDeviceDid } from "../../lib/agents/local-device";
import { useTranslation } from "../../lib/i18n";
import { BrowserAutoReply } from "./BrowserAutoReply";

/** The agent a DID belongs to: its created-with DID or a computer's. */
export function agentForDid(agents: Agent[], did: string | undefined): Agent | undefined {
  if (!did) return undefined;
  return agents.find((a) => a.did === did || a.dids?.includes(did));
}

export function InboxAgentBar({ agents }: { agents: Agent[] }) {
  const { t } = useTranslation();
  // This browser's device of each agent whose keys it holds, by agent DID.
  const [inBrowser, setInBrowser] = useState<Map<string, string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all(agents.map(async (a) => [a.did, await localDeviceDid(a)] as const)).then((pairs) => {
      if (cancelled) return;
      setInBrowser(new Map(pairs.flatMap(([did, local]) => (local ? [[did, local] as const] : []))));
    });
    return () => {
      cancelled = true;
    };
  }, [agents]);

  if (agents.length === 0) return null;

  const autoReplying = agents.filter((a) => a.auto_reply);
  // Run here: this browser is the one chosen (by default the one the agent
  // was created with). Another browser of the person: neither here nor on
  // a computer.
  const runsHere = (a: Agent) => inBrowser?.get(a.did) === (a.auto_reply_device ?? a.did);
  const browserRun = inBrowser ? autoReplying.filter(runsHere) : [];
  const otherBrowserRun = inBrowser
    ? autoReplying.filter((a) => !runsHere(a) && inBrowser.has(a.did))
    : [];
  const computerRun = inBrowser ? autoReplying.filter((a) => !inBrowser.has(a.did)) : [];
  const names = (list: Agent[]) => list.map((a) => a.label).join("、");

  return (
    <section className="inbox-agent-bar">
      {browserRun.length > 0 || computerRun.length > 0 || otherBrowserRun.length > 0 ? (
        <p
          data-testid="inbox-auto-reply-note"
          style={{
            margin: "6px 16px 4px",
            fontSize: 13,
            color: "var(--ok)",
            background: "var(--ok-soft)",
            borderRadius: 10,
            padding: "6px 12px",
          }}
        >
          {t("inboxAgents.autoReplyLead")}
          {computerRun.length > 0
            ? t("inboxAgents.onComputer", { names: names(computerRun) })
            : ""}
          {browserRun.length > 0
            ? t("inboxAgents.inBrowser", { names: names(browserRun) })
            : ""}
          {otherBrowserRun.length > 0
            ? t("inboxAgents.inOtherBrowser", { names: names(otherBrowserRun) })
            : ""}
        </p>
      ) : null}
      {browserRun.map((a) => (
        <BrowserAutoReply key={a.did} agent={a} deviceDid={inBrowser?.get(a.did) ?? a.did} />
      ))}
    </section>
  );
}
