"use client";

// The inbox's "where do automatic replies run" line (docs/34 §3 step 3).
// Also starts the browser-side auto-reply for each agent whose keys live
// in this browser, so replies go out while the inbox is open.

import { useEffect, useState } from "react";
import type { Agent } from "../../lib/api/types";
import { hasSigningPrivateKeyMaterial } from "../../lib/crypto/signing-keyring";
import { useTranslation } from "../../lib/i18n";
import { BrowserAutoReply } from "./BrowserAutoReply";

/** The agent a DID belongs to: its created-with DID or a computer's. */
export function agentForDid(agents: Agent[], did: string | undefined): Agent | undefined {
  if (!did) return undefined;
  return agents.find((a) => a.did === did || a.dids?.includes(did));
}

export function InboxAgentBar({ agents }: { agents: Agent[] }) {
  const { t } = useTranslation();
  // DIDs whose signing key this browser holds (browser-run agents).
  const [inBrowser, setInBrowser] = useState<Set<string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all(
      agents.map(async (a) => [a.did, await hasSigningPrivateKeyMaterial(a.did)] as const),
    ).then((pairs) => {
      if (cancelled) return;
      setInBrowser(new Set(pairs.filter(([, has]) => has).map(([did]) => did)));
    });
    return () => {
      cancelled = true;
    };
  }, [agents]);

  if (agents.length === 0) return null;

  const autoReplying = agents.filter((a) => a.auto_reply);
  const browserRun = inBrowser ? autoReplying.filter((a) => inBrowser.has(a.did)) : [];
  const computerRun = inBrowser ? autoReplying.filter((a) => !inBrowser.has(a.did)) : [];
  const names = (list: Agent[]) => list.map((a) => a.label).join("、");

  return (
    <section className="inbox-agent-bar">
      {browserRun.length > 0 || computerRun.length > 0 ? (
        <p
          data-testid="inbox-auto-reply-note"
          style={{
            margin: "6px 16px 4px",
            fontSize: 13,
            color: "#0f7b4b",
            background: "#e7f6ee",
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
        </p>
      ) : null}
      {browserRun.map((a) => (
        <BrowserAutoReply key={a.did} agent={a} />
      ))}
    </section>
  );
}
