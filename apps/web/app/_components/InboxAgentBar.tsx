"use client";

// The inbox's agent filter and the "where do automatic replies run" line
// (docs/34 §3 step 3). Also starts the browser-side auto-reply for each
// agent whose keys live in this browser, so replies go out while the
// inbox is open.

import { useEffect, useState } from "react";
import type { Agent } from "../../lib/api/types";
import { hasSigningPrivateKeyMaterial } from "../../lib/crypto/signing-keyring";
import { useTranslation } from "../../lib/i18n";
import { BrowserAutoReply } from "./BrowserAutoReply";

const CHIP_COLORS: Array<{ color: string; background: string }> = [
  { color: "#6d28d9", background: "#f1eafe" },
  { color: "#0e7490", background: "#e3f6fa" },
  { color: "#b45309", background: "#fdf1e3" },
  { color: "#15803d", background: "#e8f6ec" },
  { color: "#be185d", background: "#fbe8f1" },
];

/** The agent a DID belongs to: its created-with DID or a computer's. */
export function agentForDid(agents: Agent[], did: string | undefined): Agent | undefined {
  if (!did) return undefined;
  return agents.find((a) => a.did === did || a.dids?.includes(did));
}

/** A stable color per agent, by its position in the agent list. */
export function agentChipStyle(agents: Agent[], did: string | undefined): React.CSSProperties | null {
  const owner = agentForDid(agents, did);
  const index = owner ? agents.indexOf(owner) : -1;
  if (index < 0) return null;
  const c = CHIP_COLORS[index % CHIP_COLORS.length];
  return {
    display: "inline-block",
    fontSize: 11,
    fontWeight: 700,
    borderRadius: 6,
    padding: "0 7px",
    marginRight: 6,
    color: c.color,
    background: c.background,
    verticalAlign: 1,
  };
}

export function InboxAgentBar({
  agents,
  selected,
  onSelect,
}: {
  agents: Agent[];
  /** "all" or an agent's aid. */
  selected: string;
  onSelect: (aidOrAll: string) => void;
}) {
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
    <section className="inbox-agent-bar" style={{ padding: "6px 16px 2px" }}>
      {agents.length > 1 ? (
        <div
          role="tablist"
          aria-label={t("inboxAgents.filterLabel")}
          style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}
        >
          <button
            type="button"
            role="tab"
            aria-selected={selected === "all"}
            className={"filter-tab" + (selected === "all" ? " active" : "")}
            onClick={() => onSelect("all")}
          >
            {t("inboxAgents.all")}
          </button>
          {agents.map((a) => (
            <button
              key={a.did}
              type="button"
              role="tab"
              aria-selected={selected === a.aid}
              className={"filter-tab" + (selected === a.aid ? " active" : "")}
              onClick={() => onSelect(a.aid)}
            >
              <span style={agentChipStyle(agents, a.did) ?? undefined}>{a.label}</span>
              {t("inboxAgents.only")}
            </button>
          ))}
        </div>
      ) : null}
      {browserRun.length > 0 || computerRun.length > 0 ? (
        <p
          data-testid="inbox-auto-reply-note"
          style={{
            margin: "0 0 4px",
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
