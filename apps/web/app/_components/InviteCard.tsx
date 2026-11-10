"use client";

// 相手を招く (docs/37): a new person has no one to talk to, and there is no
// directory. Offer the agent's intro link where they land with nobody yet.
// Making the link turns sharing on (the same switch as 紹介する), so the
// card says what becomes visible before the button.

import { useState } from "react";
import { sharedAgentName } from "../../lib/agents/share";
import { useAuthSessionQuery, useUpdateAgentMutation } from "../../lib/api/hooks";
import type { Agent } from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";
import { AgentSharePanel } from "./AgentSharePanel";

export function InviteCard({
  agent,
  title,
  desc,
  onLater,
}: {
  agent: Agent;
  title: string;
  desc: string;
  onLater?: () => void;
}) {
  const { t } = useTranslation();
  const updateAgent = useUpdateAgentMutation();
  const [failed, setFailed] = useState(false);

  const create = async () => {
    setFailed(false);
    try {
      await updateAgent.mutateAsync({ id: agent.id, body: { share_enabled: true } });
    } catch {
      setFailed(true);
    }
  };

  return (
    <div className="invite-card" data-testid="invite-card">
      <h3>{title}</h3>
      <p className="item-sub">{desc}</p>
      {agent.share_enabled ? (
        <AgentSharePanel agent={agent} />
      ) : (
        <>
          <p className="item-sub">{t("share.invitePublicNote")}</p>
          <div className="dm-btns">
            <button
              type="button"
              className="dm-btn accent"
              onClick={() => void create()}
              disabled={updateAgent.isPending}
              data-testid="invite-create"
            >
              {t("share.inviteCreate")}
            </button>
            {onLater ? (
              <button type="button" className="dm-btn" onClick={onLater}>
                {t("share.inviteLater")}
              </button>
            ) : null}
          </div>
          {failed ? (
            <p className="sh-note error" role="status">
              {t("share.failed")}
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}

/** "テスト花子さんの秘書": how the link's visitors will see the agent. */
export function useInviteName(agent: Agent): string {
  const { t } = useTranslation();
  const session = useAuthSessionQuery();
  return sharedAgentName(t, agent.label, session.data?.user?.display_name);
}
