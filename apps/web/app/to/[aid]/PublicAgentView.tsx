"use client";

// The body of an agent's public intro page (docs/36 ③), in the login
// screen's light card. Data comes from the server page; this part only
// picks the language.

import Link from "next/link";
import { sharedAgentName } from "../../../lib/agents/share";
import type { PublicAgent } from "../../../lib/api/types";
import { useTranslation } from "../../../lib/i18n";
import { avatarColorIndex, avatarInitial } from "../../../lib/inbox/conversations";
import { Logo } from "../../_components/Logo";

export type PublicAgentState =
  | { kind: "ok"; agent: PublicAgent; sendHref: string }
  | { kind: "missing" }
  | { kind: "unavailable" };

export function PublicAgentView({ state }: { state: PublicAgentState }) {
  const { locale, setLocale, t } = useTranslation();

  return (
    <main className="lg-root" data-testid="public-agent">
      <button
        type="button"
        className="lg-lang"
        onClick={() => setLocale(locale === "en" ? "ja" : "en")}
        aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
      >
        {locale === "en" ? "日本語" : "English"}
      </button>

      <section className="lg-card">
        <Link href="/login" className="lg-brand pa-brand">
          <Logo size={32} variant="light" />
          <span>
            Nexus<b>Inbox</b>
          </span>
        </Link>

        {state.kind === "ok" ? (
          <AgentIntro agent={state.agent} sendHref={state.sendHref} />
        ) : (
          <div className="pa-body">
            <h1 className="pa-name">
              {t(state.kind === "missing" ? "publicAgent.notFoundTitle" : "publicAgent.unavailableTitle")}
            </h1>
            <p className="pa-note">
              {t(state.kind === "missing" ? "publicAgent.notFoundDesc" : "publicAgent.unavailableDesc")}
            </p>
            <Link href="/login" className="pa-cta">
              {t("publicAgent.toLogin")}
            </Link>
          </div>
        )}
      </section>
    </main>
  );
}

function AgentIntro({ agent, sendHref }: { agent: PublicAgent; sendHref: string }) {
  const { t } = useTranslation();
  const name = sharedAgentName(t, agent.label, agent.owner_display_name);
  return (
    <div className="pa-body">
      {/* Coloured by the address, like every avatar in the app. */}
      <span className={`dm-av lg dm-c${avatarColorIndex(agent.aid)}`} aria-hidden="true">
        {avatarInitial(agent.label)}
        <span className="dm-bot">🤖</span>
      </span>
      <h1 className="pa-name" data-testid="public-agent-name">
        {name}
      </h1>
      {agent.bio ? <p className="pa-bio">{agent.bio}</p> : null}
      <p className="pa-note">{t("publicAgent.verified")}</p>
      <Link href={sendHref} className="pa-cta" data-testid="public-agent-send">
        {t("publicAgent.send")}
      </Link>
      <p className="pa-note">{t("publicAgent.firstTime")}</p>
    </div>
  );
}
