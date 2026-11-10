"use client";

// Help for people using NexusInbox (docs/34 §3 step 4): the words of the
// first-run setup and the app, nothing about keys, protocols or APIs.
// The technical reference lives at /help/developers.

import Link from "next/link";
import type { ReactNode } from "react";
import { AppShell } from "../_components/AppShell";
import { useAuthSessionQuery } from "../../lib/api/hooks";
import { useTranslation } from "../../lib/i18n";
import { AccordionChevron, PublicHelpShell, RichText } from "./HelpParts";

const SECTIONS = ["what", "start", "daily", "ai", "safe", "trouble", "words"] as const;

function Section({ id, children }: { id: (typeof SECTIONS)[number]; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <section className="help-card" id={`help-${id}`} data-testid={`help-${id}`}>
      <h2 className="help-card-title" style={{ marginBottom: 12 }}>
        {t(`guide.${id}.title`)}
      </h2>
      {children}
    </section>
  );
}

function Para({ k }: { k: string }) {
  const { t } = useTranslation();
  return (
    <p className="help-card-desc" style={{ margin: "6px 0" }}>
      <RichText text={t(k)} />
    </p>
  );
}

/** Term and description pairs, `guide.<prefix>.<key>Term` / `…Desc`. */
function Terms({ prefix, keys }: { prefix: string; keys: string[] }) {
  const { t } = useTranslation();
  return (
    <dl className="help-glossary-list">
      {keys.map((key) => (
        <div key={key} className="help-glossary-item">
          <dt className="help-glossary-term">{t(`guide.${prefix}.${key}Term`)}</dt>
          <dd className="help-glossary-desc">
            <RichText text={t(`guide.${prefix}.${key}Desc`)} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Steps({ prefix, count, link }: { prefix: string; count: number; link?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <ol className="help-steps">
      {Array.from({ length: count }, (_, i) => (
        <li key={i} className="help-step">
          <span className="help-step-num">{i + 1}</span>
          <div>
            <p className="help-step-title">{t(`guide.${prefix}.step${i + 1}Title`)}</p>
            <p className="help-step-body">
              <RichText text={t(`guide.${prefix}.step${i + 1}Body`)} />
            </p>
            {i === 0 ? link : null}
          </div>
        </li>
      ))}
    </ol>
  );
}

function Question({ k, id, children }: { k: string; id?: string; children?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <details className="help-card help-card-accordion" id={id} style={{ padding: 0, marginTop: 10 }}>
      <summary className="help-card-header help-accordion-summary" style={{ padding: "14px 18px" }}>
        <span style={{ fontWeight: 600 }}>{t(`${k}Q`)}</span>
        <AccordionChevron />
      </summary>
      <div className="help-accordion-content" style={{ padding: "0 18px 14px" }}>
        <p className="help-card-desc" style={{ margin: 0 }}>
          <RichText text={t(`${k}A`)} />
        </p>
        {children}
      </div>
    </details>
  );
}

const BOX: React.CSSProperties = {
  borderRadius: 12,
  padding: "10px 14px",
  margin: "8px 0",
  fontSize: 14,
  lineHeight: 1.6,
};

export default function HelpPage() {
  const { t } = useTranslation();
  const sessionQuery = useAuthSessionQuery();
  const isAuthenticated = sessionQuery.data?.authenticated === true;

  const content = (
    <div className="help-container">
      <div className="help-hero">
        <h1 className="help-hero-title">{t("guide.title")}</h1>
        <p className="help-hero-subtitle">{t("guide.subtitle")}</p>
        <nav style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 14 }} aria-label={t("guide.toc")}>
          {SECTIONS.map((id) => (
            <a
              key={id}
              href={`#help-${id}`}
              style={{
                fontSize: 13,
                color: "var(--primary)",
                background: "var(--surface-alt)",
                borderRadius: 999,
                padding: "3px 12px",
                textDecoration: "none",
              }}
            >
              {t(`guide.${id}.title`)}
            </a>
          ))}
        </nav>
      </div>

      <Section id="what">
        <Para k="guide.what.body" />
        <Terms prefix="what" keys={["private", "human", "ai"]} />
      </Section>

      <Section id="start">
        <Steps
          prefix="start"
          count={4}
          link={
            <Link href={isAuthenticated ? "/onboarding" : "/login?next=/onboarding"} className="help-step-link">
              {t("guide.start.open")} →
            </Link>
          }
        />
        <Question k="guide.start.where" id="help-modes" />
      </Section>

      <Section id="daily">
        <Terms prefix="daily" keys={["inbox", "review", "sent", "compose", "replies", "block"]} />
        <Para k="guide.daily.retention" />
      </Section>

      <Section id="ai">
        <Para k="guide.ai.body" />
        <Terms prefix="ai" keys={["can", "cannot"]} />
        <h3 style={{ fontSize: 16, margin: "18px 0 4px" }}>{t("guide.ai.cloudTitle")}</h3>
        <Para k="guide.ai.cloudNeedsComputer" />
        <Steps prefix="ai" count={4} />
        <h3 style={{ fontSize: 15, margin: "16px 0 4px" }}>{t("guide.ai.appsTitle")}</h3>
        <Para k="guide.ai.muse" />
        <div style={{ ...BOX, background: "var(--surface-alt)" }} data-testid="help-muse-phrase">
          {t("guide.ai.musePhrase")}
        </div>
        <Para k="guide.ai.museNote" />
        <Para k="guide.ai.claude" />
        <Para k="guide.ai.others" />
        <div style={{ ...BOX, background: "var(--warn-soft)", color: "var(--warn)" }}>
          <RichText text={t("guide.ai.provider")} />
        </div>
        <h3 style={{ fontSize: 16, margin: "18px 0 4px" }}>{t("guide.ai.localTitle")}</h3>
        <p className="help-card-desc" style={{ margin: "6px 0" }}>
          {t("guide.ai.localBody")}{" "}
          <Link href="/help/developers" className="help-step-link">
            {t("guide.developersLink")} →
          </Link>
        </p>
      </Section>

      <Section id="safe">
        <Terms prefix="safe" keys={["unread", "expiry", "human", "keys", "stop", "history"]} />
      </Section>

      <Section id="trouble">
        <Question k="guide.trouble.stopped" />
        <Question k="guide.trouble.preparing" />
        <Question k="guide.trouble.autoReply" />
        <Question k="guide.trouble.cannotRead" />
        <Question k="guide.trouble.stranger" />
      </Section>

      <Section id="words">
        <Terms prefix="words" keys={["address", "review", "cloud", "history", "technical"]} />
      </Section>

      <p className="help-card-desc" style={{ textAlign: "center" }}>
        {t("guide.developersNote")}{" "}
        <Link href="/help/developers" className="help-step-link" data-testid="help-developers-link">
          {t("guide.developersLink")} →
        </Link>
      </p>
    </div>
  );

  return isAuthenticated ? (
    <AppShell title={t("guide.title")} activePath="/help">
      {content}
    </AppShell>
  ) : (
    <PublicHelpShell>{content}</PublicHelpShell>
  );
}
