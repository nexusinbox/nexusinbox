// An agent's public intro page (docs/36 ③). Works without a session: the
// API returns the name, bio and owner's display name only for an agent
// whose owner turned sharing on, and 404 for every other address.
// Rendered on the server so link previews (docs/36 ②) get the name.

import type { Metadata } from "next";
import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import { cache } from "react";
import { sendMessageHref, sharedAgentName } from "../../../lib/agents/share";
import type { PublicAgent } from "../../../lib/api/types";
import { translate } from "../../../lib/i18n/translate";
import { alt as ogImageAlt, size as ogImageSize } from "../../opengraph-image";
import { PublicAgentView } from "./PublicAgentView";

type Props = { params: Promise<{ aid: string }> };

type Lookup = { kind: "ok"; agent: PublicAgent } | { kind: "missing" } | { kind: "unavailable" };

// The same API the browser reaches through the /api rewrite (next.config.ts).
const API_ORIGIN =
  process.env.API_ORIGIN ?? (process.env.NODE_ENV !== "production" ? "http://localhost:8080" : "");

// Link previews and search: Japanese first, like the UI.
const t = (key: string, vars?: Record<string, string | number>) => translate("ja", key, vars);

function decodeParam(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// One API call per request, shared by generateMetadata and the page.
// Cached for 60 s across visitors (see revalidate below); deduped within a request.
const lookup = cache(async (aid: string): Promise<Lookup> => {
  if (!API_ORIGIN) return { kind: "unavailable" };
  try {
    const response = await fetch(`${API_ORIGIN}/public/agents/${encodeURIComponent(aid)}`, {
      // Shared by every visitor and link preview; turning sharing off
      // takes effect within this minute.
      next: { revalidate: 60 },
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
    if (response.status === 404) return { kind: "missing" };
    if (!response.ok) return { kind: "unavailable" };
    const body = (await response.json()) as Partial<PublicAgent>;
    if (typeof body.label !== "string") return { kind: "unavailable" };
    return {
      kind: "ok",
      agent: {
        aid,
        label: body.label,
        bio: typeof body.bio === "string" ? body.bio : "",
        owner_display_name:
          typeof body.owner_display_name === "string" ? body.owner_display_name : null,
        avatar_color: body.avatar_color,
      },
    };
  } catch {
    return { kind: "unavailable" };
  }
});

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const aid = decodeParam((await params).aid);
  const found = await lookup(aid);
  // Shared by link, not listed: search engines stay out either way.
  const robots = { index: false, follow: false };
  if (found.kind !== "ok") {
    return {
      title: t(found.kind === "missing" ? "publicAgent.notFoundTitle" : "publicAgent.unavailableTitle"),
      robots,
    };
  }
  const title = t("publicAgent.ogTitle", {
    name: sharedAgentName(t, found.agent.label, found.agent.owner_display_name),
  });
  const description = t("auth.sub");
  return {
    title,
    description,
    robots,
    // Setting openGraph / twitter here replaces the inherited ones, images
    // included, so point back at the app's own cards (app/opengraph-image.tsx,
    // app/twitter-image.tsx).
    openGraph: {
      title,
      description,
      siteName: "NexusInbox",
      type: "website",
      url: `/to/${encodeURIComponent(aid)}`,
      images: [{ url: "/opengraph-image", alt: ogImageAlt, ...ogImageSize }],
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      images: [{ url: "/twitter-image", alt: ogImageAlt }],
    },
  };
}

export default async function PublicAgentPage({ params }: Props) {
  const aid = decodeParam((await params).aid);
  const found = await lookup(aid);
  if (found.kind === "missing") notFound();
  if (found.kind === "unavailable") return <PublicAgentView state={{ kind: "unavailable" }} />;
  // A session cookie is enough to skip /login; if it has expired, the
  // middleware sends /compose through /login with the same `next`.
  const signedIn = Boolean((await cookies()).get("nexusinbox_session")?.value);
  return (
    <PublicAgentView
      state={{ kind: "ok", agent: found.agent, sendHref: sendMessageHref(aid, signedIn) }}
    />
  );
}
