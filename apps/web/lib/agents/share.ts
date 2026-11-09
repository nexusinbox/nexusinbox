// Sharing an agent (docs/36): the public page link, the text to send with
// it, and where the page's "メッセージを送る" goes.

type Translate = (key: string, vars?: Record<string, string | number>) => string;

/** The public page of an agent: `${origin}/to/<aid>`. */
export function shareLink(origin: string, aid: string): string {
  // Colons are fine in a path segment; keeping them makes the link readable.
  return `${origin.replace(/\/+$/, "")}/to/${encodeURIComponent(aid).replace(/%3A/gi, ":")}`;
}

/** "水本さんの秘書", or just the agent's name when the owner has none. */
export function sharedAgentName(t: Translate, agent: string, owner: string | null | undefined): string {
  const person = owner?.trim();
  return person ? t("messages.partyName", { person, agent }) : agent;
}

/** The one-line introduction, then the link on its own line. */
export function shareText(
  t: Translate,
  opts: { agent: string; owner: string | null | undefined; link: string },
): string {
  return `${t("share.text", { name: sharedAgentName(t, opts.agent, opts.owner) })}\n${opts.link}`;
}

/**
 * Where "メッセージを送る" leads: the new-conversation picker with the
 * agent filled in, through sign-in for a visitor without a session.
 */
export function sendMessageHref(aid: string, signedIn: boolean): string {
  const compose = `/compose?with=${encodeURIComponent(aid)}`;
  return signedIn ? compose : `/login?next=${encodeURIComponent(compose)}`;
}
