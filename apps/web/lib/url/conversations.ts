// Where the conversation list lives (docs/41 §3): `/conversations`. Home is
// `/`; an old link to `/` that names a conversation, an agent or a view is
// sent on with its query (next.config.ts, CONVERSATION_PARAMS).

export const CONVERSATIONS_PATH = "/conversations";

/** Query parameters that meant the conversation list on `/`. */
export const CONVERSATION_PARAMS = ["with", "as", "agent", "view"] as const;

export type ConversationsQuery = {
  /** The other party: opens the conversation with them. */
  with?: string;
  /** Which of the person's agents writes. */
  as?: string;
  /** Show one agent's conversations. */
  agent?: string;
  view?: "archive";
  /** Only conversations an automatic reply went to (docs/41 §6.3). */
  filter?: "auto";
};

export function conversationsHref(query: ConversationsQuery = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value) params.set(key, value);
  }
  const qs = params.toString();
  return qs ? `${CONVERSATIONS_PATH}?${qs}` : CONVERSATIONS_PATH;
}
