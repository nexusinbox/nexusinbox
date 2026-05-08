// Inbox list helper: collapse a flat message list into Gmail-style
// thread groups.
//
// Why client-side: the existing `/messages` endpoint returns one
// `message_index` row per message. Adding server-side thread
// aggregation would be a separate, larger change (DISTINCT ON +
// GROUP BY rewrite, plus pagination semantics — does "page 1, 20
// per page" mean "20 threads" or "20 messages"?). Keeping the
// grouping local lets us ship the UX win immediately. The cost is
// that pagination still operates on individual messages, so the
// last page of a heavily-threaded view may surface fewer "rows"
// than `per_page` after collapse — acceptable for now and easy to
// revisit when threads grow large enough to matter.
//
// Folder context: the messages array passed in is already
// folder-scoped (e.g. inbox, sent, all_mail) by the caller's API
// query. We do not re-filter, so a Sent view shows thread groups
// where the current agent is the sender (count = how many of MY
// sends in this thread), and Inbox shows groups where the agent
// is the recipient. This matches Gmail's "count in this view"
// behaviour rather than "count across the whole conversation".

import type { MessageIndexEntry } from "../api/types";

export type ThreadGroup = {
  /**
   * Representative entry — the newest message in the group. Used as
   * the seed when opening the detail view; ConversationThread will
   * walk the full thread from there.
   */
  representative: MessageIndexEntry;
  /** All messages in the group, newest-first. */
  messages: MessageIndexEntry[];
  /** Convenience: messages.length. Lets the row renderer skip the
   *  array allocation when it only needs the count badge. */
  count: number;
  /** True if any message in the group has `status === "unread"`. The
   *  row stays bold when even one reply is unread, matching Gmail. */
  hasUnread: boolean;
};

export function groupMessagesByThread(
  messages: MessageIndexEntry[],
): ThreadGroup[] {
  const byKey = new Map<string, MessageIndexEntry[]>();

  for (const msg of messages) {
    // Messages without a thread_id stand alone. Synthesise a unique
    // key so two unrelated standalone messages aren't accidentally
    // merged into one "group".
    const key = msg.thread_id ?? `__singleton__:${msg.id}`;
    const list = byKey.get(key);
    if (list) {
      list.push(msg);
    } else {
      byKey.set(key, [msg]);
    }
  }

  const groups: ThreadGroup[] = [];
  for (const list of byKey.values()) {
    // Newest-first inside each group so the first element is the
    // representative and the detail view can still walk older
    // messages via thread_id.
    list.sort((a, b) => b.created_at.localeCompare(a.created_at));
    groups.push({
      representative: list[0],
      messages: list,
      count: list.length,
      hasUnread: list.some((m) => m.status === "unread"),
    });
  }

  // Outer sort: most recent activity first, same as the flat-list
  // ordering the caller already produced.
  groups.sort((a, b) =>
    b.representative.created_at.localeCompare(a.representative.created_at),
  );

  return groups;
}
