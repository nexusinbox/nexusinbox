// Which auto-reply label an inbox row gets. A row is marked "sent" both
// when a reply went out and when an executor handled it without answering
// (not a request, a policy override, …); only the first carries the
// reply's id, and only it is labelled as auto-replied (docs/31 §5.6).

export type AutoReplyBadge = "replied" | "incomplete" | "decided" | null;

export function autoReplyBadge(row: {
  sentAt?: string;
  replyMessageId?: string;
  claimedAt?: string;
  decision?: string;
}): AutoReplyBadge {
  // Handled: replied, or nothing to say about it.
  if (row.sentAt) return row.replyMessageId ? "replied" : null;
  // Taken for sending but never confirmed (docs/29 §2.5).
  if (row.claimedAt) return "incomplete";
  if (row.decision) return "decided";
  return null;
}
