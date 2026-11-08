import { describe, expect, it } from "vitest";
import { autoReplyBadge } from "./auto-reply-badge";

describe("autoReplyBadge", () => {
  it("says auto-replied only when a reply went out", () => {
    expect(autoReplyBadge({ sentAt: "t", replyMessageId: "r", claimedAt: "t", decision: "auto_accept" })).toBe(
      "replied",
    );
    // Handled without answering: no label at all, not the decision.
    expect(autoReplyBadge({ sentAt: "t", claimedAt: "t", decision: "auto_accept" })).toBeNull();
  });

  it("keeps the unconfirmed and decided labels", () => {
    expect(autoReplyBadge({ claimedAt: "t", decision: "auto_accept" })).toBe("incomplete");
    expect(autoReplyBadge({ decision: "queue_for_human" })).toBe("decided");
    expect(autoReplyBadge({})).toBeNull();
  });
});
