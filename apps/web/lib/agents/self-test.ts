// The first-run guide's test (docs/31): the new agent sends itself a
// scheduling proposal, and the guide shows what happened to it — that it
// arrived, what the chosen setting decided, and, on a connected computer,
// that the computer answered.

import type { ScheduleCandidate } from "@nexusinbox/core/a2a";
import type { MessageIndexEntry } from "../api/types";
import { toIsoWithLocalOffset } from "../protocol/candidateInput";

const pad = (n: number) => String(n).padStart(2, "0");

/** Two 30-minute slots at 10:00 on the next two days, local time. */
export function selfTestCandidates(now: Date): ScheduleCandidate[] {
  return [1, 2].map((days) => {
    const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() + days);
    const date = `${day.getFullYear()}-${pad(day.getMonth() + 1)}-${pad(day.getDate())}`;
    return {
      start: toIsoWithLocalOffset(`${date}T10:00`),
      end: toIsoWithLocalOffset(`${date}T10:30`),
    };
  });
}

export type SelfTestState =
  /** Not in the inbox yet. */
  | "waiting"
  /** In the inbox; the setting has not been applied yet. */
  | "arrived"
  /** Left to the person. */
  | "queued"
  /** Left to the person because the sender (the agent itself) is not a contact. */
  | "queued_not_contact"
  /** To be accepted by the computer, which has not answered yet. */
  | "accept_pending_pc"
  /** Accepted by the computer. */
  | "accepted_pc"
  /** To be accepted by this browser once the agent's inbox is open. */
  | "accept_in_browser";

export function selfTestState(
  row: MessageIndexEntry | null,
  where: "browser" | "pc",
): SelfTestState {
  if (!row) return "waiting";
  if (!row.auto_reply_decision) return "arrived";
  if (row.auto_reply_decision === "auto_accept") {
    if (where === "browser") return "accept_in_browser";
    return row.auto_reply_sent_at ? "accepted_pc" : "accept_pending_pc";
  }
  return row.auto_reply_reason === "not_a_contact" ? "queued_not_contact" : "queued";
}

/** Whether nothing more will happen without the person. */
export function selfTestSettled(state: SelfTestState): boolean {
  return state !== "waiting" && state !== "arrived" && state !== "accept_pending_pc";
}
