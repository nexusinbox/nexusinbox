// The three answers the first-run guide offers to "how should requests be
// handled?" (docs/31), as the agent's auto-reply switch and policy.
//
// The server tags each incoming message with a decision before anyone
// can read it, so it only knows the policy's default branch: a default of
// auto_accept is what lets the executors pick a message up. They then see
// the protocol and answer scheduling proposals only. Task delegations stay
// with the person in every preset.

import type { AutoReplyPolicy } from "../api/types";

export type AutoReplyPreset = "manual" | "contacts" | "all";

export type PresetSettings = {
  autoReply: boolean;
  /** null: leave the policy as it is (auto-reply is off anyway). */
  policy: AutoReplyPolicy | null;
};

const TASKS_STAY_WITH_THE_PERSON: AutoReplyPolicy["protocols"] = {
  task_delegation: { delegate: { action: "queue_for_human" } },
};

export function presetSettings(preset: AutoReplyPreset): PresetSettings {
  switch (preset) {
    case "manual":
      return { autoReply: false, policy: null };
    case "contacts":
      return {
        autoReply: true,
        policy: {
          v: 1,
          default_action: "auto_accept",
          default_conditions: { require_contact: true },
          protocols: TASKS_STAY_WITH_THE_PERSON,
        },
      };
    case "all":
      return {
        autoReply: true,
        policy: {
          v: 1,
          default_action: "auto_accept",
          protocols: TASKS_STAY_WITH_THE_PERSON,
        },
      };
  }
}
