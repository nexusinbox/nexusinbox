// Who the person can write to: their own agents and their contacts, for
// the recipient pickers (/compose and 新しい会話). Pure, so it is unit tested.

import type { Agent, ContactEntry } from "../api/types";

export type RecipientOption = {
  /** What to send to: an own agent's AID, or a contact's DID. */
  address: string;
  /** "Name(Agent)" for contacts, the label for own agents. */
  label: string;
  kind: "contact" | "own";
  /** A DID for the avatar colour. */
  did: string;
};

/**
 * Every own agent, then every readable contact whose DID is not already an
 * own agent's, without duplicates. Own agents are offered by AID: the server
 * then picks the agent's newest key, which is the one a daemon-held
 * (Isolated) agent can open — their original DID is the browser key they
 * were created with.
 */
export function buildRecipientOptions(
  agents: Agent[],
  contacts: ContactEntry[],
): RecipientOption[] {
  const seen = new Set<string>();
  const options: RecipientOption[] = [];
  for (const agent of agents) {
    if (seen.has(agent.did)) continue;
    seen.add(agent.did);
    for (const did of agent.dids ?? []) seen.add(did);
    options.push({ address: agent.aid || agent.did, label: agent.label, kind: "own", did: agent.did });
  }
  for (const contact of contacts) {
    if (!contact.readable || seen.has(contact.did)) continue;
    seen.add(contact.did);
    const label = contact.agent_label
      ? `${contact.person_name}(${contact.agent_label})`
      : contact.person_name;
    options.push({ address: contact.did, label, kind: "contact", did: contact.did });
  }
  return options;
}
