import type { Agent, ContactEntry } from "./types";

// Build a friendly participant label for a DID, preferring the
// caller's own address book over whatever the server joined in
// from its agent/user rows. Falls back to "未登録の相手": the technical
// id is shown only in a message's details (docs/34 §2).
//
// Precedence:
//   1. contact entry owned by the current user (person_name + agent_label)
//   2. server-provided label (usually "display_name(agent_label)")
//   3. the caller's own agent, matched by any of its DIDs
//   4. "未登録の相手"
export function resolveParticipantLabel(
  did: string | null | undefined,
  serverLabel: string | null | undefined,
  contactsByDid: Map<string, ContactEntry> | null | undefined,
  ownAgents?: Agent[],
): string {
  if (!did) return "(不明な相手)";

  const contact = contactsByDid?.get(did);
  // A contact this device cannot open has no name to show.
  if (contact && contact.readable) {
    const label = contact.agent_label?.trim();
    if (label && label.length > 0) {
      return `${contact.person_name}(${label})`;
    }
    return contact.person_name;
  }

  const trimmed = serverLabel?.trim();
  if (trimmed) return trimmed;

  const own = ownAgents?.find((a) => a.did === did || a.dids?.includes(did));
  if (own) return own.label;

  return "未登録の相手";
}

// Convenience: build a DID→contact map once per render pass.
export function indexContactsByDid(contacts: ContactEntry[] | undefined): Map<string, ContactEntry> {
  const map = new Map<string, ContactEntry>();
  if (!contacts) return map;
  for (const contact of contacts) {
    map.set(contact.did, contact);
  }
  return map;
}
