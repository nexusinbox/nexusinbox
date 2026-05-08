import type { ContactEntry } from "./types";

// Build a friendly participant label for a DID, preferring the
// caller's own address book over whatever the server joined in
// from its agent/user rows. Falls back to a truncated DID.
//
// Precedence:
//   1. contact entry owned by the current user (person_name + agent_label)
//   2. server-provided label (usually "display_name(agent_label)")
//   3. truncated DID head..tail
export function resolveParticipantLabel(
  did: string | null | undefined,
  serverLabel: string | null | undefined,
  contactsByDid: Map<string, ContactEntry> | null | undefined,
): string {
  if (!did) return "(不明な相手)";

  const contact = contactsByDid?.get(did);
  if (contact) {
    const label = contact.agent_label?.trim();
    if (label && label.length > 0) {
      return `${contact.person_name}(${label})`;
    }
    return contact.person_name;
  }

  const trimmed = serverLabel?.trim();
  if (trimmed) return trimmed;

  if (did.length <= 18) return did;
  return did.slice(0, 12) + "…" + did.slice(-4);
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
