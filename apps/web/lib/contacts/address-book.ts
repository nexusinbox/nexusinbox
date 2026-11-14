// The person's address book, opened on this device (docs/28 P3-8).
//
// The server keeps each contact's DID plus a sealed blob, and the contacts
// key only as wraps for the person's own agents. A device that holds one of
// those agents' X25519 keys opens a wrap, decrypts the contacts, and adds
// wraps for agents that lack one.
//
// Trust: the agents' public keys come from the server, as recipients' keys
// do when sending. This protects against a leaked database or a curious
// operator, not against a server that hands out keys of its own.

import { ApiError } from "../api/client";
import type {
  AddContactKeysRequest,
  Agent,
  ContactEntry,
  ContactKeysResponse,
  ContactRecord,
  ContactRecordsResponse,
  ContactsResponse,
} from "../api/types";
import {
  type ContactFields,
  generateContactsKey,
  openContactFields,
  sealContactFields,
} from "../crypto/contacts";
import {
  isValidX25519PublicKeyB64Url,
  unwrapContactsKey,
  wrapContactsKeyForAgent,
} from "../crypto/keywrap";
import { getRecipientPrivateKey } from "../crypto/recipient-keyring";
import { rememberContactRoots } from "../agents/peer-pins";

export type AddressBookApi = {
  listContacts(): Promise<ContactRecordsResponse>;
  addDeviceContactKey?(payload: { did: string; wrapped_key: string }): Promise<void>;
  listContactKeys(): Promise<ContactKeysResponse>;
  addContactKeys(payload: AddContactKeysRequest): Promise<void>;
  resetContactKeys(): Promise<void>;
  listAgents(): Promise<{ agents: Agent[] }>;
};

export class ContactsLockedError extends Error {
  constructor() {
    super("contacts are locked on this device");
  }
}

// The opened key for this page session. Dropped on reset.
let cachedKey: string | null = null;

async function wrapsFor(key: string, agents: Agent[]): Promise<AddContactKeysRequest["wraps"]> {
  const wraps: AddContactKeysRequest["wraps"] = [];
  for (const agent of agents) {
    if (!agent.encryption_key || !isValidX25519PublicKeyB64Url(agent.encryption_key)) continue;
    wraps.push({
      agent_id: agent.id,
      wrapped_key: await wrapContactsKeyForAgent(key, agent.encryption_key),
    });
  }
  return wraps;
}

async function holdsAnyAgentKey(agents: Agent[]): Promise<boolean> {
  for (const agent of agents) {
    if (await getRecipientPrivateKey(agent.did)) return true;
  }
  return false;
}

type KeyResolution = { key: string | null; canReset: boolean };

async function resolveContactsKey(api: AddressBookApi, attempt = 0): Promise<KeyResolution> {
  const [{ wraps }, { agents }] = await Promise.all([api.listContactKeys(), api.listAgents()]);

  let key: string | null = null;
  for (const wrap of wraps) {
    const privateKey = await getRecipientPrivateKey(wrap.agent_did);
    if (!privateKey) continue;
    try {
      key = await unwrapContactsKey(wrap.wrapped_key, privateKey);
      break;
    } catch {
      // try the next wrap
    }
  }

  if (key) {
    // Fill in agents that have no wrap yet (new agents, other devices).
    const wrapped = new Set(wraps.map((wrap) => wrap.agent_id));
    const missing = await wrapsFor(
      key,
      agents.filter((agent) => !wrapped.has(agent.id)),
    );
    if (missing.length > 0) {
      await api.addContactKeys({ wraps: missing }).catch(() => {
        // best effort; the next load tries again
      });
    }
    return { key, canReset: false };
  }

  // Only a device that can open the key later may start one.
  const holdsKey = await holdsAnyAgentKey(agents);
  if (wraps.length > 0 || !holdsKey) {
    return { key: null, canReset: wraps.length > 0 && holdsKey };
  }
  const fresh = generateContactsKey();
  const initial = await wrapsFor(fresh, agents);
  if (initial.length === 0) return { key: null, canReset: false };
  try {
    await api.addContactKeys({ wraps: initial, initial: true });
    return { key: fresh, canReset: false };
  } catch (error) {
    // Another device started the key first: open that one instead.
    if (error instanceof ApiError && error.status === 409 && attempt === 0) {
      return resolveContactsKey(api, attempt + 1);
    }
    throw error;
  }
}

function entry(record: ContactRecord, fields: ContactFields, readable: boolean): ContactEntry {
  return {
    id: record.id,
    did: record.did,
    ...fields,
    readable,
    created_at: record.created_at,
    updated_at: record.updated_at,
  };
}

export async function loadAddressBook(api: AddressBookApi): Promise<ContactsResponse> {
  const [{ contacts: records }, { key, canReset }] = await Promise.all([
    api.listContacts(),
    resolveContactsKey(api),
  ]);
  cachedKey = key;

  const contacts: ContactEntry[] = [];
  for (const record of records) {
    let opened: ContactFields | null = null;
    if (key) {
      try {
        opened = await openContactFields(key, record.did, record.sealed);
      } catch {
        // sealed under a key this device no longer has
      }
    }
    contacts.push(
      opened
        ? entry(record, opened, true)
        : entry(record, { person_name: "", agent_label: null, note: null }, false),
    );
  }

  if (key) rememberContactRoots(contacts);
  contacts.sort((a, b) => {
    if (a.readable !== b.readable) return a.readable ? -1 : 1;
    return (
      a.person_name.localeCompare(b.person_name, "ja") || a.created_at.localeCompare(b.created_at)
    );
  });
  return { contacts, keyState: key ? "ready" : "locked", canReset };
}

/** Seals a contact for saving, opening the key first if needed. */
export async function sealForSave(
  api: AddressBookApi,
  did: string,
  fields: ContactFields,
): Promise<string> {
  const key = cachedKey ?? (await resolveContactsKey(api)).key;
  if (!key) throw new ContactsLockedError();
  cachedKey = key;
  return sealContactFields(key, did, fields);
}

/** Drops every wrap so this device can start a new contacts key. */
/**
 * Wrap the contacts key to a browser being added (docs/40 §17.4), so it
 * opens the address book with its own key. Nothing when there is no
 * contacts key yet.
 */
export async function shareContactsKeyWithDevice(api: AddressBookApi, did: string, enc: string): Promise<void> {
  if (!api.addDeviceContactKey || !isValidX25519PublicKeyB64Url(enc)) return;
  const key = cachedKey ?? (await resolveContactsKey(api)).key;
  if (!key) return;
  cachedKey = key;
  await api.addDeviceContactKey({ did, wrapped_key: await wrapContactsKeyForAgent(key, enc) });
}

export async function resetContactsKey(api: AddressBookApi): Promise<void> {
  await api.resetContactKeys();
  cachedKey = null;
}

/** For tests. */
export function forgetContactsKey(): void {
  cachedKey = null;
}
