// What this browser remembers of each agent's device list (docs/40 §12.4):
// the root that signs it and the newest version seen. Senders stop when
// a list comes back signed by another root or older than one seen.
//
// Kept per browser in localStorage. For agents in the person's contacts
// the root is also sealed into the contact, so the person's other
// browsers remember the same root; the contacts are read through
// `rememberContactRoots` whenever the address book is opened.

import type { DevicePin } from "@nexusinbox/core/device-list";
import type { ContactEntry } from "../api/types";

const pinKey = (aid: string) => `nexusinbox.devicelist.pin.${aid}`;
// Stage 1 kept only the newest version seen, for the person's own agents.
const legacySeenKey = (aid: string) => `nexusinbox.devicelist.version.${aid}`;

function parsePin(raw: string | null): DevicePin | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    if (typeof value.root !== "string" || !value.root.startsWith("did:key:")) return null;
    const version = Number(value.version);
    return { root: value.root, version: Number.isSafeInteger(version) && version > 0 ? version : 0 };
  } catch {
    return null;
  }
}

/**
 * The pin for `aid`. `ownRoot` is the root of one of the person's own
 * agents: a version stage 1 remembered without a root is read as that
 * root's.
 */
export function loadPin(aid: string, ownRoot?: string): DevicePin | null {
  try {
    const pin = parsePin(window.localStorage.getItem(pinKey(aid)));
    if (pin) return pin;
    if (!ownRoot) return null;
    const legacy = Number(window.localStorage.getItem(legacySeenKey(aid)));
    return Number.isSafeInteger(legacy) && legacy > 0 ? { root: ownRoot, version: legacy } : null;
  } catch {
    return null;
  }
}

export function savePin(aid: string, pin: DevicePin): void {
  try {
    window.localStorage.setItem(pinKey(aid), JSON.stringify(pin));
    window.localStorage.removeItem(legacySeenKey(aid));
  } catch {
    // Storage blocked: this browser cannot notice changes, as before.
  }
}

// Agents seen signing with v2 (docs/40 §15.2): a message from them without
// a signature is a warning, as the server may have stripped it.
const signerKey = (aid: string) => `nexusinbox.devicelist.signed.${aid}`;

export function rememberSigner(aid: string): void {
  try {
    window.localStorage.setItem(signerKey(aid), "1");
  } catch {
    // Storage blocked: such messages keep the quiet old-format note.
  }
}

export function knownSigner(aid: string): boolean {
  try {
    return window.localStorage.getItem(signerKey(aid)) === "1";
  } catch {
    return false;
  }
}

// A DID belongs to one agent for good. Remember which, so a server that
// moves a DID to another agent is noticed (docs/40 §12.3).
const didAidKey = (did: string) => `nexusinbox.devicelist.didaid.${did}`;

export function rememberDidAid(did: string, aid: string): void {
  try {
    window.localStorage.setItem(didAidKey(did), aid);
  } catch {
    // Storage blocked.
  }
}

/** The agent `did` was seen under before (here or in the person's contacts). */
export function knownAidFor(did: string): string | null {
  const fromContact = contactsByDid.get(did)?.aid;
  if (fromContact) return fromContact;
  try {
    return window.localStorage.getItem(didAidKey(did));
  } catch {
    return null;
  }
}

// Contacts that carry a sealed agent, as last opened on this page.
let contactsByAid = new Map<string, ContactEntry>();
let contactsByDid = new Map<string, ContactEntry>();
let contactsLoaded = false;

export function rememberContactRoots(contacts: ContactEntry[]): void {
  const byAid = new Map<string, ContactEntry>();
  const byDid = new Map<string, ContactEntry>();
  for (const c of contacts) {
    if (!c.readable || !c.aid) continue;
    byAid.set(c.aid, c);
    byDid.set(c.did, c);
  }
  contactsByAid = byAid;
  contactsByDid = byDid;
  contactsLoaded = true;
}

export function contactsOpened(): boolean {
  return contactsLoaded;
}

/** The contact for `aid`, if the person keeps one. */
export function contactForAid(aid: string): ContactEntry | undefined {
  return contactsByAid.get(aid);
}

/** For tests. */
export function forgetContactRoots(): void {
  contactsByAid = new Map();
  contactsByDid = new Map();
  contactsLoaded = false;
}
