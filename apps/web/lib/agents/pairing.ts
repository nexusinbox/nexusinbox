// Connect code secrets (docs/40 §13.5). The browser that shows a connect
// code makes a secret only it and the computer know. The computer MACs its
// keys with it when it activates; this browser checks that MAC against the
// keys the server shows before approving the computer into the signed
// list, then MACs the agent's root back for the computer.
//
// The secret is kept as a non-extractable HMAC key in this browser's
// keystore (IndexedDB), per credential, until the computer is approved or
// turns out not to match. What is waiting or did not match is noted in
// localStorage, so a notice survives a reload.

import {
  generatePairingSecret,
  importPairingKey,
  longPairingCode,
  macEqual,
  pairingDeviceMac,
  pairingRootMac,
} from "@nexusinbox/core/pairing";
import { defaultApiClient } from "../api/client";
import type { Agent, AgentDevice } from "../api/types";
import { secureDeleteKey, secureLoadKey, secureStoreKey } from "../crypto/keystore";
import { approvalOf, approvedWith, checkDeviceList, listSignerHere, storeDeviceList } from "./device-list";

type PairingNote = {
  aid: string;
  state: "waiting" | "mismatch";
  /** The DID the server showed for the computer, when it did not match. */
  did?: string;
  at: number;
};

const noteKey = (credentialId: string) => `nexusinbox.pairing.${credentialId}`;
const keyId = (credentialId: string) => `pairing:${credentialId}`;
const NOTE_PREFIX = "nexusinbox.pairing.";
// A code works for 10 minutes; a computer that has not shown up in an hour
// never will.
const WAITING_MS = 60 * 60 * 1000;

function readNote(credentialId: string): PairingNote | null {
  try {
    const value = JSON.parse(window.localStorage.getItem(noteKey(credentialId)) ?? "null") as PairingNote | null;
    return value && typeof value.aid === "string" ? value : null;
  } catch {
    return null;
  }
}

function writeNote(credentialId: string, note: PairingNote): void {
  try {
    window.localStorage.setItem(noteKey(credentialId), JSON.stringify(note));
  } catch {
    // Storage blocked: the computer falls back to being approved by hand.
  }
}

async function forget(credentialId: string): Promise<void> {
  try {
    window.localStorage.removeItem(noteKey(credentialId));
  } catch {
    // ignore
  }
  await secureDeleteKey(keyId(credentialId)).catch(() => undefined);
}

/**
 * Make a secret for a fresh pairing code and keep it for the credential.
 * Returns the code to show, or null when this browser cannot keep it
 * (the short code still works; the computer is then approved by hand).
 */
export async function pairingCodeWithSecret(credentialId: string, aid: string, code: string): Promise<string | null> {
  try {
    const secret = generatePairingSecret();
    await secureStoreKey(keyId(credentialId), await importPairingKey(secret));
    writeNote(credentialId, { aid, state: "waiting", at: Date.now() });
    return longPairingCode(code, secret);
  } catch {
    return null;
  }
}

/** Whether this browser made the connect code `device` was connected with. */
export function pairedHere(device: AgentDevice): boolean {
  return !!device.credential_id && readNote(device.credential_id) !== null;
}

/** A computer whose keys did not match its connect code here. */
export function pairingMismatch(device: AgentDevice): boolean {
  if (!device.credential_id) return false;
  const note = readNote(device.credential_id);
  return note?.state === "mismatch" && (!note.did || note.did === device.did);
}

export type PairingCheck = {
  /** Computers whose keys match the code made here: approve them. */
  matched: AgentDevice[];
  /** Computers whose keys the server shows differently. */
  mismatched: AgentDevice[];
};

/** Check the agent's computers connected with a code this browser made. */
export async function checkPairedDevices(agent: Agent): Promise<PairingCheck> {
  const matched: AgentDevice[] = [];
  const mismatched: AgentDevice[] = [];
  const devices = agent.devices ?? [];
  for (const device of devices) {
    const credentialId = device.credential_id;
    if (!credentialId) continue;
    const note = readNote(credentialId);
    if (!note || note.aid !== agent.aid) continue;
    if (note.state === "mismatch") {
      if (pairingMismatch(device)) mismatched.push(device);
      continue;
    }
    const key = await secureLoadKey(keyId(credentialId)).catch(() => null);
    if (!key) {
      // The secret is gone from this browser: approve by hand as before.
      await forget(credentialId);
      continue;
    }
    const expected =
      device.encryption_public_key && (await pairingDeviceMac(key, credentialId, device.did, device.encryption_public_key));
    if (expected && device.pairing_mac && macEqual(expected, device.pairing_mac)) {
      matched.push(device);
    } else {
      // A computer connected with a code made here always sends a MAC, so
      // a missing one is as wrong as a different one.
      writeNote(credentialId, { aid: agent.aid, state: "mismatch", did: device.did, at: Date.now() });
      await secureDeleteKey(keyId(credentialId)).catch(() => undefined);
      mismatched.push(device);
    }
  }
  forgetStale(agent, devices);
  return { matched, mismatched };
}

/** Notes for computers that were removed, or never connected. */
function forgetStale(agent: Agent, devices: AgentDevice[]): void {
  const present = new Set(devices.map((d) => d.credential_id).filter(Boolean));
  let keys: string[] = [];
  try {
    keys = Object.keys(window.localStorage).filter((k) => k.startsWith(NOTE_PREFIX));
  } catch {
    return;
  }
  for (const k of keys) {
    const credentialId = k.slice(NOTE_PREFIX.length);
    const note = readNote(credentialId);
    if (!note || note.aid !== agent.aid || present.has(credentialId)) continue;
    if (note.state === "mismatch" || Date.now() - note.at > WAITING_MS) void forget(credentialId);
  }
}

/**
 * After approving a matched computer: give it the agent's root, MACed with
 * the secret, then forget the secret.
 */
export async function finishPairing(agent: Agent, device: AgentDevice): Promise<void> {
  const credentialId = device.credential_id;
  if (!credentialId) return;
  const key = await secureLoadKey(keyId(credentialId));
  if (!key) return;
  const mac = await pairingRootMac(key, credentialId, agent.aid, agent.did);
  await defaultApiClient.putPairingRoot(credentialId, mac);
  await forget(credentialId);
}

/**
 * Check the agent's paired computers and, in the browser that holds the
 * root key, approve the matching ones into the signed list and give them
 * the root. `changed` when a new list was stored.
 */
export async function settlePairing(agent: Agent): Promise<PairingCheck & { changed: boolean }> {
  const check = await checkPairedDevices(agent);
  let changed = false;
  if (check.matched.length === 0 || (await listSignerHere(agent)) === null) return { ...check, changed };
  const status = await checkDeviceList(agent);
  if (status.kind === "broken") return { ...check, changed };
  const missing = check.matched.filter((d) => status.kind !== "ok" || approvalOf(d, status) !== "approved");
  if (missing.length > 0) {
    await storeDeviceList(
      agent,
      approvedWith(
        agent,
        status,
        missing.map((d) => d.did),
      ),
    );
    changed = true;
  }
  for (const device of check.matched) await finishPairing(agent, device).catch(() => undefined);
  return { ...check, changed };
}
