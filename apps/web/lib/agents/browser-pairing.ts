// Adding another browser of the person (docs/40 §17.4).
//
// The browser that can sign shows a link `/pair#<code>.<secret>`. The code
// goes to the server; the secret after `#` never does. The new browser
// makes its own keys for each agent, MACs them with the secret and sends
// them with proof it holds them. The browser that showed the link checks
// the MACs against the keys the server shows, signs them into each agent's
// device list as signers, wraps the contacts key for them, and MACs each
// agent's root back. The new browser checks those MACs before it trusts
// the root, so the server can swap neither side's keys.

import { didKeyFromEd25519 } from "@nexusinbox/core/device-list";
import {
  browserPairDeviceMac,
  browserPairFragment,
  browserPairRootMac,
  generatePairingSecret,
  longPairingCode,
  macEqual,
  parseBrowserPairFragment,
} from "@nexusinbox/core/pairing";
import { ApiError, defaultApiClient } from "../api/client";
import type { Agent, AgentDevice, BrowserPairing, BrowserPairingKey } from "../api/types";
import { shareContactsKeyWithDevice } from "../contacts/address-book";
import { fromBase64Url, toBase64Url } from "../crypto/keystore";
import { generateX25519KeyPairMaterial, storeRecipientPrivateKey } from "../crypto/recipient-keyring";
import { generateEd25519SigningKeyPairMaterial, storeSigningPrivateKey } from "../crypto/signing-keyring";
import { approvedWith, checkDeviceList, listSignerHere, storeDeviceList } from "./device-list";
import { savePin } from "./peer-pins";

/** Signed over by each new key, as the server checks it. */
const PROOF_PREFIX = "nexusinbox-browser-pair-v1\n";

/** A short name for this browser, from its user agent ("Safari (iPhone)"). */
export function browserLabel(userAgent: string): string {
  const browser = /Edg\//.test(userAgent)
    ? "Edge"
    : /Firefox\//.test(userAgent)
      ? "Firefox"
      : /Chrome\//.test(userAgent)
        ? "Chrome"
        : /Safari\//.test(userAgent)
          ? "Safari"
          : "Browser";
  const os = /iPhone/.test(userAgent)
    ? "iPhone"
    : /iPad/.test(userAgent)
      ? "iPad"
      : /Android/.test(userAgent)
        ? "Android"
        : /Mac OS X|Macintosh/.test(userAgent)
          ? "Mac"
          : /Windows/.test(userAgent)
            ? "Windows"
            : /Linux/.test(userAgent)
              ? "Linux"
              : null;
  return os ? `${browser} (${os})` : browser;
}

// ---------------------------------------------------------------------------
// The browser that can sign.

export type Showing = {
  pairing: { id: string; expires_at: string };
  secret: string;
  /** What the QR code and "copy" carry. */
  link: string;
  /** The same, for typing on another computer. */
  code: string;
  /** The agents the new browser is added to. */
  agents: Agent[];
};

/** The agents this browser may sign the list of: the new browser joins them all. */
export async function signableAgents(agents: Agent[]): Promise<Agent[]> {
  const out: Agent[] = [];
  for (const agent of agents) if ((await listSignerHere(agent)) !== null) out.push(agent);
  return out;
}

export async function startAddingBrowser(agents: Agent[], origin: string): Promise<Showing> {
  const pairing = await defaultApiClient.createBrowserPairing(agents.map((a) => a.aid));
  const secret = generatePairingSecret();
  return {
    pairing,
    secret,
    link: `${origin}/pair#${browserPairFragment(pairing.code, secret)}`,
    code: longPairingCode(pairing.code, secret),
    agents,
  };
}

export type Settled =
  /** The new browser has not sent its keys yet. */
  | { kind: "waiting" }
  /** Added to every agent. */
  | { kind: "done"; label: string | null }
  /** A key the server shows is not one the new browser MACed: nothing signed. */
  | { kind: "mismatch" }
  /** The server wants a recent World ID sign-in to change the signers. */
  | { kind: "reauth" }
  | { kind: "expired" };

/**
 * Check the new browser's keys and, when every MAC holds, sign them into
 * each agent's list, share the contacts key and MAC each root back.
 */
export async function settleAddedBrowser(showing: Showing): Promise<Settled> {
  let pairing: BrowserPairing;
  try {
    pairing = await defaultApiClient.getBrowserPairing(showing.pairing.id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return { kind: "expired" };
    throw error;
  }
  const claimed = pairing.claimed;
  if (!claimed) return { kind: "waiting" };
  if (pairing.root_macs) return { kind: "done", label: pairing.label };

  for (const agent of showing.agents) {
    const keys = claimed.filter((k) => k.aid === agent.aid);
    if (keys.length !== 1) return { kind: "mismatch" };
    const [key] = keys;
    const mac = await browserPairDeviceMac(showing.secret, pairing.id, agent.aid, key.did, key.encryption_public_key);
    if (!macEqual(mac, key.mac)) return { kind: "mismatch" };
  }

  const roots: Array<{ aid: string; mac: string }> = [];
  for (const agent of showing.agents) {
    const key = claimed.find((k) => k.aid === agent.aid) as BrowserPairingKey;
    const status = await checkDeviceList(agent);
    const device: AgentDevice = {
      did: key.did,
      encryption_public_key: key.encryption_public_key,
      kind: "browser",
      label: pairing.label,
      activated_at: new Date().toISOString(),
    };
    try {
      await storeDeviceList(agent, approvedWith(agent, status, [key.did]), [device]);
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) return { kind: "reauth" };
      throw error;
    }
    roots.push({ aid: agent.aid, mac: await browserPairRootMac(showing.secret, pairing.id, agent.aid, agent.did) });
  }
  // The new browser opens the address book with its own wrap. Best effort:
  // it can still read and send without one.
  for (const key of claimed) {
    await shareContactsKeyWithDevice(defaultApiClient, key.did, key.encryption_public_key).catch(() => undefined);
  }
  await defaultApiClient.putBrowserPairingRoot(pairing.id, roots);
  return { kind: "done", label: pairing.label };
}

// ---------------------------------------------------------------------------
// The new browser.

export type Joining = { id: string; secret: string; aids: string[] };

/** Find the pairing a link or a typed code names (same person, not expired). */
export async function findPairing(raw: string): Promise<Joining | null> {
  const parsed = parseBrowserPairFragment(raw);
  if (!parsed) return null;
  const pairing = await defaultApiClient.resolveBrowserPairing(parsed.code);
  return { id: pairing.id, secret: parsed.secret, aids: pairing.aids };
}

/** Make this browser's keys for each agent, keep them here, and send them. */
export async function joinPairing(joining: Joining, label: string): Promise<void> {
  const devices: Array<BrowserPairingKey & { proof: string }> = [];
  for (const aid of joining.aids) {
    const signing = await generateEd25519SigningKeyPairMaterial();
    const encryption = await generateX25519KeyPairMaterial();
    const did = didKeyFromEd25519(fromBase64Url(signing.publicKey));
    await storeSigningPrivateKey(did, signing.privateKey);
    await storeRecipientPrivateKey(did, encryption.privateKey);
    const proofInput = `${PROOF_PREFIX}${joining.id}\n${aid}\n${did}\n${encryption.publicKey}`;
    const proof = new Uint8Array(
      await crypto.subtle.sign("Ed25519", signing.privateKey, new TextEncoder().encode(proofInput)),
    );
    devices.push({
      aid,
      did,
      signing_public_key: signing.publicKey,
      encryption_public_key: encryption.publicKey,
      mac: await browserPairDeviceMac(joining.secret, joining.id, aid, did, encryption.publicKey),
      proof: toBase64Url(proof),
    });
  }
  await defaultApiClient.claimBrowserPairing(joining.id, { label, devices });
}

export type Joined =
  | { kind: "waiting" }
  | { kind: "done" }
  /** A root the server shows is not the one the other browser MACed. */
  | { kind: "mismatch" }
  | { kind: "expired" };

/**
 * Once the other browser has signed: check each agent's root against its
 * MAC, remember it, and check the list (followed from version 1) names
 * this browser.
 */
export async function finishJoining(joining: Joining, agents: Agent[]): Promise<Joined> {
  let pairing: BrowserPairing;
  try {
    pairing = await defaultApiClient.getBrowserPairing(joining.id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return { kind: "expired" };
    throw error;
  }
  if (!pairing.root_macs) return { kind: "waiting" };
  for (const aid of joining.aids) {
    const agent = agents.find((a) => a.aid === aid);
    const sent = pairing.root_macs.find((r) => r.aid === aid);
    if (!agent || !sent) return { kind: "mismatch" };
    const mac = await browserPairRootMac(joining.secret, joining.id, aid, agent.did);
    if (!macEqual(mac, sent.mac)) return { kind: "mismatch" };
    // The root, from the browser that signed; the list is followed from it.
    savePin(aid, { root: agent.did, version: 0 });
    const status = await checkDeviceList(agent);
    const own = pairing.claimed?.find((k) => k.aid === aid)?.did;
    if (status.kind !== "ok" || !status.list.devices.some((d) => d.did === own)) return { kind: "mismatch" };
  }
  return { kind: "done" };
}
