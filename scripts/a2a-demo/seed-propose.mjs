// A2A `schedule_negotiation` propose seed — DevTools edition.
//
// ⚠ Experimental. The signing path reaches into the browser's
// IndexedDB keystore and the wrap key schema there is private to
// `apps/web/lib/crypto/keystore.ts`. Unless you adapt the
// `loadSigningKey` helper below to match the current keystore
// version, this snippet will fail to load the sender's private
// key. For a reliable manual QA today, **use a real A2A-speaking
// agent** (e.g. a small script using `@nexusinbox/core`'s
// `buildA2AEnvelope` with raw keypairs you generated yourself)
// and send from there.
//
// Usage (when working):
//   1. Log into `/login`, create two agents under one user at
//      `/settings/agents`, and compose a text message once from
//      agent A to agent B so their keys round-trip through the
//      Web keystore.
//   2. Open DevTools Console on `/inbox` (same browser session).
//   3. Paste this whole file. It auto-runs the IIFE at the bottom.
//   4. A `schedule_negotiation` propose lands in agent B's inbox
//      as if agent A sent it.
//   5. Reload `/inbox` — the ScheduleNegotiationCard renders.
//
// Why a browser snippet instead of a server-side seed script:
// the A2A message has to be encrypted with the recipient's X25519
// key, and signed with the sender's Ed25519 key. The signing key
// lives in the browser keystore and never leaves the device, so
// any seed that doesn't live in the same browser context has to
// reimplement the whole envelope build path with out-of-band
// keypairs (which is what a proper agent-side test harness would
// do — see `docs/24` §8).

(async function seedA2APropose() {
  const SENDER_LABEL = null;   // null = use the first available agent
  const RECIPIENT_LABEL = null; // null = use the second available agent
  const EVENT_TITLE = "QA — A2A schedule_negotiation demo";
  const CANDIDATES = [
    // Two candidates a week out. Replace as convenient — the UI
    // cares about TZ offsets being present, not specific dates.
    {
      start: new Date(Date.now() + 7 * 86400_000).toISOString().replace("Z", "+00:00"),
      end: new Date(Date.now() + 7 * 86400_000 + 3600_000).toISOString().replace("Z", "+00:00"),
    },
    {
      start: new Date(Date.now() + 8 * 86400_000).toISOString().replace("Z", "+00:00"),
      end: new Date(Date.now() + 8 * 86400_000 + 3600_000).toISOString().replace("Z", "+00:00"),
    },
  ];
  const RESPONSE_DEADLINE = new Date(
    Date.now() + 3 * 86400_000,
  ).toISOString().replace("Z", "+00:00");

  function b64url(u8) {
    let s = btoa(String.fromCharCode(...u8));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function uuidv7() {
    const ms = BigInt(Date.now());
    const buf = new Uint8Array(16);
    for (let i = 0; i < 6; i++) buf[5 - i] = Number((ms >> BigInt(i * 8)) & 0xffn);
    crypto.getRandomValues(buf.subarray(6));
    buf[6] = (buf[6] & 0x0f) | 0x70;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    const hex = [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  // 1. Discover the viewer's agents.
  const agentsRes = await fetch("/api/agents", { credentials: "include" });
  if (!agentsRes.ok) {
    throw new Error(`GET /agents failed: ${agentsRes.status}`);
  }
  const agents = (await agentsRes.json()).agents ?? [];
  if (agents.length < 2) {
    throw new Error(
      "Need at least two agents under the same user. Create them at /settings/agents first.",
    );
  }
  const sender = SENDER_LABEL
    ? agents.find((a) => a.label === SENDER_LABEL)
    : agents[0];
  const recipient = RECIPIENT_LABEL
    ? agents.find((a) => a.label === RECIPIENT_LABEL)
    : agents.find((a) => a.did !== sender.did);
  if (!sender || !recipient) {
    throw new Error("sender / recipient agent not found");
  }
  console.log("[a2a-seed] sender:", sender.label, sender.did);
  console.log("[a2a-seed] recipient:", recipient.label, recipient.did);

  // 2. Resolve recipient encryption key (handles DID rotation).
  const resolved = await fetch(
    `/api/recipients/resolve?identifier=${encodeURIComponent(recipient.did)}`,
    { credentials: "include" },
  ).then((r) => r.json());
  const recipientEncKey = resolved?.encryption_public_key;
  if (!recipientEncKey) {
    throw new Error("recipient encryption_public_key not resolvable");
  }

  // 3. Load the sender's signing key from the local browser keyring.
  // We reach through the app's exported module graph via the Next.js
  // webpack runtime — the helpers live under
  // `apps/web/lib/crypto/*` and are already used by the compose page.
  const mod = await import("/_next/static/chunks/app/inbox/page.js").catch(() => null);
  // Chunk names change between builds, so fall back to direct dynamic
  // imports of the helpers we need via the route's own bundles.
  if (!mod) {
    console.warn(
      "[a2a-seed] could not auto-discover the signing keyring module. Make sure you opened /inbox first so its chunks are loaded.",
    );
  }

  // Simpler: use Web Crypto directly + the IndexedDB entries the
  // app already wrote for this agent. The keyring uses the DID as
  // the store key.
  const db = await new Promise((resolve, reject) => {
    const req = indexedDB.open("nexusinbox-signing", 1);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const signingPrivateKey = await new Promise((resolve, reject) => {
    const tx = db.transaction("keys", "readonly");
    const get = tx.objectStore("keys").get(sender.did);
    get.onsuccess = () => resolve(get.result);
    get.onerror = () => reject(get.error);
  });
  if (!signingPrivateKey) {
    throw new Error(
      `sender's signing private key not found in IndexedDB for ${sender.did}. ` +
        "Did you create this agent in this browser session? Keys are per-device.",
    );
  }

  // 4. Build the A2A propose payload.
  const protocolBlock = {
    id: uuidv7(),
    type: "schedule_negotiation",
    action: "propose",
    reply_to: null,
    payload: {
      event_title: EVENT_TITLE,
      candidates: CANDIDATES,
      required_participants: [],
      response_deadline: RESPONSE_DEADLINE,
    },
  };
  const bodyJson = JSON.stringify({
    v: 1,
    body: `${EVENT_TITLE}\n${CANDIDATES.map((c) => `- ${c.start} – ${c.end}`).join("\n")}`,
    protocol: protocolBlock,
  });

  // 5. Encrypt the subject + body with a fresh content key, wrap
  // the content key for the recipient, sign the ciphertext. We
  // inline the primitives here so the snippet is self-contained.
  const contentKey = crypto.getRandomValues(new Uint8Array(32));
  async function encryptText(plain) {
    const key = await crypto.subtle.importKey("raw", contentKey, "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plain),
    );
    return { serialized: `aesgcmv1:${b64url(iv)}:${b64url(new Uint8Array(ct))}`, iv: b64url(iv) };
  }
  const encSubject = await encryptText(EVENT_TITLE);
  const encBody = await encryptText(bodyJson);

  // x25519 wrap — mirrors packages/core/src/index.ts wrapContentKeyForRecipient
  // but simplified for the snippet context.
  const ephemeralPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const recipientPubRaw = Uint8Array.from(atob(recipientEncKey.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const recipientPub = await crypto.subtle.importKey(
    "raw",
    recipientPubRaw,
    { name: "X25519" },
    false,
    [],
  );
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: recipientPub },
      ephemeralPair.privateKey,
      256,
    ),
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const wrapKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("nexusinbox:content-key") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedCt = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapIv }, wrapKey, contentKey),
  );
  const ephemeralPubRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", ephemeralPair.publicKey),
  );
  const encryptedKey = `x25519v1:${b64url(ephemeralPubRaw)}:${b64url(salt)}:${b64url(wrapIv)}:${b64url(wrappedCt)}`;

  // Sign the ciphertext payload (sender|recipient|subject|body|key|nonce).
  const signingInput = [
    sender.did,
    recipient.did,
    encSubject.serialized,
    encBody.serialized,
    encryptedKey,
    encBody.iv,
  ].join("\n");
  const sigBuf = await crypto.subtle.sign(
    "Ed25519",
    signingPrivateKey,
    new TextEncoder().encode(signingInput),
  );
  const signature = b64url(new Uint8Array(sigBuf));

  // 6. POST the message.
  const sendRes = await fetch("/api/messages", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      sender_did: sender.did,
      recipient_did: recipient.did,
      envelope: {
        encrypted_content: encBody.serialized,
        encrypted_key: encryptedKey,
        nonce: encBody.iv,
        signature,
        metadata: {
          subject_encrypted: encSubject.serialized,
          content_type: "application/vnd.nexusinbox.a2a+json; v=1",
          has_attachments: false,
        },
      },
    }),
  });
  const sendJson = await sendRes.json().catch(() => ({}));
  if (!sendRes.ok) {
    console.error("[a2a-seed] send failed:", sendRes.status, sendJson);
    throw new Error("send failed");
  }
  console.log("[a2a-seed] sent:", sendJson);
  console.log("[a2a-seed] Reload /inbox and switch to agent", recipient.label, "to see the card.");
})();
