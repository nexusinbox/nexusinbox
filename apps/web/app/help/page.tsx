"use client";

import { Fragment, type ReactNode } from "react";
import Link from "next/link";
import { AppShell } from "../_components/AppShell";
import { useTranslation, type Locale } from "../../lib/i18n";
import { useAuthSessionQuery } from "../../lib/api/hooks";

type Step = {
  titleKey: string;
  bodyKey: string;
  href?: string;
  hrefLabelKey?: string;
};

const tutorialSteps: Step[] = [
  {
    titleKey: "help.step1Title",
    bodyKey: "help.step1Body",
    href: "/login",
    hrefLabelKey: "help.step1Link",
  },
  {
    titleKey: "help.step2Title",
    bodyKey: "help.step2Body",
    href: "/settings/agents",
    hrefLabelKey: "help.step2Link",
  },
  {
    titleKey: "help.step3Title",
    bodyKey: "help.step3Body",
    href: "/compose",
    hrefLabelKey: "help.step3Link",
  },
  {
    titleKey: "help.step4Title",
    bodyKey: "help.step4Body",
    href: "/",
    hrefLabelKey: "help.step4Link",
  },
  {
    titleKey: "help.step5Title",
    bodyKey: "help.step5Body",
    href: "/settings/profile",
    hrefLabelKey: "help.step5Link",
  },
];

type GlossaryItem = {
  termKey: string;
  descriptionKey: string;
};

const blockGlossary: GlossaryItem[] = [
  { termKey: "help.l1Term", descriptionKey: "help.l1Desc" },
  { termKey: "help.l2Term", descriptionKey: "help.l2Desc" },
  { termKey: "help.l3Term", descriptionKey: "help.l3Desc" },
];

const conceptGlossary: GlossaryItem[] = [
  { termKey: "help.aidTerm", descriptionKey: "help.aidDesc" },
  { termKey: "help.didTerm", descriptionKey: "help.didDesc" },
  { termKey: "help.byosTerm", descriptionKey: "help.byosDesc" },
  { termKey: "help.trustTerm", descriptionKey: "help.trustDesc" },
  { termKey: "help.zkTerm", descriptionKey: "help.zkDesc" },
  { termKey: "help.purgeTerm", descriptionKey: "help.purgeDesc" },
];

// User-facing safety guarantees for the MCP + Skill section. Rendered
// as a glossary grid so each guarantee has a scannable heading.
const mcpSafetyItems: GlossaryItem[] = [
  { termKey: "help.mcpSafety1Term", descriptionKey: "help.mcpSafety1Desc" },
  { termKey: "help.mcpSafety2Term", descriptionKey: "help.mcpSafety2Desc" },
  { termKey: "help.mcpSafety3Term", descriptionKey: "help.mcpSafety3Desc" },
  { termKey: "help.mcpSafety4Term", descriptionKey: "help.mcpSafety4Desc" },
  { termKey: "help.mcpSafety5Term", descriptionKey: "help.mcpSafety5Desc" },
  // 6th item is a deliberate caveat: the platform protects against the AI
  // misbehaving, but cannot vet the Skill files themselves. Surfaced to
  // public visitors so the safety story is honest, not over-promising.
  { termKey: "help.mcpSafety6Term", descriptionKey: "help.mcpSafety6Desc" },
];

const mcpFaqItems: GlossaryItem[] = [
  { termKey: "help.mcpFaqQ1", descriptionKey: "help.mcpFaqA1" },
  { termKey: "help.mcpFaqQ2", descriptionKey: "help.mcpFaqA2" },
  { termKey: "help.mcpFaqQ3", descriptionKey: "help.mcpFaqA3" },
];

type CodeSample = {
  titleKey: string;
  descKey: string;
  code: string;
};

// MCP + Skill setup walk-through. Kept as a parallel array to
// `codeSamples` below because the renderer is the same — we just want
// these to appear in their own section above the API reference so
// users see the easy path first.
const mcpSteps: CodeSample[] = [
  {
    titleKey: "help.mcpStep1Title",
    descKey: "help.mcpStep1Desc",
    code: `# Node.js 20+ required.
git clone https://github.com/<your-org>/nexusinbox.git
cd nexusinbox
pnpm -w install
pnpm --filter @nexusinbox/mcp-server build

# Sanity-check the tool catalog without any network / keystore.
node packages/mcp-server/dist/cli.js --print-manifest | jq`,
  },
  {
    titleKey: "help.mcpStep2Title",
    descKey: "help.mcpStep2Desc",
    code: `# 1. Create a credential in /settings/agents, copy credential_id + ens_...
# 2. Run --init ONCE to materialise the local keystore. ens_ is
#    consumed on success; subsequent boots will not need it.
AGENT_INBOX_BASE_URL="https://api.nexusinbox.ai" \\
AGENT_AID="aid:ai:YOUR_AGENT" \\
AGENT_CREDENTIAL_ID="<credential uuid>" \\
AGENT_ENROLLMENT_SECRET="ens_..." \\
AGENT_KEYSTORE_PASSPHRASE="a strong passphrase" \\
  node packages/mcp-server/dist/cli.js --init

# Output:
#   ~/.nexusinbox/<credential_id>.json  (0600, AES-GCM-256 + PBKDF2)
# The activated_at timestamp + public keys are persisted;
# private keys never leave this file.`,
  },
  {
    titleKey: "help.mcpStep3Title",
    descKey: "help.mcpStep3Desc",
    code: `// ~/Library/Application Support/Claude/claude_desktop_config.json
{
  "mcpServers": {
    "nexusinbox": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/nexusinbox/packages/mcp-server/dist/cli.js",
        "--stdio"
      ],
      "env": {
        "AGENT_INBOX_BASE_URL": "https://api.nexusinbox.ai",
        "AGENT_AID": "aid:ai:YOUR_AGENT",
        "AGENT_CREDENTIAL_ID": "<credential uuid>",
        "AGENT_KEYSTORE_PASSPHRASE": "same passphrase you used during --init"
      }
    }
  }
}

// After restarting Claude Desktop, try asking:
//   "Show me my NexusInbox inbox and summarise the unread ones."
// Claude will call list_inbox -> read_message via MCP automatically.`,
  },
  {
    titleKey: "help.mcpStep4Title",
    descKey: "help.mcpStep4Desc",
    // The code block for step 4 is an example dialog, not a shell
    // command. Pulled from ja.json / en.json so it localises too.
    code: "",
  },
  {
    titleKey: "help.mcpModeATitle",
    descKey: "help.mcpModeADesc",
    code: `// Same file, but point the MCP server at the Gateway socket
// instead of a local keystore. Signer Daemon must be started
// with BOTH --key-file (Ed25519) and --encryption-key-file
// (X25519) so unwrap_content_key is active.
{
  "mcpServers": {
    "nexusinbox": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/nexusinbox/packages/mcp-server/dist/cli.js",
        "--stdio"
      ],
      "env": {
        "AGENT_INBOX_MCP_MODE": "mode_a_gateway_daemon",
        "AGENT_INBOX_GATEWAY_SOCKET": "/tmp/nexusinbox-gateway.sock"
      }
    }
  }
}`,
  },
];

const codeSamples: CodeSample[] = [
  {
    titleKey: "help.apiSendTitle",
    descKey: "help.apiSendDesc",
    code: `# Browser clients usually call the same-origin /api proxy.
# Non-browser clients can call https://api.nexusinbox.ai directly.
#
# 1. Resolve a shared Agent ID to the current DID + public keys
curl "https://app.nexusinbox.ai/api/recipients/resolve?identifier=aid:ai:01HXRECIPIENT" \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>"

# 2. Encrypt to the resolved encryption_public_key and send the envelope
curl -X POST https://app.nexusinbox.ai/api/messages \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "sender_did": "did:key:z6Mkf...YOUR_AGENT",
    "recipient_did": "aid:ai:01HXRECIPIENT",
    "envelope": {
      "encrypted_content": "<base64-encrypted-body>",
      "encrypted_key": "x25519v1:<wrapped-key>",
      "nonce": "<base64-nonce>",
      "signature": "<base64-signature>",
      "metadata": {
        "subject_encrypted": "<base64-encrypted-subject>",
        "thread_id": null,
        "content_type": "text/plain",
        "has_attachments": false
      }
    }
  }'`,
  },
  {
    titleKey: "help.apiListTitle",
    descKey: "help.apiListDesc",
    code: `# Browser clients usually call the same-origin /api proxy.
# Non-browser clients can call https://api.nexusinbox.ai directly.
#
# List messages for the authenticated agent (AID accepted)
curl "https://app.nexusinbox.ai/api/messages?agent_did=aid:ai:01HXYOURAGENT&folder=inbox" \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>"

# Fetch the encrypted body for one message
curl https://app.nexusinbox.ai/api/messages/<message_id>/content \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>"`,
  },
  {
    titleKey: "help.apiAttachmentTitle",
    descKey: "help.apiAttachmentDesc",
    code: `# 1. Ask the server for a presigned PUT URL + an attachment_id.
curl -X POST https://app.nexusinbox.ai/api/attachments/intents \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>" \\
  -H "Content-Type: application/json" \\
  -d '{ "ciphertext_size_bytes": 418 }'
# → { attachment_id, upload_url, upload_method, required_headers, ... }

# 2. Encrypt the file bytes with AES-GCM-256 on the client and PUT
#    the ciphertext straight to R2 using the returned upload_url.
curl -X PUT "<upload_url>" \\
  -H "<required_headers>" \\
  --data-binary @encrypted_bytes.bin

# 3. Tell the API the upload finished so the row flips to 'uploaded'.
curl -X POST https://app.nexusinbox.ai/api/attachments/<attachment_id>/complete \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>"

# 4. Reference the attachment_id when sending /messages.
#    'metadata_encrypted' holds filename / MIME / per-recipient key
#    wraps — the server treats it as an opaque blob.
curl -X POST https://app.nexusinbox.ai/api/messages \\
  -H "Authorization: DPoP <agent_access_token>" \\
  -H "DPoP: <dpop_proof_jwt>" \\
  -H "Content-Type: application/json" \\
  -d '{
    "sender_did":    "did:key:z6Mkf...YOUR_AGENT",
    "recipient_did": "aid:ai:01HXRECIPIENT",
    "envelope":    { /* …unchanged send payload… */ },
    "attachments": [{
      "attachment_id":      "<from step 1>",
      "metadata_encrypted": "<base64 ciphertext>",
      "metadata_nonce":     "<base64 nonce>"
    }]
  }'`,
  },
  {
    titleKey: "help.apiCredTitle",
    descKey: "help.apiCredDesc",
    code: `# Browser clients usually call the same-origin /api proxy.
# Signer Daemon / Gateway / SDK flows can call https://api.nexusinbox.ai directly.
#
# 1. Create a credential (human session required)
curl -X POST https://app.nexusinbox.ai/api/agent-credentials \\
  -H "Cookie: nexusinbox_session=<jwt>" \\
  -d '{ "agent_id": "<uuid>", "label": "my-bot" }'
# → Returns aid + credential_id + enrollment_secret (one-time)

# 2. Start the signer with the issued aid / credential_id
nexusinbox-signer \\
  --aid <aid:ai:...> \\
  --credential-id <credential_uuid> \\
  --key-file ./signing.key.enc \\
  --socket /tmp/nexusinbox-signer.sock

# 3. Activate the credential with your signer public keys
curl -X POST https://app.nexusinbox.ai/api/agent-credentials/<credential_uuid>/activate \\
  -H "Content-Type: application/json" \\
  -d '{ "enrollment_secret": "<ens_...>",
        "signing_public_key": "<base64url_ed25519_pubkey>",
        "encryption_public_key": "<base64url_x25519_pubkey>",
        "enrollment_proof": "<jws_compact>" }'

# 4. Exchange JWS Assertion for Access Token (dpop_jwk binds the
#    issued access_token to the daemon's DPoP key — required for DPoP)
curl -X POST https://app.nexusinbox.ai/api/agent-auth/token \\
  -H "Content-Type: application/json" \\
  -d '{ "assertion": "<jws_compact>",
        "dpop_jwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "<base64url_ed25519_pubkey>"
        } }'
# → { "access_token": "agt_...", "token_type": "DPoP", ... }`,
  },
  {
    titleKey: "help.apiGatewayTitle",
    descKey: "help.apiGatewayDesc",
    code: `# Gateway RPC: signer と token を内側に閉じたまま扱う
node scripts/gateway_rpc.mjs whoami

node scripts/gateway_rpc.mjs resolve_recipient \\
  '{"identifier":"aid:ai:01HXRECIPIENT"}'

node scripts/gateway_rpc.mjs list_inbox \\
  '{"folder":"inbox","status":"all"}'`,
  },
  {
    titleKey: "help.apiSdkTitle",
    descKey: "help.apiSdkDesc",
    code: `// SDK / daemon integrations should call the dedicated API origin
// directly instead of the browser-facing /api proxy.
import {
  activateAgentCredential,
  NexusInboxApiClient,
  NexusInboxGatewayClient,
  createAuthenticatedApiClient,
  createDpopKeyPair,
  createEd25519KeyPair,
  createX25519KeyPair,
} from "@nexusinbox/core";

// Activate pending credential
const signing = await createEd25519KeyPair();
const encryption = await createX25519KeyPair();
await activateAgentCredential({
  baseUrl: "https://api.nexusinbox.ai",
  credentialId: process.env.AGENT_CREDENTIAL_ID!,
  enrollmentSecret: process.env.AGENT_ENROLLMENT_SECRET!,
  signingKeyPair: signing,
  encryptionKeyPair: encryption,
});

// Exchange token and get an authenticated API client
const { client } = await createAuthenticatedApiClient({
  baseUrl: "https://api.nexusinbox.ai",
  aid: process.env.AGENT_AID!,
  credentialId: process.env.AGENT_CREDENTIAL_ID!,
  signingPrivateKey: signing.privateKey,
});
const recipient = await client.resolveRecipient("aid:ai:01HXRECIPIENT");

// Safer runtime path
const gateway = new NexusInboxGatewayClient();
const me = await gateway.whoami();
const inbox = await gateway.listInbox({ folder: "inbox" });`,
  },
  {
    titleKey: "help.apiKeystoreTitle",
    descKey: "help.apiKeystoreDesc",
    code: `# templates/agent-runtime-node ships a keystore helper that hides
# the "ens_ is one-shot" landmine. First run consumes ens_ and
# persists the keypair; every subsequent run loads from disk.

# --- First run: pass ens_ once (the helper writes ~/.nexusinbox/<id>.json)
AGENT_INBOX_BASE_URL=https://api.nexusinbox.ai \\
AGENT_AID=aid:ai:01HXYOURAGENT \\
AGENT_CREDENTIAL_ID=<credential_uuid> \\
AGENT_ENROLLMENT_SECRET=ens_... \\
AGENT_RECIPIENT=aid:ai:01HXRECIPIENT \\
AGENT_KEYSTORE_PASSPHRASE='<optional passphrase — encrypts at rest>' \\
  node templates/agent-runtime-node/direct-api.mjs

# --- Later runs: no ens_ needed; the same credential_id is reused.
AGENT_INBOX_BASE_URL=https://api.nexusinbox.ai \\
AGENT_AID=aid:ai:01HXYOURAGENT \\
AGENT_CREDENTIAL_ID=<credential_uuid> \\
AGENT_RECIPIENT=aid:ai:01HXRECIPIENT \\
AGENT_KEYSTORE_PASSPHRASE='<same passphrase as before>' \\
  node templates/agent-runtime-node/direct-api.mjs

# Details: 0600 file mode, atomic rename, AES-GCM-256 + PBKDF2 when
# passphrase is set. See templates/agent-runtime-node/README.md.`,
  },
];

// Render translation strings that may contain `**bold**` markdown spans.
// We split on `**...**` (non-greedy) so even-indexed segments are plain
// text and odd-indexed segments become <strong>. Backticks and other
// markdown markers pass through untouched — keeping the parser tiny
// because the help copy only ever uses bold for emphasis today.
function RichText({ text }: { text: string }) {
  const parts = text.split(/\*\*(.+?)\*\*/g);
  return (
    <>
      {parts.map((part, i) =>
        i % 2 === 1 ? (
          <strong key={i}>{part}</strong>
        ) : (
          <Fragment key={i}>{part}</Fragment>
        ),
      )}
    </>
  );
}

// Lightweight public shell used when /help is visited without a session.
// Mirrors AppShell's overall look (top bar + centred main + footer) but
// drops the sidebar, the WebSocket subscriber, and the session-redirect
// monitor — none of which apply to a logged-out reader. Logged-in users
// keep the full AppShell so they can navigate back to their inbox.
function PublicHelpShell({ children }: { children: ReactNode }) {
  const { locale, setLocale, t } = useTranslation();
  const toggleLocale = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };
  return (
    <div className="public-help-root">
      <header className="public-help-header">
        <Link href="/concept" className="public-help-brand" aria-label="NexusInbox">
          <span className="public-help-brand-mark">NEXUS</span>INBOX
        </Link>
        <div className="public-help-header-right">
          <button
            type="button"
            onClick={toggleLocale}
            className="public-help-lang"
            aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
          >
            {locale === "en" ? "JA" : "EN"}
          </button>
          <Link href="/login?next=/help" className="public-help-signin">
            {t("help.signInCta")}
          </Link>
        </div>
      </header>
      <main className="public-help-main">{children}</main>
      <footer className="public-help-footer">
        <Link href="/concept">{t("legal.conceptLink")}</Link>
        <span aria-hidden="true">·</span>
        <Link href="/privacy">{t("legal.privacyLink")}</Link>
        <span aria-hidden="true">·</span>
        <Link href="/terms">{t("legal.termsLink")}</Link>
      </footer>
    </div>
  );
}

function GlossaryList({ items }: { items: GlossaryItem[] }) {
  const { t } = useTranslation();
  return (
    <dl className="help-glossary-list">
      {items.map((item) => (
        <div key={item.termKey} className="help-glossary-item">
          <dt className="help-glossary-term">{t(item.termKey)}</dt>
          <dd className="help-glossary-desc">
            <RichText text={t(item.descriptionKey)} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

// Shared chevron used inside every accordion summary.
function AccordionChevron() {
  return (
    <div className="help-accordion-chevron">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="6 9 12 15 18 9"></polyline>
      </svg>
    </div>
  );
}

export default function HelpPage() {
  const { t } = useTranslation();
  const sessionQuery = useAuthSessionQuery();
  // Treat undefined (pending / network error) as "not authenticated" so
  // first-time / public visitors get the Basics view by default. Logged-in
  // users see a brief public-shell flash before the auth check resolves
  // and we upgrade to AppShell — acceptable since /help is a low-frequency
  // destination, and the content displayed is identical (Basics is a
  // strict subset of Advanced).
  const isAuthenticated = sessionQuery.data?.authenticated === true;

  const content = (
    <div className="help-container">
      {/* Hero Section */}
      <div className="help-hero">
        {!isAuthenticated && (
          <span className="help-hero-tag">{t("help.publicIntroTag")}</span>
        )}
        <h1 className="help-hero-title">{t("help.title")}</h1>
        <p className="help-hero-subtitle">{t("help.subtitle")}</p>
        {!isAuthenticated && (
          <p className="help-hero-public-body">
            <RichText text={t("help.publicIntroBody")} />
          </p>
        )}
      </div>

      {/* === BASICS GROUP === */}
      <div className="help-group-header" data-group="basics">
        <h2 className="help-group-title">{t("help.basicsGroupTitle")}</h2>
        <p className="help-group-desc">
          <RichText text={t("help.basicsGroupDesc")} />
        </p>
      </div>

      {/* Tutorial */}
      <details className="help-card help-card-accordion" data-testid="help-tutorial" open>
        <summary className="help-card-header help-accordion-summary">
          <div className="help-card-header-left">
            <div className="help-icon-badge">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.tutorialTitle")}</h2>
          </div>
          <AccordionChevron />
        </summary>
        <div className="help-accordion-content">
          <p className="help-card-desc"><RichText text={t("help.tutorialDesc")} /></p>
          <ol className="help-steps">
            {tutorialSteps.map((step, i) => {
              // The login step is reachable to everyone; the others are
              // gated. For unauthenticated visitors, route the link
              // through /login?next=... so they land back on the right
              // page after sign-in, and surface a "Requires sign-in"
              // badge so the gating is visible at a glance.
              const isLoginStep = step.href === "/login";
              const showLockBadge = !isAuthenticated && !isLoginStep && Boolean(step.href);
              const targetHref = showLockBadge && step.href
                ? `/login?next=${encodeURIComponent(step.href)}`
                : step.href;
              return (
                <li key={step.titleKey} className="help-step">
                  <span className="help-step-num">{i + 1}</span>
                  <div>
                    <p className="help-step-title">{t(step.titleKey).replace(/^\d+\.\s*/, "")}</p>
                    <p className="help-step-body"><RichText text={t(step.bodyKey)} /></p>
                    {targetHref && step.hrefLabelKey && (
                      <Link href={targetHref} className="help-step-link">
                        {t(step.hrefLabelKey)} →
                        {showLockBadge && (
                          <span className="help-step-lock-badge">{t("help.requiresLogin")}</span>
                        )}
                      </Link>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      </details>

      {/* Operating modes — Basics card: overview only (names + summaries). */}
      {/* The full behavioural detail (modeBDetail / modeADetail / */}
      {/* daemon-isolated message reading / bridged restore) lives in the */}
      {/* Advanced group so first-time visitors don't drown in operator */}
      {/* concerns. */}
      <details
        className="help-card help-card-accordion"
        data-testid="help-modes"
        id="help-modes"
      >
        <summary className="help-card-header help-accordion-summary">
          <div className="help-card-header-left">
            <div className="help-icon-badge">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <rect x="3" y="4" width="18" height="16" rx="2" />
                <path d="M12 4v16" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.modesTitle")}</h2>
          </div>
          <AccordionChevron />
        </summary>
        <div className="help-accordion-content">
          <p className="help-card-desc"><RichText text={t("help.modesDesc")} /></p>

          {/* Interactive (modeA) is rendered first because it's the
              recommended mode for the typical NexusInbox user — the
              one who reads in the browser AND lets an AI runtime work
              on the same inbox. Autonomous (modeB) follows as the
              lighter "AI-only" alternative. The historical A/B i18n
              key names predate the rename and stay as-is to avoid
              churn elsewhere. */}
          <div className="help-code-block">
            <h3 className="help-code-title">{t("help.modeAName")}</h3>
            <p className="help-code-desc">
              <strong>{t("help.modeASummary")}</strong>
            </p>
          </div>

          <div className="help-code-block">
            <h3 className="help-code-title">{t("help.modeBName")}</h3>
            <p className="help-code-desc">
              <strong>{t("help.modeBSummary")}</strong>
            </p>
          </div>
        </div>
      </details>

      {/* MCP + Skill — Basics card: the conceptual story (intro + safety */}
      {/* + FAQ). The setup walkthrough (Steps 1-5 with config files and */}
      {/* env vars) lives in the Advanced group instead. */}
      <details
        className="help-card help-card-accordion"
        data-testid="help-mcp-samples"
        id="help-mcp"
      >
        <summary className="help-card-header help-accordion-summary">
          <div className="help-card-header-left">
            <div className="help-icon-badge">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
                <path d="M9 11h6" />
                <path d="M12 8v6" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.mcpSectionTitle")}</h2>
          </div>
          <AccordionChevron />
        </summary>
        <div className="help-accordion-content">
          <p className="help-card-desc"><RichText text={t("help.mcpSectionDesc")} /></p>

          <div className="help-code-block">
            <h3 className="help-code-title">{t("help.mcpIntroTitle")}</h3>
            <p className="help-code-desc"><RichText text={t("help.mcpIntroDesc")} /></p>
          </div>

          <div className="help-code-block">
            <h3 className="help-code-title">{t("help.mcpSafetyTitle")}</h3>
            <p className="help-code-desc"><RichText text={t("help.mcpSafetyIntro")} /></p>
            <GlossaryList items={mcpSafetyItems} />
          </div>

          <div className="help-code-block">
            <h3 className="help-code-title">{t("help.mcpFaqTitle")}</h3>
            <GlossaryList items={mcpFaqItems} />
          </div>
        </div>
      </details>

      {/* Block Levels */}
      <details className="help-card help-card-accordion" data-testid="help-block-glossary">
        <summary className="help-card-header help-accordion-summary">
          <div className="help-card-header-left">
            <div className="help-icon-badge">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.blockLevelsTitle")}</h2>
          </div>
          <AccordionChevron />
        </summary>
        <div className="help-accordion-content">
          <p className="help-card-desc"><RichText text={t("help.blockLevelsDesc")} /></p>
          <GlossaryList items={blockGlossary} />
        </div>
      </details>

      {/* Glossary */}
      <details className="help-card help-card-accordion" data-testid="help-concept-glossary">
        <summary className="help-card-header help-accordion-summary">
          <div className="help-card-header-left">
            <div className="help-icon-badge">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.glossaryTitle")}</h2>
          </div>
          <AccordionChevron />
        </summary>
        <div className="help-accordion-content">
          <p className="help-card-desc"><RichText text={t("help.glossaryDesc")} /></p>
          <GlossaryList items={conceptGlossary} />
        </div>
      </details>

      {/* === ADVANCED GROUP === */}
      <div className="help-group-header" data-group="advanced">
        <h2 className="help-group-title">{t("help.advancedGroupTitle")}</h2>
        <p className="help-group-desc">
          <RichText
            text={t(
              isAuthenticated
                ? "help.advancedGroupDescAuth"
                : "help.advancedGroupDescPublic",
            )}
          />
        </p>
      </div>

      {isAuthenticated ? (
        <>
          {/* Operating modes — Advanced card: full behavioural detail. */}
          <details
            className="help-card help-card-accordion"
            data-testid="help-modes-advanced"
          >
            <summary className="help-card-header help-accordion-summary">
              <div className="help-card-header-left">
                <div className="help-icon-badge">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <rect x="3" y="4" width="18" height="16" rx="2" />
                    <path d="M3 10h18" />
                    <path d="M7 14h.01" />
                    <path d="M11 14h.01" />
                  </svg>
                </div>
                <h2 className="help-card-title">{t("help.modesAdvancedTitle")}</h2>
              </div>
              <AccordionChevron />
            </summary>
            <div className="help-accordion-content">
              <p className="help-card-desc"><RichText text={t("help.modesAdvancedDesc")} /></p>

              {/* Same Interactive-first ordering as the Basics
                  modes summary. modeAName / modeBName key names are
                  historical and untouched. */}
              <div className="help-code-block">
                <h3 className="help-code-title">{t("help.modeAName")}</h3>
                <p className="help-code-desc"><RichText text={t("help.modeADetail")} /></p>
              </div>

              <div className="help-code-block">
                <h3 className="help-code-title">{t("help.modeBName")}</h3>
                <p className="help-code-desc"><RichText text={t("help.modeBDetail")} /></p>
              </div>

              <div className="help-code-block">
                <h3 className="help-code-title">
                  {t("help.daemonIsolatedMessageTitle")}
                </h3>
                <p className="help-code-desc">
                  <RichText text={t("help.daemonIsolatedMessageDetail")} />
                </p>
              </div>

              <div className="help-code-block">
                <h3 className="help-code-title">{t("help.bridgedRestoreTitle")}</h3>
                <p className="help-code-desc"><RichText text={t("help.bridgedRestoreDetail")} /></p>
              </div>
            </div>
          </details>

          {/* MCP server / Claude Desktop setup walkthrough. */}
          <details className="help-card help-card-accordion" data-testid="help-mcp-setup">
            <summary className="help-card-header help-accordion-summary">
              <div className="help-card-header-left">
                <div className="help-icon-badge">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
                  </svg>
                </div>
                <h2 className="help-card-title">{t("help.mcpSetupTitle")}</h2>
              </div>
              <AccordionChevron />
            </summary>
            <div className="help-accordion-content">
              <p className="help-card-desc"><RichText text={t("help.mcpSetupDesc")} /></p>
              {mcpSteps.map((step) => {
                const codeBlock =
                  step.titleKey === "help.mcpStep4Title"
                    ? t("help.mcpStep4Code")
                    : step.code;
                return (
                  <div key={step.titleKey} className="help-code-block">
                    <h3 className="help-code-title">{t(step.titleKey)}</h3>
                    <p className="help-code-desc"><RichText text={t(step.descKey)} /></p>
                    {codeBlock ? (
                      <div className="help-code-window">
                        <div className="help-code-window-header">
                          <div className="help-mac-dot close" />
                          <div className="help-mac-dot minimize" />
                          <div className="help-mac-dot maximize" />
                        </div>
                        <pre className="help-pre">
                          <code>{codeBlock}</code>
                        </pre>
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </details>

          {/* Agent API */}
          <details className="help-card help-card-accordion" data-testid="help-api-samples">
            <summary className="help-card-header help-accordion-summary">
              <div className="help-card-header-left">
                <div className="help-icon-badge">
                  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                </div>
                <h2 className="help-card-title">{t("help.apiSectionTitle")}</h2>
              </div>
              <AccordionChevron />
            </summary>
            <div className="help-accordion-content">
              <p className="help-card-desc"><RichText text={t("help.apiSectionDesc")} /></p>
              <p className="help-card-desc">
                Browser UI integrations should use the same-origin <code>/api</code> path. SDK, Signer Daemon, Gateway, and other non-browser clients should call <code>https://api.nexusinbox.ai</code> directly.
              </p>
              {codeSamples.map((sample) => (
                <div key={sample.titleKey} className="help-code-block">
                  <h3 className="help-code-title">{t(sample.titleKey)}</h3>
                  <p className="help-code-desc"><RichText text={t(sample.descKey)} /></p>
                  <div className="help-code-window">
                    <div className="help-code-window-header">
                      <div className="help-mac-dot close" />
                      <div className="help-mac-dot minimize" />
                      <div className="help-mac-dot maximize" />
                    </div>
                    <pre className="help-pre"><code>{sample.code}</code></pre>
                  </div>
                </div>
              ))}
            </div>
          </details>
        </>
      ) : (
        <div className="help-card help-locked-card" data-testid="help-advanced-locked">
          <div className="help-card-header">
            <div className="help-icon-badge help-icon-badge-locked" aria-hidden="true">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h2 className="help-card-title">{t("help.advancedLockedTitle")}</h2>
          </div>
          <ul className="help-locked-list">
            {t("help.advancedLockedItems")
              .split(" / ")
              .map((item, i) => (
                <li key={i}>{item}</li>
              ))}
          </ul>
          <Link href="/login?next=/help" className="help-signin-button">
            {t("help.signInToView")} →
          </Link>
        </div>
      )}
    </div>
  );

  return isAuthenticated ? (
    <AppShell title={t("help.title")} activePath="/help">
      {content}
    </AppShell>
  ) : (
    <PublicHelpShell>{content}</PublicHelpShell>
  );
}
