// The commands a person runs to put an agent's keys in a signer daemon on
// their own machine (docs/19 §3, docs/31). The enrollment secret is never
// part of them: the daemon asks for it, so it stays out of shell history.
// A pairing code may be: it works once, for 10 minutes.

// The signer daemon calls the API directly, not the web's /api proxy.
// NEXT_PUBLIC_DAEMON_API_URL points the commands at another API, for local
// development; production leaves it unset.
const PRODUCTION_API_URL = "https://api.nexusinbox.ai";
const DAEMON_API_URL = process.env.NEXT_PUBLIC_DAEMON_API_URL || PRODUCTION_API_URL;

/**
 * The directory under ~/.nexusinbox that holds one agent's keys and
 * settings, named after the agent: lowercase letters, digits and dashes,
 * at most 32 characters (socket paths inside it must stay short).
 */
export function agentDirName(label: string, aid: string): string {
  const fromLabel = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32)
    .replace(/-+$/g, "");
  if (fromLabel) return fromLabel;
  return "agent-" + aid.replace(/^aid:ai:/, "").slice(-8).toLowerCase();
}

export function daemonEnrollCommand(credentialId: string, dirName: string): string {
  return [
    "nexusinbox-signer --enroll \\",
    `  --credential-id ${credentialId} \\`,
    `  --dir ~/.nexusinbox/${dirName} \\`,
    `  --api-url ${DAEMON_API_URL}`,
  ].join("\n");
}

/** Pair this machine with an agent and start it, in one command (docs/31). */
export function daemonConnectCommand(pairingCode: string): string {
  const command = `scripts/run_noninteractive_stack.sh connect ${pairingCode}`;
  return DAEMON_API_URL === PRODUCTION_API_URL ? command : `${command} ${DAEMON_API_URL}`;
}

export function daemonStartCommand(dirName: string): string {
  return `scripts/run_noninteractive_stack.sh start ~/.nexusinbox/${dirName}`;
}
