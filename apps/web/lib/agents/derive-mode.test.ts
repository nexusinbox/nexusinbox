import { describe, expect, it } from "vitest";
import type { AgentCredential } from "../api/types";
import { deriveAgentMode } from "./derive-mode";

function cred(
  overrides: Partial<AgentCredential> & {
    aid?: string;
    status?: AgentCredential["status"];
    key_holder?: AgentCredential["key_holder"];
  } = {},
): AgentCredential {
  return {
    credential_id: overrides.credential_id ?? "cred-1",
    aid: overrides.aid ?? "aid:ai:01TEST",
    label: overrides.label ?? "test",
    status: overrides.status ?? "active",
    allowed_scopes: overrides.allowed_scopes ?? ["messages.read"],
    created_at: overrides.created_at ?? "2026-01-01T00:00:00Z",
    key_holder: overrides.key_holder,
    ...overrides,
  };
}

describe("deriveAgentMode", () => {
  const aid = "aid:ai:01TEST";

  it("returns 'standard' when any active credential is web_keystore", () => {
    expect(
      deriveAgentMode(aid, [cred({ key_holder: "web_keystore" })]),
    ).toBe("standard");
  });

  it("standard wins over signer_daemon when both are active", () => {
    // Documented priority — any web_keystore beats any signer_daemon
    // because the user CAN read in the browser via the local keystore.
    expect(
      deriveAgentMode(aid, [
        cred({ credential_id: "a", key_holder: "web_keystore" }),
        cred({ credential_id: "b", key_holder: "signer_daemon" }),
      ]),
    ).toBe("standard");
  });

  it("returns 'daemon_isolated' when any active credential is signer_daemon", () => {
    expect(
      deriveAgentMode(aid, [cred({ key_holder: "signer_daemon" })]),
    ).toBe("daemon_isolated");
  });

  it("returns 'daemon_isolated' for the mixed daemon + unknown case", () => {
    // Regression: the previous implementation used `every` instead of
    // `some` here, so the very common transition state (legacy MCP
    // --init credential tagged 'unknown' alongside a freshly
    // bootstrapped Isolated credential) silently fell through to
    // 'default' and the Bridge panel never appeared.
    expect(
      deriveAgentMode(aid, [
        cred({ credential_id: "old-mcp", key_holder: "unknown" }),
        cred({ credential_id: "isolated", key_holder: "signer_daemon" }),
      ]),
    ).toBe("daemon_isolated");
  });

  it("returns 'default' when only unknown credentials are active", () => {
    expect(deriveAgentMode(aid, [cred({ key_holder: "unknown" })])).toBe(
      "default",
    );
  });

  it("returns 'default' when no credentials are active", () => {
    expect(deriveAgentMode(aid, [])).toBe("default");
    expect(
      deriveAgentMode(aid, [
        cred({ status: "revoked", key_holder: "signer_daemon" }),
      ]),
    ).toBe("default");
  });

  it("ignores credentials belonging to a different aid", () => {
    expect(
      deriveAgentMode(aid, [
        cred({ aid: "aid:ai:OTHER", key_holder: "signer_daemon" }),
      ]),
    ).toBe("default");
  });

  it("ignores revoked credentials when computing mode", () => {
    expect(
      deriveAgentMode(aid, [
        cred({
          credential_id: "old",
          status: "revoked",
          key_holder: "web_keystore",
        }),
        cred({ credential_id: "new", key_holder: "signer_daemon" }),
      ]),
    ).toBe("daemon_isolated");
  });
});
