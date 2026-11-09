// node --test scripts/ct_watch.test.mjs
import assert from "node:assert/strict";
import test from "node:test";
import { findings, unexpected } from "./ct_watch.mjs";

const NOW = Date.parse("2026-11-09T06:00:00Z");
const cert = (names, ca, notBefore, sha = Math.random().toString(16).slice(2).padEnd(16, "0")) => ({
  dns_names: names,
  issuer: { friendly_name: ca },
  not_before: notBefore,
  cert_sha256: sha,
});

test("expected certificates pass", () => {
  assert.equal(unexpected(cert(["*.agent-inbox.ai", "agent-inbox.ai"], "Sectigo", "")), null);
  assert.equal(unexpected(cert(["*.agent-inbox.ai", "agent-inbox.ai"], "Google Trust Services", "")), null);
  assert.equal(unexpected(cert(["relay.agent-inbox.ai"], "Let's Encrypt", "")), null);
  assert.equal(unexpected(cert(["app.agent-inbox.ai"], "Let's Encrypt", "")), null);
  assert.equal(unexpected(cert(["vxf3r9rnba.mcp.agent-inbox.ai"], "Let's Encrypt", "")), null);
});

test("other names and CAs are flagged", () => {
  assert.match(unexpected(cert(["vxf3r9rnba.mcp.agent-inbox.ai"], "Sectigo", "")), /from Sectigo/);
  assert.match(unexpected(cert(["relay.agent-inbox.ai"], "Google Trust Services", "")), /from Google/);
  assert.match(unexpected(cert(["login.agent-inbox.ai"], "Let's Encrypt", "")), /unexpected names/);
  assert.match(unexpected(cert(["*.mcp.agent-inbox.ai"], "Let's Encrypt", "")), /unexpected names/);
  assert.match(unexpected(cert(["abc.mcp.agent-inbox.ai"], "Let's Encrypt", "")), /unexpected names/);
  assert.match(
    unexpected(cert(["vxf3r9rnba.mcp.agent-inbox.ai", "relay.agent-inbox.ai"], "Let's Encrypt", "")),
    /unexpected names/,
  );
  assert.match(unexpected(cert(["*.agent-inbox.ai"], "Unknown CA", "")), /zone certificate/);
});

test("only recent issuances are reported", () => {
  const all = [cert(["login.agent-inbox.ai"], "Let's Encrypt", "2026-10-01T00:00:00Z")];
  assert.equal(findings(all, NOW, 3).length, 0);
  assert.equal(findings(all, NOW, 60).length, 1);
});

test("a second certificate for one computer within 30 days is flagged", () => {
  const host = ["vxf3r9rnba.mcp.agent-inbox.ai"];
  const first = cert(host, "Let's Encrypt", "2026-10-20T00:00:00Z");
  const second = cert(host, "Let's Encrypt", "2026-11-08T00:00:00Z");
  const out = findings([first, second], NOW, 3);
  assert.equal(out.length, 1);
  assert.match(out[0].reason, /second certificate/);
  // A renewal two months later is normal.
  const old = cert(host, "Let's Encrypt", "2026-09-01T00:00:00Z");
  assert.equal(findings([old, second], NOW, 3).length, 0);
});

test("a burst of new computer certificates is flagged", () => {
  const all = Array.from({ length: 21 }, (_, i) =>
    cert([`abcdefghi${"abcdefghijkmnpqrstuvw"[i]}.mcp.agent-inbox.ai`], "Let's Encrypt", "2026-11-08T01:00:00Z"),
  );
  const out = findings(all, NOW, 3);
  assert.ok(out.some((f) => /21 computer certificates/.test(f.reason)), JSON.stringify(out.map((f) => f.reason)));
});
