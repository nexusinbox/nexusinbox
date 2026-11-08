import { describe, expect, it } from "vitest";
import { agentDirName, daemonEnrollCommand, daemonStartCommand } from "./enroll-command";

describe("enroll command", () => {
  it("names the directory after the agent", () => {
    expect(agentDirName("enroll-test", "aid:ai:01M6W9J3TAQPHX7R3W591MMFYF")).toBe("enroll-test");
    expect(agentDirName("  First Secretary!  ", "aid:ai:X")).toBe("first-secretary");
    expect(agentDirName("a".repeat(40) + "-b", "aid:ai:X")).toBe("a".repeat(32));
  });

  it("falls back to the AID when the name has no usable characters", () => {
    expect(agentDirName("秘書", "aid:ai:01M6W9J3TAQPHX7R3W591MMFYF")).toBe("agent-591mmfyf");
  });

  it("puts everything in one directory and leaves the secret out", () => {
    const enroll = daemonEnrollCommand("ce027e55-c128-4f7c-b970-8f06ab4cf894", "enroll-test");
    expect(enroll).toContain("--credential-id ce027e55-c128-4f7c-b970-8f06ab4cf894");
    expect(enroll).toContain("--dir ~/.nexusinbox/enroll-test");
    expect(enroll).toContain("--api-url https://api.nexusinbox.ai");
    expect(enroll).not.toMatch(/ens_|secret/i);
    expect(daemonStartCommand("enroll-test")).toBe(
      "scripts/run_noninteractive_stack.sh start ~/.nexusinbox/enroll-test",
    );
  });
});
