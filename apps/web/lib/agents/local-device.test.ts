import { describe, expect, it } from "vitest";
import type { AgentDevice } from "../api/types";
import { readableElsewhere } from "./local-device";

const device = (did: string, kind: AgentDevice["kind"]): AgentDevice => ({ did, kind, activated_at: "2026-11-14T00:00:00Z" });

describe("where else a message can be read (docs/40 §17)", () => {
  it("names the other browsers, and says when a computer can too", () => {
    const devices = [device("root", "browser"), device("phone", "browser"), device("pc", "computer")];
    expect(readableElsewhere({ devices }, "root")).toEqual({ browsers: [devices[1]], computer: true });
    // A removed browser is not among the devices: every browser is "elsewhere".
    expect(readableElsewhere({ devices: devices.slice(1, 2) }, null)?.browsers).toEqual([devices[1]]);
  });

  it("is null when only computers can (the old text fits)", () => {
    expect(readableElsewhere({ devices: [device("root", "browser"), device("pc", "computer")] }, "root")).toBeNull();
    expect(readableElsewhere({ devices: [device("pc", "computer")] }, null)).toBeNull();
  });
});
