import { describe, expect, it } from "vitest";
import { deviceState, unseenDevices } from "./devices";
import type { AgentDevice } from "../api/types";

const device = (did: string, extra: Partial<AgentDevice> = {}): AgentDevice => ({
  did,
  kind: "computer",
  activated_at: "2026-11-12 09:00:00+00",
  ...extra,
});

describe("devices that can read an agent (docs/38 stage 4)", () => {
  it("reports nothing new the first time, then only devices not seen before", () => {
    const list = [device("did:key:zB", { kind: "browser" }), device("did:key:zPc")];
    expect(unseenDevices(list, null)).toEqual([]);
    expect(unseenDevices(list, ["did:key:zB", "did:key:zPc"])).toEqual([]);
    expect(unseenDevices(list, ["did:key:zB"]).map((d) => d.did)).toEqual(["did:key:zPc"]);
  });

  it("shows this browser's key as this device and computers by when they were heard from", () => {
    const now = Date.parse("2026-11-12T10:00:00Z");
    expect(deviceState(device("b", { kind: "browser" }), now, true)).toBe("this");
    expect(deviceState(device("b", { kind: "browser" }), now, false)).toBe("other");
    expect(deviceState(device("pc", { last_used_at: "2026-11-12 09:59:00+00" }), now, false)).toBe("connected");
    expect(deviceState(device("pc", { last_used_at: "2026-11-12 09:00:00+00" }), now, false)).toBe("silent");
  });
});
