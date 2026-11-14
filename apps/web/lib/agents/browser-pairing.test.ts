// A second browser (docs/40 §17.4): either side stops when the keys the
// server shows are not the ones the other browser MACed.

import { beforeEach, describe, expect, it, vi } from "vitest";

const { api, storeDeviceList, putPin } = vi.hoisted(() => ({
  api: {
    getBrowserPairing: vi.fn(),
    putBrowserPairingRoot: vi.fn(),
  },
  storeDeviceList: vi.fn(),
  putPin: vi.fn(),
}));
vi.mock("../api/client", () => ({
  defaultApiClient: api,
  ApiError: class ApiError extends Error {
    constructor(
      message: string,
      readonly status: number,
    ) {
      super(message);
    }
  },
}));
vi.mock("./device-list", () => ({
  approvedWith: () => new Set<string>(),
  checkDeviceList: async () => ({ kind: "ok", list: { devices: [] } }),
  listSignerHere: async () => "did:key:zRoot",
  storeDeviceList,
}));
vi.mock("./peer-pins", () => ({ savePin: putPin }));
vi.mock("../contacts/address-book", () => ({ shareContactsKeyWithDevice: async () => undefined }));

import { browserPairDeviceMac, browserPairRootMac } from "@nexusinbox/core/pairing";
import type { Agent, BrowserPairing } from "../api/types";
import { browserLabel, finishJoining, settleAddedBrowser, type Showing } from "./browser-pairing";

const SECRET = "8F3JV6WN2RCPZD4E";
const agent = { id: "a1", aid: "aid:ai:one", did: "did:key:zRoot", label: "secretary" } as Agent;
const pairing = (over: Partial<BrowserPairing>): BrowserPairing => ({
  id: "p1",
  aids: [agent.aid],
  label: "Safari (iPhone)",
  claimed: null,
  root_macs: null,
  expires_at: "2026-11-14T10:10:00Z",
  ...over,
});
const showing: Showing = {
  pairing: { id: "p1", expires_at: "2026-11-14T10:10:00Z" },
  secret: SECRET,
  link: "",
  code: "",
  agents: [agent],
};

beforeEach(() => {
  api.getBrowserPairing.mockReset();
  api.putBrowserPairingRoot.mockReset();
  storeDeviceList.mockReset();
  putPin.mockReset();
});

describe("a second browser (docs/40 §17.4)", () => {
  it("names browsers by their user agent", () => {
    expect(
      browserLabel(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      ),
    ).toBe("Safari (iPhone)");
    expect(
      browserLabel(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      ),
    ).toBe("Chrome (Mac)");
  });

  it("signs nothing when a key the server shows is not the one the new browser MACed", async () => {
    const mac = await browserPairDeviceMac(SECRET, "p1", agent.aid, "did:key:zPhone", "PHONE_ENC");
    // The server swapped the encryption key.
    api.getBrowserPairing.mockResolvedValue(
      pairing({
        claimed: [
          { aid: agent.aid, did: "did:key:zPhone", signing_public_key: "", encryption_public_key: "EVIL_ENC", mac },
        ],
      }),
    );
    expect(await settleAddedBrowser(showing)).toEqual({ kind: "mismatch" });
    expect(storeDeviceList).not.toHaveBeenCalled();
    expect(api.putBrowserPairingRoot).not.toHaveBeenCalled();
  });

  it("signs the new browser in and MACs the root back when the MACs hold", async () => {
    const mac = await browserPairDeviceMac(SECRET, "p1", agent.aid, "did:key:zPhone", "PHONE_ENC");
    api.getBrowserPairing.mockResolvedValue(
      pairing({
        claimed: [
          { aid: agent.aid, did: "did:key:zPhone", signing_public_key: "", encryption_public_key: "PHONE_ENC", mac },
        ],
      }),
    );
    expect(await settleAddedBrowser(showing)).toEqual({ kind: "done", label: "Safari (iPhone)" });
    expect(storeDeviceList.mock.calls[0][2]).toMatchObject([{ did: "did:key:zPhone", kind: "browser" }]);
    expect(api.putBrowserPairingRoot).toHaveBeenCalledWith("p1", [
      { aid: agent.aid, mac: await browserPairRootMac(SECRET, "p1", agent.aid, agent.did) },
    ]);
  });

  it("the new browser does not take a root the signing browser did not MAC", async () => {
    // The server names another root for the agent than the one MACed.
    const mac = await browserPairRootMac(SECRET, "p1", agent.aid, "did:key:zRoot");
    api.getBrowserPairing.mockResolvedValue(pairing({ root_macs: [{ aid: agent.aid, mac }] }));
    const result = await finishJoining({ id: "p1", secret: SECRET, aids: [agent.aid] }, [
      { ...agent, did: "did:key:zServerRoot" },
    ]);
    expect(result).toEqual({ kind: "mismatch" });
    expect(putPin).not.toHaveBeenCalled();
  });
});
