import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// token-store pulls in the IndexedDB-backed at-rest envelope; none of it
// is exercised by clearAllBridgeTokens, so stub it out to keep this a
// pure localStorage/sessionStorage test.
vi.mock("./at-rest", () => ({
  isWrappedBridgeToken: () => true,
  unwrapBridgeToken: async () => null,
  wrapBridgeToken: async (token: string) => token,
  BridgeSecureStorageUnavailableError: class extends Error {},
}));

import { clearAllBridgeTokens } from "./token-store";

class MemoryStorage implements Storage {
  private items = new Map<string, string>();
  get length(): number {
    return this.items.size;
  }
  key(index: number): string | null {
    return Array.from(this.items.keys())[index] ?? null;
  }
  getItem(key: string): string | null {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
  removeItem(key: string): void {
    this.items.delete(key);
  }
  clear(): void {
    this.items.clear();
  }
}

describe("clearAllBridgeTokens", () => {
  let localStorage: MemoryStorage;
  let sessionStorage: MemoryStorage;

  beforeEach(() => {
    localStorage = new MemoryStorage();
    sessionStorage = new MemoryStorage();
    vi.stubGlobal("window", { localStorage, sessionStorage });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("removes every bridge token and session nonce but nothing else", () => {
    localStorage.setItem("nexusinbox:bridge-token:aid:ai:one", "{}");
    localStorage.setItem("nexusinbox:bridge-token:aid:ai:two", "{}");
    localStorage.setItem("nexusinbox:locale", "ja");
    sessionStorage.setItem("nexusinbox:bridge-session-nonce:aid:ai:one", "nonce");
    sessionStorage.setItem("unrelated", "keep");

    clearAllBridgeTokens();

    expect(localStorage.getItem("nexusinbox:bridge-token:aid:ai:one")).toBeNull();
    expect(localStorage.getItem("nexusinbox:bridge-token:aid:ai:two")).toBeNull();
    expect(localStorage.getItem("nexusinbox:locale")).toBe("ja");
    expect(sessionStorage.getItem("nexusinbox:bridge-session-nonce:aid:ai:one")).toBeNull();
    expect(sessionStorage.getItem("unrelated")).toBe("keep");
  });

  it("is a no-op outside the browser", () => {
    vi.unstubAllGlobals();
    expect(() => clearAllBridgeTokens()).not.toThrow();
  });
});
