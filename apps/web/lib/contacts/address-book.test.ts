import { beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type {
  AddContactKeysRequest,
  Agent,
  ContactKeyWrap,
  ContactRecord,
} from "../api/types";
import { generateX25519KeyPairMaterial } from "../crypto/recipient-keyring";

// The keys "this device" holds, by agent DID.
const deviceKeys = new Map<string, CryptoKey>();
vi.mock("../crypto/recipient-keyring", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../crypto/recipient-keyring")>()),
  getRecipientPrivateKey: async (did: string) => deviceKeys.get(did) ?? null,
}));

const { forgetContactsKey, loadAddressBook, sealForSave } = await import("./address-book");

type AgentWithKey = Agent & { privateKey: CryptoKey };

async function makeAgent(name: string): Promise<AgentWithKey> {
  const pair = await generateX25519KeyPairMaterial();
  return {
    id: `agent-${name}`,
    aid: `aid:ai:${name}`,
    did: `did:key:z6Mk${name}`,
    label: name,
    encryption_key: pair.publicKey,
    is_active: true,
    auto_reply: false,
    unread_count: 0,
    created_at: "2026-11-07T00:00:00Z",
    privateKey: pair.privateKey,
  };
}

/** The server, as far as the address book can tell. */
class FakeServer {
  agents: AgentWithKey[] = [];
  wraps: ContactKeyWrap[] = [];
  contacts: ContactRecord[] = [];
  addCalls: AddContactKeysRequest[] = [];
  /** wraps another device adds just before ours (the race) */
  raceWith: ContactKeyWrap[] | null = null;

  async listContacts() {
    return { contacts: this.contacts.map((c) => ({ ...c })) };
  }
  async listContactKeys() {
    return { wraps: this.wraps.map((w) => ({ ...w })) };
  }
  async listAgents() {
    return { agents: this.agents };
  }
  async addContactKeys(payload: AddContactKeysRequest) {
    this.addCalls.push(payload);
    if (this.raceWith) {
      this.wraps.push(...this.raceWith);
      this.raceWith = null;
    }
    if (payload.initial && this.wraps.length > 0) {
      throw new ApiError("a contacts key already exists", 409);
    }
    for (const wrap of payload.wraps) {
      if (this.wraps.some((w) => w.agent_id === wrap.agent_id)) continue;
      const agent = this.agents.find((a) => a.id === wrap.agent_id)!;
      this.wraps.push({ agent_id: agent.id, agent_did: agent.did, wrapped_key: wrap.wrapped_key });
    }
  }
  async resetContactKeys() {
    this.wraps = [];
  }
}

function record(id: string, did: string, sealed: string): ContactRecord {
  return {
    id,
    did,
    sealed,
    created_at: "2026-11-01T00:00:00Z",
    updated_at: "2026-11-01T00:00:00Z",
  };
}

const name = (person_name: string) => ({ person_name, agent_label: null, note: "met at work" });

beforeEach(() => {
  deviceKeys.clear();
  forgetContactsKey();
});

describe("address book", () => {
  it("starts a key on a device with an agent key and wraps it for every agent", async () => {
    const server = new FakeServer();
    const [a, b] = [await makeAgent("A"), await makeAgent("B")];
    server.agents = [a, b];
    deviceKeys.set(a.did, a.privateKey);

    const book = await loadAddressBook(server);

    expect(book).toMatchObject({ keyState: "ready", contacts: [] });
    expect(server.addCalls[0].initial).toBe(true);
    expect(server.wraps.map((w) => w.agent_id).sort()).toEqual([a.id, b.id]);

    // What it saves holds no plaintext, and opens again on the next load.
    const sealed = await sealForSave(server, "did:key:z6MkBob", name("Bob"));
    expect(sealed).toMatch(/^cs1:/);
    expect(sealed).not.toContain("Bob");
    server.contacts = [record("c1", "did:key:z6MkBob", sealed)];
    forgetContactsKey();
    const reopened = await loadAddressBook(server);
    expect(reopened.contacts[0]).toMatchObject({ person_name: "Bob", note: "met at work", readable: true });
  });

  it("opens the same contacts on another device that holds a different agent's key", async () => {
    const server = new FakeServer();
    const [a, b] = [await makeAgent("A2"), await makeAgent("B2")];
    server.agents = [a, b];
    deviceKeys.set(a.did, a.privateKey);
    await loadAddressBook(server);
    server.contacts = [
      record("c1", "did:key:z6MkCarol", await sealForSave(server, "did:key:z6MkCarol", name("Carol"))),
    ];

    // Device 2 holds only B's key.
    deviceKeys.clear();
    forgetContactsKey();
    deviceKeys.set(b.did, b.privateKey);
    const book = await loadAddressBook(server);
    expect(book.keyState).toBe("ready");
    expect(book.contacts[0]).toMatchObject({ person_name: "Carol", readable: true });
  });

  it("stays locked on a device without agent keys, and never starts a key there", async () => {
    const server = new FakeServer();
    const a = await makeAgent("A3");
    server.agents = [a];
    deviceKeys.set(a.did, a.privateKey);
    const sealed = await sealForSave(server, "did:key:z6MkDave", {
      person_name: "Dave",
      agent_label: null,
      note: null,
    });
    server.contacts = [record("c1", "did:key:z6MkDave", sealed)];

    deviceKeys.clear();
    forgetContactsKey();
    const book = await loadAddressBook(server);
    expect(book).toMatchObject({ keyState: "locked", canReset: false });
    expect(book.contacts[0]).toMatchObject({ readable: false, person_name: "" });
    await expect(
      sealForSave(server, "did:key:z6MkErin", { person_name: "Erin", agent_label: null, note: null }),
    ).rejects.toThrow(/locked/);

    // A device with no agent key at all and no key yet starts nothing either.
    const empty = new FakeServer();
    empty.agents = [a];
    await expect(loadAddressBook(empty)).resolves.toMatchObject({ keyState: "locked" });
    expect(empty.addCalls).toHaveLength(0);
  });

  it("offers a reset to a device whose agent has no wrap, and fills in wraps once opened", async () => {
    const server = new FakeServer();
    const [a, c] = [await makeAgent("A4"), await makeAgent("C4")];
    server.agents = [a];
    deviceKeys.set(a.did, a.privateKey);
    await loadAddressBook(server);

    // A new agent C appears; a device holding only C cannot open the key yet.
    server.agents = [a, c];
    deviceKeys.clear();
    forgetContactsKey();
    deviceKeys.set(c.did, c.privateKey);
    await expect(loadAddressBook(server)).resolves.toMatchObject({
      keyState: "locked",
      canReset: true,
    });

    // The device holding A adds C's wrap on its next load; then C opens it.
    deviceKeys.set(a.did, a.privateKey);
    forgetContactsKey();
    await loadAddressBook(server);
    expect(server.addCalls.at(-1)?.wraps.map((w) => w.agent_id)).toEqual([c.id]);
    deviceKeys.delete(a.did);
    forgetContactsKey();
    await expect(loadAddressBook(server)).resolves.toMatchObject({ keyState: "ready" });
  });

  it("opens the other device's key when both start one at once", async () => {
    const server = new FakeServer();
    const a = await makeAgent("A5");
    server.agents = [a];
    deviceKeys.set(a.did, a.privateKey);

    // Another device wins the race with its own key for the same agent.
    const other = new FakeServer();
    other.agents = [a];
    await loadAddressBook(other);
    const sealedByOther = await sealForSave(other, "did:key:z6MkFrank", {
      person_name: "Frank",
      agent_label: null,
      note: null,
    });
    forgetContactsKey();
    server.raceWith = other.wraps;
    server.contacts = [record("c1", "did:key:z6MkFrank", sealedByOther)];

    const book = await loadAddressBook(server);
    expect(book.keyState).toBe("ready");
    expect(book.contacts[0]).toMatchObject({ person_name: "Frank", readable: true });
  });
});
