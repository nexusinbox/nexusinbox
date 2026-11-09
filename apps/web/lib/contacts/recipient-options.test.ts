import { describe, expect, it } from "vitest";
import type { Agent, ContactEntry } from "../api/types";
import { buildRecipientOptions } from "./recipient-options";

const agent = (over: Partial<Agent>): Agent => ({
  id: "a1",
  aid: "aid:ai:one",
  did: "did:key:one",
  label: "秘書",
  is_active: true,
  auto_reply: false,
  unread_count: 0,
  created_at: "2026-11-01T00:00:00Z",
  ...over,
});

const contact = (over: Partial<ContactEntry>): ContactEntry => ({
  id: "c1",
  did: "did:key:yamada",
  person_name: "山田",
  agent_label: "秘書",
  note: null,
  readable: true,
  created_at: "2026-11-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z",
  ...over,
});

describe("buildRecipientOptions", () => {
  it("offers own agents by AID and contacts by DID", () => {
    expect(buildRecipientOptions([agent({})], [contact({})])).toEqual([
      { address: "aid:ai:one", label: "秘書", kind: "own", did: "did:key:one" },
      { address: "did:key:yamada", label: "山田(秘書)", kind: "contact", did: "did:key:yamada" },
    ]);
  });

  it("skips unreadable contacts and contacts that are own agents", () => {
    const options = buildRecipientOptions(
      [agent({ dids: ["did:key:one", "did:key:computer"] })],
      [
        contact({ did: "did:key:computer" }),
        contact({ id: "c2", did: "did:key:locked", readable: false }),
        contact({ id: "c3", did: "did:key:suzuki", person_name: "鈴木", agent_label: null }),
      ],
    );
    expect(options.map((o) => o.label)).toEqual(["秘書", "鈴木"]);
  });
});
