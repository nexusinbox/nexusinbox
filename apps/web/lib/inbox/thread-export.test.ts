import { describe, expect, it } from "vitest";
import { formatThreadExport, threadExportFileName } from "./thread-export";

describe("formatThreadExport", () => {
  const savedAt = new Date("2026-11-07T12:34:00Z");

  it("writes every message with its headers, body and A2A block", () => {
    const text = formatThreadExport({
      subject: "Sync",
      savedAt,
      notDecryptedNote: "(not decrypted)",
      messages: [
        {
          senderLabel: "Alice",
          senderDid: "did:key:zA",
          recipientLabel: "Bob",
          recipientDid: "did:key:zB",
          createdAt: "2026-11-01T09:00:00Z",
          subject: "Sync",
          body: "Can we meet?",
          protocol: { type: "schedule_negotiation", action: "propose" },
        },
        {
          senderLabel: "Bob",
          senderDid: "did:key:zB",
          recipientLabel: "Alice",
          recipientDid: "did:key:zA",
          createdAt: "2026-11-01T10:00:00Z",
          subject: "Re: Sync",
          body: null,
          protocol: { type: "schedule_negotiation", action: "accept" },
        },
      ],
    });
    expect(text.startsWith("NexusInbox: Sync\nSaved: 2026-11-07T12:34:00.000Z\n")).toBe(true);
    expect(text).toContain("From: Alice <did:key:zA>\nTo: Bob <did:key:zB>\nDate: 2026-11-01T09:00:00Z");
    expect(text).toContain("Can we meet?\n\nA2A:\n{\n  \"type\": \"schedule_negotiation\"");
    // An undecrypted body gets the note, and no structured data leaks.
    expect(text).toContain("Subject: Re: Sync\n\n(not decrypted)");
    expect(text).not.toContain("\"accept\"");
  });

  it("names the file by time only, never by subject", () => {
    expect(threadExportFileName(new Date(2026, 10, 7, 9, 5))).toBe("nexusinbox-thread-20261107-0905.txt");
  });
});
