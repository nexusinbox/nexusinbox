// Plain-text export of a conversation, so people can keep what they want
// before the server deletes it 90 days after sending (docs/28 §4, §5 P2-7).
// Built from what this browser already decrypted; nothing is fetched again.

export type ExportMessage = {
  senderLabel: string;
  senderDid: string;
  recipientLabel: string;
  recipientDid: string;
  createdAt: string;
  subject: string;
  /** Decrypted body, or null when this device could not decrypt it. */
  body: string | null;
  /** Structured A2A block, if the message carried one. */
  protocol: unknown;
};

export type ThreadExportInput = {
  subject: string;
  savedAt: Date;
  messages: ExportMessage[];
  /** Line used in place of a body this device could not decrypt. */
  notDecryptedNote: string;
};

export function formatThreadExport(input: ThreadExportInput): string {
  const lines = [`NexusInbox: ${input.subject}`, `Saved: ${input.savedAt.toISOString()}`];
  for (const m of input.messages) {
    lines.push(
      "",
      "----------------------------------------",
      `From: ${m.senderLabel} <${m.senderDid}>`,
      `To: ${m.recipientLabel} <${m.recipientDid}>`,
      `Date: ${m.createdAt}`,
      `Subject: ${m.subject}`,
      "",
      m.body ?? input.notDecryptedNote,
    );
    if (m.body !== null && m.protocol) {
      lines.push("", "A2A:", JSON.stringify(m.protocol, null, 2));
    }
  }
  return lines.join("\n") + "\n";
}

/** File name without the subject, which may be sensitive. */
export function threadExportFileName(savedAt: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `nexusinbox-thread-${savedAt.getFullYear()}${pad(savedAt.getMonth() + 1)}${pad(savedAt.getDate())}` +
    `-${pad(savedAt.getHours())}${pad(savedAt.getMinutes())}.txt`
  );
}
