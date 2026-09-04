import { describe, expect, it } from "vitest";
import { NexusInboxApiClient, createDpopKeyPair } from "../src/index";

describe("NexusInboxApiClient path encoding", () => {
  it("percent-encodes ids so a crafted id cannot escape its route", async () => {
    const urls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      urls.push(String(input));
      return new Response(JSON.stringify({}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new NexusInboxApiClient({
      baseUrl: "https://app.nexusinbox.ai/api",
      accessToken: "agt_test_token",
      dpop: await createDpopKeyPair(),
      fetchImpl,
    });

    await client.readMessage("../auth/session?x=1");
    await client.completeAttachment({ attachmentId: "a/b", ciphertextSizeBytes: 1 });

    expect(urls).toEqual([
      "https://app.nexusinbox.ai/api/messages/..%2Fauth%2Fsession%3Fx%3D1/content",
      "https://app.nexusinbox.ai/api/attachments/a%2Fb/complete",
    ]);
  });
});
