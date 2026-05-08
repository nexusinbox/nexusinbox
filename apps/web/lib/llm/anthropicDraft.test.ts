import { describe, expect, it, vi } from "vitest";
import {
  AnthropicDraftError,
  generateReplyDraft,
  type GenerateReplyDraftInput,
} from "./anthropicDraft";

function mockFetch(response: {
  ok?: boolean;
  status?: number;
  body?: unknown;
}): typeof fetch {
  return vi.fn(async () => {
    const jsonBody = response.body;
    return {
      ok: response.ok ?? true,
      status: response.status ?? 200,
      json: async () => jsonBody,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

function base(overrides: Partial<GenerateReplyDraftInput> = {}): GenerateReplyDraftInput {
  return {
    incomingBody: "Can we meet tomorrow?",
    incomingSubject: "Sync",
    apiKey: "sk-test",
    model: "claude-haiku-4-5",
    ...overrides,
  };
}

describe("generateReplyDraft — happy path", () => {
  it("sends a POST to Anthropic with expected headers + shape", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Sure, tomorrow at 10 works." }] },
    });
    const draft = await generateReplyDraft(base({ fetcher }));

    expect(draft).toBe("Sure, tomorrow at 10 works.");
    expect(fetcher).toHaveBeenCalledTimes(1);
    const [url, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe("https://api.anthropic.com/v1/messages");
    expect(init.method).toBe("POST");
    expect(init.headers["x-api-key"]).toBe("sk-test");
    expect(init.headers["anthropic-dangerous-direct-browser-access"]).toBe("true");
    const body = JSON.parse(init.body);
    expect(body.model).toBe("claude-haiku-4-5");
    expect(body.system).toContain("drafting a reply");
    expect(body.messages[0].role).toBe("user");
    expect(body.messages[0].content).toContain("Sync");
    expect(body.messages[0].content).toContain("Can we meet tomorrow?");
  });

  it("concatenates multiple text chunks in the response", async () => {
    const fetcher = mockFetch({
      body: {
        content: [
          { type: "text", text: "Part one. " },
          { type: "text", text: "Part two." },
        ],
      },
    });
    const draft = await generateReplyDraft(base({ fetcher }));
    expect(draft).toBe("Part one. Part two.");
  });
});

describe("generateReplyDraft — tone (Phase 4.6)", () => {
  it("formal tone appends a formal-register instruction", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Acknowledged." }] },
    });
    await generateReplyDraft(base({ fetcher, tone: "formal" }));
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.system).toContain("formal, professional register");
  });

  it("casual tone appends a friendly-tone instruction", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Sounds good." }] },
    });
    await generateReplyDraft(base({ fetcher, tone: "casual" }));
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.system).toContain("casual, friendly tone");
  });

  it("brief tone caps the response length", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Yes." }] },
    });
    await generateReplyDraft(base({ fetcher, tone: "brief" }));
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.system).toContain("two sentences or fewer");
  });

  it("detailed tone asks for explicit reasoning", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Long answer..." }] },
    });
    await generateReplyDraft(base({ fetcher, tone: "detailed" }));
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.system).toContain("thorough");
  });

  it("omitting tone keeps the base system prompt unchanged", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "Hello." }] },
    });
    await generateReplyDraft(base({ fetcher }));
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    // None of the tone-specific fragments leak into the default prompt.
    expect(body.system).not.toContain("formal, professional");
    expect(body.system).not.toContain("casual, friendly");
    expect(body.system).not.toContain("two sentences");
    expect(body.system).not.toContain("thorough");
  });
});

describe("generateReplyDraft — protocol hints", () => {
  it("includes schedule_negotiation candidates in the prompt", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "OK, Friday 10am works." }] },
    });
    await generateReplyDraft(
      base({
        fetcher,
        incomingBody: "",
        protocolBlock: {
          id: "p1",
          type: "schedule_negotiation",
          action: "propose",
          reply_to: null,
          payload: {
            event_title: "Sync",
            candidates: [
              { start: "2026-05-01T10:00:00+09:00", end: "2026-05-01T10:30:00+09:00" },
            ],
            required_participants: ["did:key:A", "did:key:B"],
          },
        },
      }),
    );
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.messages[0].content).toContain("proposed a meeting");
    expect(body.messages[0].content).toContain("2026-05-01T10:00:00+09:00");
  });

  it("includes task_delegation fields in the prompt", async () => {
    const fetcher = mockFetch({
      body: { content: [{ type: "text", text: "I'll take it." }] },
    });
    await generateReplyDraft(
      base({
        fetcher,
        incomingBody: "",
        protocolBlock: {
          id: "t1",
          type: "task_delegation",
          action: "delegate",
          reply_to: null,
          payload: {
            title: "Review PR",
            description: "Please review #123.",
            due_date: "2026-05-10",
            priority: "high",
          },
        },
      }),
    );
    const [, init] = (fetcher as ReturnType<typeof vi.fn>).mock.calls[0];
    const body = JSON.parse(init.body);
    expect(body.messages[0].content).toContain("delegated a task");
    expect(body.messages[0].content).toContain("Review PR");
    expect(body.messages[0].content).toContain("high");
  });
});

describe("generateReplyDraft — error paths", () => {
  it("wraps 401 as AnthropicDraftError(code=auth)", async () => {
    const fetcher = mockFetch({ ok: false, status: 401, body: {} });
    await expect(generateReplyDraft(base({ fetcher }))).rejects.toMatchObject({
      name: "AnthropicDraftError",
      code: "auth",
      status: 401,
    });
  });

  it("wraps 429 as AnthropicDraftError(code=rate_limit)", async () => {
    const fetcher = mockFetch({ ok: false, status: 429, body: {} });
    await expect(generateReplyDraft(base({ fetcher }))).rejects.toMatchObject({
      code: "rate_limit",
    });
  });

  it("wraps 500 as AnthropicDraftError(code=api_error)", async () => {
    const fetcher = mockFetch({ ok: false, status: 500, body: {} });
    await expect(generateReplyDraft(base({ fetcher }))).rejects.toMatchObject({
      code: "api_error",
      status: 500,
    });
  });

  it("wraps network exceptions as AnthropicDraftError(code=network)", async () => {
    const fetcher: typeof fetch = vi.fn(async () => {
      throw new Error("boom");
    }) as unknown as typeof fetch;
    await expect(generateReplyDraft(base({ fetcher }))).rejects.toMatchObject({
      code: "network",
    });
  });

  it("throws empty_response when content array is empty", async () => {
    const fetcher = mockFetch({ body: { content: [] } });
    await expect(generateReplyDraft(base({ fetcher }))).rejects.toMatchObject({
      code: "empty_response",
    });
  });

  it("AnthropicDraftError is catchable as Error", async () => {
    const fetcher = mockFetch({ ok: false, status: 401, body: {} });
    try {
      await generateReplyDraft(base({ fetcher }));
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(AnthropicDraftError);
      expect(e).toBeInstanceOf(Error);
    }
  });
});
