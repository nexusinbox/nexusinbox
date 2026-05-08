import { afterEach, describe, expect, it, vi } from "vitest";
import { NexusInboxApiClient, ApiError } from "./client";

describe("NexusInboxApiClient", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends listMessages request with auth header and query params", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          messages: [],
          total: 0,
          page: 1,
          per_page: 50,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.listMessages({ agentDid: "all", status: "all", page: 1, perPage: 50 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/messages?");
    expect(String(url)).toContain("agent_did=all");

    const headers = init?.headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer dev-user-test");
    expect(init?.credentials).toBe("include");
  });

  it("throws ApiError on non-2xx response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ message: "missing bearer token" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "bad-token",
    });

    await expect(client.listMessages({ agentDid: "all" })).rejects.toBeInstanceOf(ApiError);
  });

  it("posts createAgent payload", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "agent-id", did: "did:key:new" }), {
        status: 201,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.createAgent({
      label: "営業アシスタント",
      public_key: "pk",
      encryption_key: "ek",
    });

    const [, init] = fetchMock.mock.calls[0];
    expect(init?.method).toBe("POST");
    expect(String(init?.body)).toContain("営業アシスタント");
  });

  it("patches message status", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ id: "m-1", status: "read" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.updateMessageStatus("m-1", "read");

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/messages/m-1");
    expect(init?.method).toBe("PATCH");
    expect(String(init?.body)).toContain("\"status\":\"read\"");
  });

  it("calls auth verify without authorization header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(
        JSON.stringify({
          user: {
            id: "u-1",
            display_name: null,
            verification_level: "orb",
            created_at: "2026-04-11T00:00:00Z",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.verifyAuth({
      idkit_result: {
        protocol_version: "3.0",
        nonce: "test",
        responses: [{ identifier: "orb", proof: "p", merkle_root: "r", nullifier: "n" }],
      },
      action: "login",
    });

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });

  it("does not attach authorization header when no bearer token exists", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ agents: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "",
    });

    await client.listAgents();

    const [, init] = fetchMock.mock.calls[0];
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });

  it("calls auth logout without authorization header", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const client = new NexusInboxApiClient({
      baseUrl: "http://localhost:8080",
      bearerToken: "dev-user-test",
    });

    await client.logoutAuth();

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/auth/logout");
    expect(init?.method).toBe("POST");
    const headers = new Headers(init?.headers as HeadersInit);
    expect(headers.get("Authorization")).toBe(null);
    expect(init?.credentials).toBe("include");
  });
});
