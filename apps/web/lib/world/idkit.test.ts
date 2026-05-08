import { describe, expect, it } from "vitest";
import type { IDKitResult } from "@worldcoin/idkit";
import { toAuthVerifyRequest, extractNullifierHash } from "./idkit";

describe("toAuthVerifyRequest", () => {
  it("wraps v3 IDKit result as-is", () => {
    const result: IDKitResult = {
      protocol_version: "3.0",
      nonce: "0xabc",
      action: "login",
      responses: [
        {
          identifier: "orb",
          proof: "0xproof",
          merkle_root: "0xroot",
          nullifier: "0xnullifier",
        },
      ],
      environment: "production",
    };

    const req = toAuthVerifyRequest(result, "login");
    expect(req.action).toBe("login");
    expect(req.idkit_result).toHaveProperty("protocol_version", "3.0");
    expect(req.idkit_result).toHaveProperty("responses");
  });

  it("wraps v4 IDKit result as-is", () => {
    const result: IDKitResult = {
      protocol_version: "4.0",
      nonce: "0xabc",
      action: "login",
      responses: [
        {
          identifier: "proof_of_human",
          proof: ["0x1", "0x2", "0x3", "0x4", "0x5"],
          nullifier: "0xnullifier",
          issuer_schema_id: 1,
          expires_at_min: 0,
        },
      ],
      environment: "production",
    };

    const req = toAuthVerifyRequest(result, "login");
    expect(req.action).toBe("login");
    expect(req.idkit_result).toHaveProperty("protocol_version", "4.0");
  });
});

describe("extractNullifierHash", () => {
  it("extracts nullifier from v3 result", () => {
    const result: IDKitResult = {
      protocol_version: "3.0",
      nonce: "0xabc",
      action: "login",
      responses: [
        {
          identifier: "orb",
          proof: "0xproof",
          merkle_root: "0xroot",
          nullifier: "0xnullifier123",
        },
      ],
      environment: "production",
    };

    expect(extractNullifierHash(result)).toBe("0xnullifier123");
  });

  it("throws on empty responses", () => {
    const result: IDKitResult = {
      protocol_version: "3.0",
      nonce: "0xabc",
      action: "login",
      responses: [],
      environment: "production",
    };

    expect(() => extractNullifierHash(result)).toThrowError("no responses");
  });
});
