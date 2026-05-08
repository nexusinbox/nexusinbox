import type { IDKitResult } from "@worldcoin/idkit";
import type { AuthVerifyRequest } from "../api/types";

/**
 * Convert IDKit result to AuthVerifyRequest.
 * Forward the raw IDKit payload as-is per World ID v4 docs:
 * "Forward the IDKit result payload as-is. No field remapping is required."
 */
export function toAuthVerifyRequest(result: IDKitResult, action: string): AuthVerifyRequest {
  return {
    idkit_result: result as unknown as Record<string, unknown>,
    action,
  };
}

/**
 * Extract nullifier_hash from IDKit result for replay/block checks.
 * Works with both protocol_version 3.0 and 4.0.
 */
export function extractNullifierHash(result: IDKitResult): string {
  const responses = result.responses ?? [];
  const first = responses[0];
  if (!first) {
    throw new Error("IDKit result has no responses.");
  }
  // v3.0 and v4.0 both have nullifier field
  const record = first as unknown as Record<string, unknown>;
  return (record.nullifier as string) ?? "";
}
