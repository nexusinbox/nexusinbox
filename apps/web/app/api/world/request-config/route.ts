import { NextResponse } from "next/server";
import { signRequest } from "@worldcoin/idkit/signing";

export const dynamic = "force-dynamic";

// Per-request nonce + signature must never be cached: a stale copy locks
// every subsequent IDKit handshake into the same nonce, which Worldcoin
// rejects (replay) and causes a confusing `malformed_request` after any
// signer-key rotation. `force-dynamic` above tells Next.js to re-run on
// every request server-side; these headers tell the browser, the Vercel
// edge, and any intermediate proxy not to retain the response either.
const NO_CACHE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
  Pragma: "no-cache",
  Expires: "0",
} as const;

function normalizeHexKey(raw: string): string {
  const trimmed = raw.trim();
  return trimmed.startsWith("0x") ? trimmed.slice(2) : trimmed;
}

export async function GET() {
  const appId = process.env.WORLD_ID_APP_ID ?? "";
  const action = process.env.WORLD_ID_ACTION ?? "login";
  const rpId = process.env.WORLD_ID_RP_ID ?? "";
  const signingKey = process.env.WORLD_ID_SIGNER_PRIVATE_KEY ?? "";

  if (!appId || !rpId || !signingKey) {
    return NextResponse.json(
      {
        message:
          "World ID config is incomplete. Set WORLD_ID_APP_ID, WORLD_ID_RP_ID, and WORLD_ID_SIGNER_PRIVATE_KEY.",
      },
      { status: 503, headers: NO_CACHE_HEADERS },
    );
  }

  try {
    const signature = signRequest({
      signingKeyHex: normalizeHexKey(signingKey),
      action,
      ttl: 300,
    });

    return NextResponse.json(
      {
        app_id: appId,
        action,
        rp_context: {
          rp_id: rpId,
          nonce: signature.nonce,
          created_at: signature.createdAt,
          expires_at: signature.expiresAt,
          signature: signature.sig,
        },
        allow_legacy_proofs: true,
      },
      { headers: NO_CACHE_HEADERS },
    );
  } catch {
    return NextResponse.json(
      { message: "Failed to generate RP signature for IDKit request." },
      { status: 500, headers: NO_CACHE_HEADERS },
    );
  }
}
