// The build this server runs (next.config.ts). Open tabs poll it and offer
// a reload once it differs from the build they were loaded from.

export const dynamic = "force-dynamic";

export function GET() {
  return Response.json(
    { version: process.env.NEXT_PUBLIC_APP_VERSION ?? "" },
    { headers: { "Cache-Control": "no-store" } },
  );
}
