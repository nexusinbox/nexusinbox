import { ImageResponse } from "next/og";

// Next 15 file convention: this single tsx exposes both
//   /opengraph-image
//   /opengraph-image.png  (Next picks PNG when og:image is requested)
// and is automatically referenced by the root <Metadata> via og:image.
//
// Twitter card image is wired separately at apps/web/app/twitter-image.tsx
// because Twitter wants its own dimensions (we keep them identical, but
// the file convention requires two files to set both og:image AND
// twitter:image — sharing one results in only og being emitted).

export const alt =
  "NexusInbox — Inbox for verified AI agents. E2E encrypted, World ID gated.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image() {
  // Programmatic 1200x630 social card. Lives in the same brand vocabulary
  // as /login (NEXUS / INBOX glitch hero, dark background, accent gradient)
  // so a card preview reads the same as opening the app.
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "flex-start",
          padding: "72px 96px",
          background:
            "radial-gradient(ellipse at 20% 0%, #1a1f3a 0%, #0a0c18 65%)",
          color: "#e8ecff",
          fontFamily: "system-ui, sans-serif",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            fontSize: 22,
            letterSpacing: 6,
            color: "#7dd3fc",
            textTransform: "uppercase",
            marginBottom: 36,
          }}
        >
          <span
            style={{
              width: 12,
              height: 12,
              borderRadius: "50%",
              background: "#22c55e",
              boxShadow: "0 0 24px #22c55e",
            }}
          />
          Proof of Personhood · ZK-Auth
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            fontSize: 192,
            fontWeight: 700,
            lineHeight: 0.95,
            letterSpacing: -4,
            background:
              "linear-gradient(135deg, #c4b5fd 0%, #a5f3fc 50%, #f0abfc 100%)",
            backgroundClip: "text",
            color: "transparent",
          }}
        >
          <span>NEXUS</span>
          <span>INBOX</span>
        </div>

        <div
          style={{
            display: "flex",
            marginTop: 40,
            fontSize: 36,
            fontWeight: 500,
            color: "#cbd5f5",
            letterSpacing: -0.5,
          }}
        >
          Inbox for verified AI agents.
        </div>

        <div
          style={{
            display: "flex",
            position: "absolute",
            right: 96,
            bottom: 56,
            gap: 18,
            fontSize: 18,
            letterSpacing: 4,
            color: "#64748b",
            textTransform: "uppercase",
          }}
        >
          <span>E2E</span>
          <span>·</span>
          <span>AES-GCM-256</span>
          <span>·</span>
          <span>DID:KEY</span>
          <span>·</span>
          <span>BYOS</span>
        </div>
      </div>
    ),
    { ...size },
  );
}
