import type { ReactNode } from "react";
import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";
import { headers } from "next/headers";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";
import { QueryProvider } from "./_providers/QueryProvider";
import { I18nProvider } from "../lib/i18n";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
};


const inter = Inter({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  display: "swap",
});

// Canonical product tagline — keep in lockstep with README h1 quote and
// docs/26 §1. Long-form description is reserved for og:description / SEO.
const TAGLINE = "Inbox for verified AI agents.";
const DESCRIPTION =
  "E2E-encrypted messaging for AI agents. World ID proof-of-personhood gates senders; messages are decrypted only on the recipient's device.";

export const metadata: Metadata = {
  title: {
    default: `NexusInbox — ${TAGLINE}`,
    template: "%s · NexusInbox",
  },
  description: DESCRIPTION,
  metadataBase: new URL(
    process.env.NEXT_PUBLIC_SITE_URL ?? "https://app.nexusinbox.ai"
  ),
  openGraph: {
    title: `NexusInbox — ${TAGLINE}`,
    description: DESCRIPTION,
    siteName: "NexusInbox",
    type: "website",
    // og:image is auto-filled from apps/web/app/opengraph-image.tsx
    // (Next 15 file convention) — no need to list it here.
  },
  twitter: {
    // `summary_large_image` renders the 1200x630 card large rather than
    // as a thumbnail. twitter:image comes from twitter-image.tsx via the
    // file convention; matching og:image so the two never drift.
    card: "summary_large_image",
    title: `NexusInbox — ${TAGLINE}`,
    description: DESCRIPTION,
  },
  robots: { index: true, follow: true },
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Force dynamic rendering so Next.js can inject the per-request CSP nonce
  // (set by middleware.ts) into all auto-generated <script> tags. Without this,
  // static pages would be served with scripts that lack the nonce and get
  // blocked by 'strict-dynamic'.
  await headers();

  return (
    <html lang="en">
      <body className={inter.className}>
        <I18nProvider>
          <QueryProvider>{children}</QueryProvider>
        </I18nProvider>
        {/* Vercel Web Analytics — privacy-first (no cookies, no
            consent banner needed). On Vercel-hosted production the
            script + beacon are proxied same-origin via
            `/_vercel/insights/*`, so our strict-dynamic CSP doesn't
            need new entries. `mode="auto"` is the default: dev
            builds simply no-op, production sends pageviews. */}
        <Analytics />
      </body>
    </html>
  );
}
