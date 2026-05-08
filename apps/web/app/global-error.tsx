"use client";

import { useTranslation } from "../lib/i18n";

/**
 * Last-resort error boundary — fires when the root layout itself throws,
 * so the `.ai-login-*` CSS classes are not guaranteed to have loaded.
 * Everything here is inline-styled so the screen renders even when the
 * stylesheet bundle is missing. Visually we mimic the /login dark stage
 * (deep navy, soft cyan/violet radial washes, centred card) so the user
 * still lands somewhere that looks like the product.
 */
export default function GlobalError({
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const { t } = useTranslation();
  return (
    <html lang="ja">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          padding: 24,
          boxSizing: "border-box",
          fontFamily:
            "'Space Grotesk', 'Google Sans', 'Noto Sans JP', system-ui, sans-serif",
          color: "#e8ecff",
          background:
            "radial-gradient(ellipse at 20% 10%, rgba(90, 64, 255, 0.28) 0%, transparent 55%)," +
            "radial-gradient(ellipse at 85% 90%, rgba(0, 210, 255, 0.22) 0%, transparent 55%)," +
            "radial-gradient(ellipse at 50% 50%, #0a0c18 0%, #04050b 75%)",
        }}
      >
        <section
          role="alertdialog"
          aria-labelledby="ai-global-error-title"
          style={{
            width: "min(440px, 100%)",
            padding: "40px 36px 32px",
            borderRadius: 22,
            background:
              "linear-gradient(180deg, rgba(12, 16, 32, 0.78), rgba(6, 8, 18, 0.78))",
            boxShadow:
              "0 30px 80px rgba(0, 0, 0, 0.55), inset 0 0 0 1px rgba(120, 140, 255, 0.15)",
            textAlign: "center",
          }}
        >
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 11,
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: "#8190c4",
              marginBottom: 24,
            }}
          >
            <span
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: "#ff6384",
                boxShadow: "0 0 10px rgba(255, 99, 132, 0.8)",
              }}
            />
            <span>{t("errors.errorLabel")}</span>
          </div>

          <h1
            id="ai-global-error-title"
            style={{
              fontSize: 44,
              fontWeight: 800,
              letterSpacing: "-0.02em",
              lineHeight: 1.1,
              margin: 0,
              background:
                "linear-gradient(135deg, #7dd7ff 0%, #a9b8ff 50%, #d49eff 100%)",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              WebkitTextFillColor: "transparent",
              color: "transparent",
            }}
          >
            {t("errors.somethingWrong")}
          </h1>

          <p
            style={{
              color: "#b0bad8",
              fontSize: 14,
              lineHeight: 1.6,
              margin: "16px 0 24px",
            }}
          >
            {t("errors.unexpectedError")}
          </p>

          <button
            onClick={reset}
            type="button"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              padding: "12px 28px",
              borderRadius: 14,
              border: "1px solid rgba(160, 180, 255, 0.4)",
              background:
                "linear-gradient(135deg, rgba(125, 215, 255, 0.25) 0%, rgba(212, 158, 255, 0.25) 100%)",
              color: "#e8ecff",
              fontSize: 14,
              fontWeight: 600,
              letterSpacing: "0.02em",
              cursor: "pointer",
              fontFamily: "inherit",
            }}
          >
            {t("errors.tryAgain")}
          </button>
        </section>
      </body>
    </html>
  );
}
