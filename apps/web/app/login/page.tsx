"use client";

// /login hosts the auth entry point but does NOT load @worldcoin/idkit.
// The IDKit widget is isolated in the /login/idkit sub-route and
// embedded here via a same-origin iframe. Keeping IDKit out of this
// file means the CSP for /login can omit 'unsafe-eval', so an XSS
// here cannot bootstrap arbitrary JS via Function()/eval().
//
// This is **main-document CSP isolation** + **route-level isolation**,
// not origin isolation — parent and child share app.nexusinbox.ai.
// The security boundary against spoofed auth messages is the
// postMessage handler below (origin + source + type prefix), not
// anything about where the child was rendered.
//
// See /Users/mizumoto/.claude/plans/atomic-booping-umbrella.md for
// the isolation design and docs/18_production_bootstrap_runbook.md
// §10.3 for the original WalletConnect eval footgun.

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation, type Locale } from "../../lib/i18n";
import { sanitiseNextPath } from "../../lib/url/next-path";
import { Logo } from "../_components/Logo";

// Message contract between the iframe (`/login/idkit`) and this
// page. Keep the keys flat and serialisable — postMessage cannot
// carry Errors, refs, or functions.
type IdkitIncomingMessage =
  | { type: "idkit/auth-success" }
  | { type: "idkit/auth-error"; messageKey: string; messageParams?: Record<string, string | number> }
  | { type: "idkit/auth-cancelled" };

function isIdkitMessage(data: unknown): data is IdkitIncomingMessage {
  if (!data || typeof data !== "object") return false;
  const maybe = data as { type?: unknown };
  return typeof maybe.type === "string" && maybe.type.startsWith("idkit/");
}

export default function LoginPage() {
  const { locale, setLocale, t } = useTranslation();
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const finalizingRef = useRef(false);

  const toggleLocale = () => {
    const next: Locale = locale === "en" ? "ja" : "en";
    setLocale(next);
  };

  const [statusText, setStatusText] = useState<string>("");
  const [iframeVisible, setIframeVisible] = useState(false);
  const [nextPath, setNextPath] = useState("/");

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setNextPath(sanitiseNextPath(params.get("next")));
  }, []);

  const redirectToNext = useCallback(() => {
    // Hard navigation so any iframe / modal state is blown away. The
    // finalizingRef guard prevents double-fire from overlapping
    // onSuccess / handleVerify postMessages (IDKit sends both).
    if (finalizingRef.current) return;
    finalizingRef.current = true;
    window.location.assign(nextPath);
  }, [nextPath]);

  const closeIframe = useCallback(() => {
    setIframeVisible(false);
  }, []);

  // postMessage listener. Registered once for the lifetime of the
  // page; gates on origin + source + message shape so extensions
  // and cross-frame noise don't drive our state machine.
  useEffect(() => {
    const handler = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      if (!iframeRef.current || event.source !== iframeRef.current.contentWindow) return;
      if (!isIdkitMessage(event.data)) return;

      const msg = event.data;
      switch (msg.type) {
        case "idkit/auth-success": {
          setStatusText(t("auth.statusSuccess"));
          setIframeVisible(false);
          redirectToNext();
          return;
        }
        case "idkit/auth-error": {
          const translated = t(
            msg.messageKey,
            msg.messageParams as Record<string, string | number> | undefined,
          );
          setStatusText(translated);
          setIframeVisible(false);
          return;
        }
        case "idkit/auth-cancelled": {
          setIframeVisible(false);
          return;
        }
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, [redirectToNext, t]);

  // Let the user dismiss the iframe with Esc. Backdrop click is
  // handled inline on the overlay element below.
  useEffect(() => {
    if (!iframeVisible) return;
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeIframe();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [iframeVisible, closeIframe]);

  const iframeSrc = useMemo(() => {
    // `next` is propagated as a query param so that if we ever let
    // the iframe handle its own post-success navigation, it already
    // has the target. Today the parent is what navigates, but
    // passing it along keeps the two routes interchangeable for
    // direct debugging access to /login/idkit.
    return `/login/idkit?next=${encodeURIComponent(nextPath)}`;
  }, [nextPath]);

  const handleOpenWidget = () => {
    setStatusText(t("auth.statusVerifying"));

    // Mobile UA detection. On phones IDKit's "Open World App" button
    // fires either an Android App Link (`https://world.org/...`) or an
    // iOS universal link, both of which Chrome/Safari intercept BEFORE
    // making the network request to open World App directly. From
    // *inside an iframe* that intent-handoff is unreliable on Android
    // Chrome — the browser tends to navigate the iframe to world.org
    // instead of opening the app, so the user never sees World App
    // launch. Top-level navigation works around this without sandboxing
    // tricks. Desktop keeps the iframe so the eval-isolation boundary
    // (docs/18 §10.3) stays intact.
    if (typeof navigator !== "undefined") {
      const isMobile = /Android|iPhone|iPad|iPod|Mobile/i.test(
        navigator.userAgent,
      );
      if (isMobile) {
        window.location.assign(iframeSrc);
        return;
      }
    }

    setIframeVisible(true);
  };

  const statusKind: "idle" | "ok" | "error" = statusText === t("auth.statusSuccess")
    ? "ok"
    : statusText.includes("failed") || statusText.includes("error") || statusText.includes("Failed") || statusText.includes("Error") || statusText.includes("失敗")
      ? "error"
      : "idle";

  return (
    <main className="lg-root" data-testid="login-root">
      <button
        type="button"
        className="lg-lang"
        onClick={toggleLocale}
        aria-label={locale === "en" ? "日本語に切り替え" : "Switch to English"}
        data-testid="login-lang-toggle"
      >
        {locale === "en" ? "日本語" : "English"}
      </button>

      {iframeVisible ? (
        <div
          className="ai-login-iframe-overlay"
          role="dialog"
          aria-modal="true"
          aria-label={t("auth.connectWorldId")}
          data-testid="login-iframe-overlay"
          onClick={(event) => {
            // Backdrop-click cancel: only trigger when the click
            // lands on the overlay itself, not on the iframe child.
            if (event.target === event.currentTarget) {
              closeIframe();
            }
          }}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 1000,
            // Semi-transparent dim so the background isn't fully
            // hidden — reassures the user that they're still on
            // NexusInbox while IDKit does its thing.
            background: "rgba(4, 6, 14, 0.72)",
            backdropFilter: "blur(4px)",
          }}
        >
          <iframe
            ref={iframeRef}
            src={iframeSrc}
            name="idkit"
            title={t("auth.connectWorldId")}
            data-testid="login-iframe"
            // No sandbox attribute: IDKit needs clipboard, popups
            // (World App deeplink), and network access to the
            // WalletConnect bridge. Security is enforced via the
            // iframe's own CSP (`frame-ancestors 'self'` + strict
            // nonce) and the same-origin boundary.
            style={{
              position: "fixed",
              inset: 0,
              width: "100vw",
              height: "100vh",
              border: 0,
              background: "transparent",
            }}
          />
        </div>
      ) : null}

      <section className="lg-card" aria-labelledby="lg-title">
        <h1 id="lg-title" className="lg-brand">
          <Logo size={40} variant="light" />
          <span>
            Nexus<b>Inbox</b>
          </span>
        </h1>
        <p className="lg-hero">{t("auth.hero")}</p>
        <p className="lg-sub">{t("auth.sub")}</p>

        {/* docs/36: a two-line scene of what using it looks like. */}
        <div className="lg-scene" aria-hidden="true">
          <span className="lg-scene-who">{t("auth.sceneThemWho")}</span>
          <span className="lg-bubble">{t("auth.sceneThem")}</span>
          <span className="lg-scene-who mine">{t("auth.sceneYouWho")}</span>
          <span className="lg-bubble mine">{t("auth.sceneYou")}</span>
        </div>

        <button
          className="lg-cta"
          type="button"
          onClick={handleOpenWidget}
          disabled={iframeVisible}
          data-testid="login-cta"
        >
          <svg
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
            <path d="M2 12h20" />
          </svg>
          <span>{iframeVisible ? t("auth.verifying") : t("auth.start")}</span>
        </button>
        <p className="lg-cta-note">{t("auth.ctaNote")}</p>

        <p
          className="lg-status"
          data-kind={statusKind}
          data-testid="login-status"
          role="status"
          aria-live="polite"
        >
          {statusText || "\u00A0"}
        </p>

        <ul className="lg-points">
          <li>
            <span className="lg-point-icon" aria-hidden="true">🔒</span>
            <span>
              <b>{t("auth.pointPrivateTitle")}</b>
              <span>{t("auth.pointPrivateDesc")}</span>
            </span>
          </li>
          <li>
            <span className="lg-point-icon" aria-hidden="true">🙋</span>
            <span>
              <b>{t("auth.pointHumanTitle")}</b>
              <span>{t("auth.pointHumanDesc")}</span>
            </span>
          </li>
          <li>
            <span className="lg-point-icon" aria-hidden="true">🤖</span>
            <span>
              <b>{t("auth.pointAiTitle")}</b>
              <span>{t("auth.pointAiDesc")}</span>
            </span>
          </li>
        </ul>

        <nav className="lg-links" aria-label={t("auth.linksLabel")}>
          <Link href="/concept">{t("auth.conceptLink")}</Link>
          <Link href="/help">{t("legal.helpLink")}</Link>
          <Link href="/terms">{t("legal.termsLink")}</Link>
          <Link href="/privacy">{t("legal.privacyLink")}</Link>
        </nav>
      </section>
    </main>
  );
}
