"use client";

// IDKit-isolated sub-route. This page is the only place in the Web
// UI that imports @worldcoin/idkit (and therefore pulls in
// WalletConnect's `new Function()` dependency). Every other route —
// including the parent /login that embeds this one as an iframe —
// runs under a strict `script-src 'self' 'nonce-…' 'strict-dynamic'`
// CSP with no `unsafe-eval`. An XSS on any other route cannot
// bootstrap via eval.
//
// **Scope of this isolation**: we rely on *main-document CSP
// isolation* (the top frame of /login doesn't load IDKit code, so
// its CSP stays strict) plus *route-level isolation* (the eval
// allowance lives on exactly one path). This is NOT origin
// isolation — parent and child share the same origin, so a full
// sandbox-style boundary does not exist. Security against spoofed
// post-auth messages is enforced by the parent's postMessage
// handler (origin + source + type prefix), not by any guarantee
// that the child was embedded by a trusted frame.
//
// See docs/18_production_bootstrap_runbook.md §10.3 for the CSP
// rationale and the plan at
// /Users/mizumoto/.claude/plans/atomic-booping-umbrella.md for
// the isolation design.
//
// Parent contract: we're loaded from the same-origin parent /login
// and report out via `postMessage` only. Never navigate the top
// frame from here; the parent owns that responsibility.

import {
  IDKitErrorCodes,
  IDKitRequestWidget,
  orbLegacy,
  type IDKitResult,
  type RpContext,
} from "@worldcoin/idkit";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "../../../lib/api/client";
import { useAuthVerifyMutation } from "../../../lib/api/hooks";
import { toAuthVerifyRequest, extractNullifierHash } from "../../../lib/world/idkit";
import { sanitiseNextPath } from "../../../lib/url/next-path";

type WorldRequestConfig = {
  app_id: `app_${string}`;
  action: string;
  rp_context: RpContext;
  allow_legacy_proofs: boolean;
};

// Messages the parent /login listens for. Keep these stable — they
// are the public contract between the two routes.
type IdkitPostMessage =
  | { type: "idkit/auth-success" }
  | { type: "idkit/auth-error"; messageKey: string; messageParams?: Record<string, string | number> }
  | { type: "idkit/auth-cancelled" };

function postToParent(msg: IdkitPostMessage) {
  if (typeof window === "undefined") return;

  // Standalone (no parent) mode is hit on mobile — /login does a
  // top-level redirect to /login/idkit instead of embedding it as
  // an iframe, because Android Chrome won't fire App Links from
  // inside an iframe. Without a parent there's nothing to
  // postMessage to, so we drive the same UX transitions locally:
  // success navigates to `next`, error/cancel returns to /login.
  if (window.parent === window) {
    handleStandaloneOutcome(msg);
    return;
  }

  // Target origin = our own origin. postMessage drops the message
  // if the parent's origin doesn't match, which is the secure
  // default for any third-party embedding attempt.
  try {
    window.parent.postMessage(msg, window.location.origin);
  } catch {
    // postMessage shouldn't throw normally, but some extensions
    // patch window.parent. Fail closed.
  }
}

function handleStandaloneOutcome(msg: IdkitPostMessage) {
  const params = new URLSearchParams(window.location.search);
  const next = sanitiseNextPath(params.get("next"));
  switch (msg.type) {
    case "idkit/auth-success":
      // Cookie has been set by /api/auth/verify; hop to the
      // requested destination. Hard navigation so any IDKit DOM
      // is wiped.
      window.location.assign(next);
      return;
    case "idkit/auth-error":
    case "idkit/auth-cancelled":
      // Bounce back to /login so the user can retry. We don't
      // surface the specific error message in standalone mode
      // today — IDKit also renders its own error UI inline, so
      // the user already sees something actionable. Keeping the
      // login URL stable also means a fresh redirect re-arms the
      // CTA the user originally clicked.
      window.location.assign(`/login?next=${encodeURIComponent(next)}`);
      return;
  }
}

type FrameState = "embedded" | "standalone";

function detectFrameState(): FrameState {
  if (typeof window === "undefined") return "standalone";
  // Only check whether we're in *some* frame. We deliberately do
  // NOT inspect `window.location.ancestorOrigins` — it's Safari +
  // Chromium-only and Firefox returns an empty list, so any code
  // that treats its absence as "cross-origin" would misclassify
  // Firefox embeds.
  //
  // document.referrer is a soft hint: same-origin iframes fill it
  // with the parent URL, but extensions / privacy settings may
  // redact it, so treat mismatch as a warning signal at most. The
  // real security boundary is the parent's message handler which
  // verifies event.origin and event.source.
  return window.parent === window ? "standalone" : "embedded";
}

export default function IdkitEmbeddedPage() {
  const authVerify = useAuthVerifyMutation();
  // We only distinguish "embedded" vs "standalone" for UX reasons
  // (logging, debugging). Security doesn't rely on this — the
  // parent's postMessage handler is the real boundary.
  const [frameState, setFrameState] = useState<FrameState | null>(null);
  const [requestConfig, setRequestConfig] = useState<WorldRequestConfig | null>(null);
  const [widgetOpen, setWidgetOpen] = useState(false);
  // Track whether verification already succeeded so that the IDKit
  // widget closing via `onOpenChange(false)` after success is NOT
  // reported to the parent as a cancel. Without this flag we would
  // race: the widget auto-closes after onSuccess, our handler fires
  // before we set state, and the parent both redirects AND unmounts.
  const succeededRef = useRef(false);
  // IDKit invokes onVerify from an internal useEffect, so React 19 Strict
  // Mode double-invokes it in dev and submits the same proof twice. We
  // cache the in-flight Promise keyed on the exact proof so the second
  // caller awaits the first one instead of (a) racing it to a 422 or
  // (b) returning early, which would let IDKit fire onSuccess before
  // our fetch resolves and abort the winning response.
  const inflightProofRef = useRef<{ key: string; promise: Promise<void> } | null>(null);

  useEffect(() => {
    setFrameState(detectFrameState());
    // Third-party embedding is prevented by
    //   (a) CSP `frame-ancestors 'self'` on this route
    //   (b) X-Frame-Options: SAMEORIGIN on this route
    //   (c) the parent /login's postMessage handler validating
    //       event.origin and event.source
    // We do NOT try to detect it here because reliable cross-origin
    // parent-checks aren't portable (ancestorOrigins is Firefox-blind,
    // parent.location.origin throws opaquely).
  }, []);

  useEffect(() => {
    if (frameState === null) return;
    let cancelled = false;
    (async () => {
      try {
        const response = await fetch("/api/world/request-config", {
          method: "GET",
          cache: "no-store",
        });
        const raw = await response.text();
        let payload: {
          message?: string;
          app_id?: string;
          action?: string;
          rp_context?: RpContext;
          allow_legacy_proofs?: boolean;
        };
        try {
          payload = JSON.parse(raw) as typeof payload;
        } catch {
          throw new Error(
            `World ID config endpoint returned non-JSON (HTTP ${response.status}).`,
          );
        }
        if (!response.ok || !payload.app_id || !payload.action || !payload.rp_context) {
          throw new Error(
            payload.message ??
              `Failed to load World ID request config (HTTP ${response.status}).`,
          );
        }
        if (cancelled) return;
        setRequestConfig({
          app_id: payload.app_id as `app_${string}`,
          action: payload.action,
          rp_context: payload.rp_context,
          allow_legacy_proofs: payload.allow_legacy_proofs ?? true,
        });
        setWidgetOpen(true);
      } catch (error) {
        if (cancelled) return;
        const message = error instanceof Error ? error.message : "";
        postToParent({
          type: "idkit/auth-error",
          messageKey: message ? "auth.statusPrepFailed" : "auth.statusPrepFailedGeneric",
          messageParams: message ? { message } : undefined,
        });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [frameState]);

  const handleVerify = async (result: IDKitResult) => {
    const config = requestConfig;
    if (!config) {
      // Shouldn't happen — the widget only opens after config resolves.
      // Fail the verify so IDKit fires onError on its side.
      throw new Error("World request config is not initialized.");
    }
    const proofKey = extractNullifierHash(result);
    if (inflightProofRef.current?.key === proofKey) {
      await inflightProofRef.current.promise;
      succeededRef.current = true;
      postToParent({ type: "idkit/auth-success" });
      return;
    }
    const promise = authVerify.mutateAsync(toAuthVerifyRequest(result, config.action)).then(
      () => undefined,
    );
    inflightProofRef.current = { key: proofKey, promise };
    try {
      await promise;
    } catch (error) {
      inflightProofRef.current = null;
      // Re-throw so IDKit treats this as a verification failure and
      // fires onError(FailedByHostApp) instead of onSuccess.
      if (error instanceof ApiError) {
        postToParent({
          type: "idkit/auth-error",
          messageKey: "auth.statusAuthFailed",
          messageParams: { message: error.message, status: String(error.status) },
        });
      } else if (error instanceof Error) {
        postToParent({
          type: "idkit/auth-error",
          messageKey: "auth.statusAuthFailedMsg",
          messageParams: { message: error.message },
        });
      } else {
        postToParent({
          type: "idkit/auth-error",
          messageKey: "auth.statusAuthFailedGeneric",
        });
      }
      throw error;
    }
    succeededRef.current = true;
    postToParent({ type: "idkit/auth-success" });
  };

  return (
    <main
      style={{
        // Transparent so the parent's backdrop shows through. IDKit's
        // own modal is position:fixed and covers the viewport on its
        // own, so we don't render any chrome here.
        minHeight: "100vh",
        background: "transparent",
      }}
      data-testid="idkit-embedded-root"
    >
      {requestConfig ? (
        <IDKitRequestWidget
          open={widgetOpen}
          onOpenChange={(open) => {
            setWidgetOpen(open);
            if (!open && !succeededRef.current) {
              // User dismissed the widget without completing — tell
              // the parent so it can unmount the overlay. Success
              // closes come through onSuccess / handleVerify and set
              // succeededRef first.
              postToParent({ type: "idkit/auth-cancelled" });
            }
          }}
          app_id={requestConfig.app_id}
          action={requestConfig.action}
          rp_context={requestConfig.rp_context}
          allow_legacy_proofs={requestConfig.allow_legacy_proofs}
          preset={orbLegacy({ signal: "" })}
          handleVerify={handleVerify}
          onSuccess={() => {
            succeededRef.current = true;
            postToParent({ type: "idkit/auth-success" });
          }}
          onError={(errorCode) => {
            if (errorCode === IDKitErrorCodes.FailedByHostApp) {
              // handleVerify already postMessage'd a specific error
              // for this case — don't overwrite it with the generic
              // server-failed key.
              return;
            }
            postToParent({
              type: "idkit/auth-error",
              messageKey: "auth.idkitError",
              messageParams: { code: String(errorCode) },
            });
          }}
        />
      ) : null}
    </main>
  );
}
