"use client";

// 「ほかのブラウザを足す」 on a browser that can sign (docs/40 §17.4, mock
// docs/40_stage7_mock.html ② ⑥). World ID first (the server asks for a
// recent sign-in to change the signers), then a QR code, a link and a
// 26-character code. When the new browser has sent its keys, this browser
// checks them and signs them in without asking.

import qrcode from "qrcode-generator";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  settleAddedBrowser,
  signableAgents,
  startAddingBrowser,
  type Settled,
  type Showing,
} from "../../lib/agents/browser-pairing";
import { defaultApiClient } from "../../lib/api/client";
import { useTranslation } from "../../lib/i18n";

type Step =
  | { kind: "reauth" }
  | { kind: "starting" }
  | { kind: "showing"; showing: Showing }
  | { kind: "settled"; result: Exclude<Settled, { kind: "waiting" }> }
  | { kind: "failed" };

/** The page to come back to after World ID, with the panel open. */
function returnPath(): string {
  const url = new URL(window.location.href);
  url.searchParams.set("addBrowser", "1");
  return url.pathname + url.search;
}

export function AddBrowserPanel({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>({ kind: "reauth" });
  const [now, setNow] = useState(() => Date.now());
  const settling = useRef(false);

  // Back from World ID: start at once, and take the flag out of the URL so
  // a reload does not start another pairing.
  useEffect(() => {
    const url = new URL(window.location.href);
    if (url.searchParams.get("addBrowser") !== "1") return;
    url.searchParams.delete("addBrowser");
    window.history.replaceState(null, "", url.pathname + url.search);
    void start();
  }, []);

  const start = async () => {
    setStep({ kind: "starting" });
    try {
      const { agents } = await defaultApiClient.listAgents();
      const signable = await signableAgents(agents);
      if (signable.length === 0) throw new Error("no agent to add to");
      setStep({ kind: "showing", showing: await startAddingBrowser(signable, window.location.origin) });
    } catch {
      setStep({ kind: "failed" });
    }
  };

  // Watch for the new browser's keys every 2 seconds while shown.
  useEffect(() => {
    if (step.kind !== "showing") return;
    const timer = window.setInterval(() => {
      setNow(Date.now());
      if (settling.current) return;
      settling.current = true;
      void settleAddedBrowser(step.showing)
        .then((result) => {
          if (result.kind === "waiting") return;
          setStep({ kind: "settled", result });
          if (result.kind === "done") onDone();
        })
        .catch(() => setStep({ kind: "failed" }))
        .finally(() => {
          settling.current = false;
        });
    }, 2000);
    return () => window.clearInterval(timer);
  }, [step, onDone]);

  const box = { borderRadius: 12, background: "var(--primary-soft)", padding: "12px 14px" } as const;

  if (step.kind === "reauth") {
    return (
      <div style={box} data-testid="add-browser-reauth">
        <p style={{ margin: 0, fontWeight: 700 }}>{t("addBrowser.reauthTitle")}</p>
        <p className="item-sub" style={{ margin: "2px 0 8px" }}>
          {t("addBrowser.reauthBody")}
        </p>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            type="button"
            className="btn primary"
            onClick={() => window.location.assign(`/login?next=${encodeURIComponent(returnPath())}`)}
          >
            {t("addBrowser.reauthButton")}
          </button>
          <button type="button" className="btn" onClick={onClose}>
            {t("addBrowser.cancel")}
          </button>
        </div>
      </div>
    );
  }

  if (step.kind === "starting") {
    return (
      <p className="item-sub" style={{ margin: 0 }}>
        {t("addBrowser.starting")}
      </p>
    );
  }

  if (step.kind === "failed") {
    return (
      <div style={box} role="alert">
        <p className="item-sub" style={{ margin: 0 }}>
          {t("addBrowser.failed")}
        </p>
        <button type="button" className="btn" style={{ marginTop: 8 }} onClick={onClose}>
          {t("addBrowser.close")}
        </button>
      </div>
    );
  }

  if (step.kind === "settled") {
    const { result } = step;
    const message =
      result.kind === "done"
        ? t("addBrowser.done", { name: result.label ?? t("agentStatus.deviceBrowser") })
        : result.kind === "mismatch"
          ? t("addBrowser.mismatch")
          : result.kind === "reauth"
            ? t("addBrowser.reauth")
            : t("addBrowser.expired");
    return (
      <div
        role={result.kind === "done" ? "status" : "alert"}
        data-testid={`add-browser-${result.kind}`}
        style={{
          borderRadius: 12,
          padding: "10px 12px",
          background: result.kind === "done" ? "var(--ok-soft)" : "var(--danger-soft)",
          border: result.kind === "mismatch" ? "1px solid var(--danger)" : undefined,
        }}
      >
        <p style={{ margin: 0 }}>{message}</p>
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          {result.kind === "reauth" ? (
            <a className="btn primary" href={`/login?next=${encodeURIComponent(returnPath())}`}>
              {t("addBrowser.reauthButton")}
            </a>
          ) : result.kind !== "done" ? (
            <button type="button" className="btn" onClick={() => void start()}>
              {t("addBrowser.retry")}
            </button>
          ) : null}
          <button type="button" className="btn" onClick={onClose}>
            {t("addBrowser.close")}
          </button>
        </div>
      </div>
    );
  }

  const { showing } = step;
  const left = Math.max(0, Date.parse(showing.pairing.expires_at) - now);
  const minutes = Math.floor(left / 60000);
  const seconds = Math.floor((left % 60000) / 1000);
  return (
    <div style={box} data-testid="add-browser-showing">
      <p style={{ margin: 0, fontWeight: 700 }}>{t("addBrowser.scanTitle")}</p>
      <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", margin: "8px 0" }}>
        <QrCode text={showing.link} />
        <div style={{ flex: 1, minWidth: 220 }}>
          <p className="item-sub" style={{ margin: "0 0 6px" }}>
            {t("addBrowser.scanBody")}
          </p>
          <button type="button" className="btn" onClick={() => void navigator.clipboard?.writeText(showing.link)}>
            {t("addBrowser.copyLink")}
          </button>
          <p className="item-sub" style={{ margin: "10px 0 4px" }}>
            {t("addBrowser.typeCode")}
          </p>
          <code
            data-testid="add-browser-code"
            style={{ font: "700 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace", wordBreak: "break-all" }}
          >
            {showing.code}
          </code>
        </div>
      </div>
      <p className="item-sub" style={{ margin: 0 }}>
        {t("addBrowser.waiting", { m: minutes, s: String(seconds).padStart(2, "0") })}
      </p>
      <p className="item-sub" style={{ margin: "4px 0 0" }}>
        {t("addBrowser.agents", { names: showing.agents.map((a) => a.label).join("、") })}
      </p>
      <button type="button" className="btn" style={{ marginTop: 8 }} onClick={onClose}>
        {t("addBrowser.cancel")}
      </button>
    </div>
  );
}

/** A QR code drawn as SVG cells (no HTML from the library). */
function QrCode({ text }: { text: string }) {
  const cells = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    const dark: Array<[number, number]> = [];
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) dark.push([r, c]);
    return { n, dark };
  }, [text]);
  const margin = 4;
  const size = cells.n + margin * 2;
  return (
    <svg
      viewBox={`0 0 ${size} ${size}`}
      width={168}
      height={168}
      role="img"
      aria-label="QR"
      data-testid="add-browser-qr"
      style={{ background: "#fff", borderRadius: 8, flex: "none" }}
    >
      {cells.dark.map(([r, c]) => (
        <rect key={`${r}-${c}`} x={c + margin} y={r + margin} width={1} height={1} fill="#000" />
      ))}
    </svg>
  );
}
