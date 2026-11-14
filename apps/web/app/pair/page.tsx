"use client";

// The browser being added (docs/40 §17.4, mock docs/40_stage7_mock.html ③
// ④). The link's part after `#` holds the code and the secret; the secret
// never goes to the server. This browser makes its keys for each agent,
// sends them with MACs, and waits until the browser that can sign has
// checked them and MACed each agent's root back.

import { useEffect, useRef, useState } from "react";
import { AppShell } from "../_components/AppShell";
import {
  browserLabel,
  findPairing,
  finishJoining,
  joinPairing,
  type Joining,
} from "../../lib/agents/browser-pairing";
import { ApiError, defaultApiClient } from "../../lib/api/client";
import type { Agent } from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";

type Step =
  | { kind: "reading" }
  | { kind: "enter" }
  | { kind: "found"; joining: Joining; agents: Agent[] }
  | { kind: "adding"; joining: Joining; sent: boolean }
  | { kind: "done" }
  | { kind: "error"; message: "notFound" | "mismatch" | "expired" | "failed" | "noKeystore" };

export default function PairPage() {
  const { t } = useTranslation();
  const [step, setStep] = useState<Step>({ kind: "reading" });
  const [typed, setTyped] = useState("");
  const polling = useRef(false);

  const find = async (raw: string) => {
    try {
      const joining = await findPairing(raw);
      if (!joining) {
        setStep({ kind: "error", message: "notFound" });
        return;
      }
      const { agents } = await defaultApiClient.listAgents();
      setStep({ kind: "found", joining, agents: agents.filter((a) => joining.aids.includes(a.aid)) });
    } catch (error) {
      setStep({ kind: "error", message: error instanceof ApiError && error.status === 404 ? "notFound" : "failed" });
    }
  };

  // Read the code and secret from the link, then drop them from the address
  // bar so they are not left in history or shown again.
  useEffect(() => {
    const fragment = window.location.hash.replace(/^#/, "");
    if (fragment) {
      window.history.replaceState(null, "", window.location.pathname);
      void find(fragment);
    } else {
      setStep({ kind: "enter" });
    }
  }, []);

  const add = async (joining: Joining) => {
    setStep({ kind: "adding", joining, sent: false });
    try {
      await joinPairing(joining, browserLabel(navigator.userAgent));
      setStep({ kind: "adding", joining, sent: true });
    } catch (error) {
      setStep({
        kind: "error",
        message:
          error instanceof ApiError
            ? error.status === 404
              ? "expired"
              : "failed"
            : error instanceof Error && /cannot keep keys/.test(error.message)
              ? "noKeystore"
              : "failed",
      });
    }
  };

  // Wait for the browser that can sign, every 2 seconds.
  useEffect(() => {
    if (step.kind !== "adding" || !step.sent) return;
    const { joining } = step;
    const timer = window.setInterval(() => {
      if (polling.current) return;
      polling.current = true;
      void (async () => {
        try {
          const { agents } = await defaultApiClient.listAgents();
          const result = await finishJoining(joining, agents);
          if (result.kind === "done") setStep({ kind: "done" });
          else if (result.kind !== "waiting") setStep({ kind: "error", message: result.kind });
        } catch {
          setStep({ kind: "error", message: "failed" });
        } finally {
          polling.current = false;
        }
      })();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [step]);

  return (
    <AppShell title={t("pair.title")} activePath="/pair">
      <section className="card" style={{ maxWidth: 440, margin: "0 auto", padding: "18px 20px" }} data-testid="pair">
        {step.kind === "reading" ? <p className="item-sub">{t("pair.adding")}</p> : null}

        {step.kind === "enter" ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void find(typed);
            }}
          >
            <p style={{ margin: "0 0 6px", fontWeight: 700 }}>{t("pair.enterCode")}</p>
            <input
              className="input"
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              placeholder={t("pair.codePlaceholder")}
              autoComplete="off"
              spellCheck={false}
              style={{ width: "100%", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}
              data-testid="pair-code"
            />
            <button type="submit" className="btn primary" style={{ marginTop: 10 }} disabled={!typed.trim()}>
              {t("pair.findCode")}
            </button>
          </form>
        ) : null}

        {step.kind === "found" ? (
          <>
            <p style={{ margin: "0 0 4px", fontWeight: 700 }}>{t("pair.title")}</p>
            <p className="item-sub" style={{ margin: "0 0 8px" }}>
              {t("pair.body")}
            </p>
            <ul style={{ margin: "0 0 12px", paddingLeft: 18 }}>
              {step.agents.map((a) => (
                <li key={a.aid}>🤖 {a.label}</li>
              ))}
            </ul>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" className="btn primary" onClick={() => void add(step.joining)} data-testid="pair-add">
                {t("pair.add")}
              </button>
              <a className="btn" href="/">
                {t("pair.cancel")}
              </a>
            </div>
          </>
        ) : null}

        {step.kind === "adding" ? (
          <>
            <p style={{ margin: "0 0 6px", fontWeight: 700 }}>{t("pair.adding")}</p>
            <ul style={{ margin: 0, paddingLeft: 18 }} className="item-sub">
              {step.sent ? <li>✓ {t("pair.stepKeys")}</li> : null}
              {step.sent ? <li>{t("pair.stepWaiting")}</li> : null}
            </ul>
          </>
        ) : null}

        {step.kind === "done" ? (
          <div role="status" data-testid="pair-done">
            <p style={{ margin: "0 0 4px", fontWeight: 700 }}>✓ {t("pair.done")}</p>
            <p className="item-sub" style={{ margin: "0 0 10px" }}>
              {t("pair.doneBody")}
            </p>
            <a className="btn primary" href="/">
              {t("pair.toInbox")}
            </a>
          </div>
        ) : null}

        {step.kind === "error" ? (
          <p role="alert" data-testid={`pair-${step.message}`} style={{ margin: 0, color: "var(--danger)" }}>
            {t(`pair.${step.message}`)}
          </p>
        ) : null}
      </section>
    </AppShell>
  );
}
