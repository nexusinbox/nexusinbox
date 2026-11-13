"use client";

// The confirmation number with another agent (docs/40 §16.2, mock
// docs/40_stage6_mock.html ① ②). Both people read it aloud; "same" seals
// the checked root into the contact, "different" stops sending to it.

import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { confirmationNumber } from "@nexusinbox/core/confirmation";
import { defaultApiClient } from "../../lib/api/client";
import { queryKeys } from "../../lib/api/hooks";
import type { Agent, ContactEntry } from "../../lib/api/types";
import { sealForSave } from "../../lib/contacts/address-book";
import { checkedRoot } from "../../lib/crypto/device-wraps";
import { useTranslation } from "../../lib/i18n";

type Loaded = { kind: "loading" } | { kind: "ready"; root: string; number: string } | { kind: "unavailable" };

export function ConfirmationPanel({
  counterpart,
  name,
  ownAgent,
  contact,
}: {
  /** The other agent: an AID, or a DID of it. */
  counterpart: string;
  /** The other agent as the person knows it. */
  name: string;
  ownAgent: Pick<Agent, "did" | "label">;
  /** The contact the result is sealed into; without one, the number only. */
  contact: ContactEntry | null;
}) {
  const { t, locale } = useTranslation();
  const queryClient = useQueryClient();
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<"same" | "different" | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoaded({ kind: "loading" });
    void (async () => {
      try {
        const served = await defaultApiClient.resolveRecipient(counterpart);
        const checked = await checkedRoot(served.aid);
        if (cancelled) return;
        if ("stop" in checked) {
          setLoaded({ kind: "unavailable" });
          return;
        }
        // The own agent's root is the DID it was created with (docs/40 §4.1).
        const number = await confirmationNumber(ownAgent.did, checked.root);
        if (!cancelled) setLoaded({ kind: "ready", root: checked.root, number });
      } catch {
        if (!cancelled) setLoaded({ kind: "unavailable" });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [counterpart, ownAgent.did]);

  const record = async (same: boolean) => {
    if (!contact || loaded.kind !== "ready") return;
    setSaving(true);
    setFailed(false);
    try {
      const sealed = await sealForSave(defaultApiClient, contact.did, {
        person_name: contact.person_name,
        agent_label: contact.agent_label,
        note: contact.note,
        aid: contact.aid ?? null,
        // Matching numbers check the root shown; a mismatch keeps the old one.
        root: same ? loaded.root : (contact.root ?? loaded.root),
        verified: same ? { root: loaded.root, at: new Date().toISOString() } : null,
        distrusted_root: same ? null : loaded.root,
      });
      await defaultApiClient.updateContact(contact.id, { sealed });
      await queryClient.invalidateQueries({ queryKey: queryKeys.contacts() });
      setSaved(same ? "same" : "different");
    } catch {
      setFailed(true);
    } finally {
      setSaving(false);
    }
  };

  const verifiedHere =
    loaded.kind === "ready" && contact?.verified?.root === loaded.root ? contact.verified : null;
  const distrustedHere = loaded.kind === "ready" && contact?.distrusted_root === loaded.root;
  const date = (iso: string) =>
    new Date(iso).toLocaleDateString(locale === "ja" ? "ja-JP" : "en-US", { month: "numeric", day: "numeric" });

  return (
    <div data-testid="confirmation-panel" style={{ marginTop: 12 }}>
      <p style={{ margin: "0 0 4px", fontWeight: 700 }}>{t("confirm.title")}</p>
      {loaded.kind === "loading" ? (
        <p className="item-sub" style={{ margin: 0 }}>
          {t("confirm.loading")}
        </p>
      ) : loaded.kind === "unavailable" ? (
        <p className="item-sub" style={{ margin: 0 }}>
          {t("confirm.unavailable", { name })}
        </p>
      ) : (
        <>
          {verifiedHere && saved !== "different" ? (
            <p className="item-sub" data-testid="confirmation-verified" style={{ margin: "0 0 4px", color: "var(--ok)" }}>
              {t("confirm.verifiedAt", { date: date(verifiedHere.at) })}
            </p>
          ) : null}
          <p className="item-sub" style={{ margin: 0 }}>
            {t("confirm.body", { own: ownAgent.label, name })}
          </p>
          <p
            data-testid="confirmation-number"
            style={{
              margin: "8px 0",
              padding: "12px 14px",
              borderRadius: 12,
              background: "var(--primary-soft)",
              textAlign: "center",
              font: "700 20px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace",
              letterSpacing: 1,
            }}
          >
            {loaded.number}
          </p>
          {!contact ? (
            <p className="item-sub" style={{ margin: 0 }}>
              {t("confirm.needContact")}
            </p>
          ) : saved === "same" || (verifiedHere && saved === null) ? null : saved === "different" || distrustedHere ? (
            <p className="item-sub" role="status" style={{ margin: 0, color: "var(--danger)" }}>
              {t("confirm.differentDone", { name })}
            </p>
          ) : (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                type="button"
                className="btn primary"
                disabled={saving}
                onClick={() => void record(true)}
                data-testid="confirmation-same"
              >
                {t("confirm.same")}
              </button>
              <button
                type="button"
                className="btn"
                style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                disabled={saving}
                onClick={() => void record(false)}
                data-testid="confirmation-different"
              >
                {t("confirm.different")}
              </button>
            </div>
          )}
          {saved === "same" ? (
            <p className="item-sub" role="status" style={{ margin: "4px 0 0", color: "var(--ok)" }}>
              {t("confirm.sameDone")}
            </p>
          ) : null}
          {failed ? (
            <p className="item-sub" role="status" style={{ margin: "4px 0 0", color: "var(--danger)" }}>
              {t("confirm.failed")}
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}
