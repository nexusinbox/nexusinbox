"use client";

// Policy editor for Phase 4.4a. Lives in /settings/agents right
// next to the master auto_reply toggle (see docs/25 §6). The panel
// itself only reads / writes the declarative DSL — it never fires
// the policy. That logic lands in 4.4b (evaluator) and 4.4c
// (executor).
//
// UI invariants (from the plan file):
//   - When the master switch (`agents.auto_reply`) is off, the
//     panel shows a banner — policy can still be saved (drafts are
//     valid) but no auto-reply will run.
//   - Optimistic lock: every PUT echoes back the latest `revision`;
//     save failures with a 409 prompt the user to reload.
//   - `auto_accept_if_free` (Phase 4.4d Calendar) and `delegate_
//     to_llm` (4.4e LLM) stay in the action enum but are flagged
//     "(not yet active)" so users don't expect behaviour the
//     executor can't provide yet.

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { ApiError } from "../../lib/api/client";
import {
  useAutoReplyPolicyQuery,
  useDeleteAutoReplyPolicyMutation,
  useUpdateAutoReplyPolicyMutation,
} from "../../lib/api/hooks";
import type {
  AutoReplyAction,
  AutoReplyConditions,
  AutoReplyPolicy,
  AutoReplyPriorityValue,
  AutoReplyProtocolAction,
} from "../../lib/api/types";
import { useTranslation } from "../../lib/i18n";

type Props = {
  agentId: string | null;
  /**
   * `agents.auto_reply` master switch. When false the policy is
   * still editable but won't be evaluated.
   */
  masterEnabled: boolean;
};

type DraftProtocolAction = {
  enabled: boolean;
  action: AutoReplyAction;
  min_trust_score: string; // empty string ≈ undefined
  require_contact: boolean;
  priority_at_most: AutoReplyPriorityValue | "";
  sender_in_allowlist: string; // newline-separated DIDs
  note_template: string;
};

type Draft = {
  default_action: AutoReplyAction;
  schedule_propose: DraftProtocolAction;
  task_delegate: DraftProtocolAction;
};

const ACTION_OPTIONS: AutoReplyAction[] = [
  "queue_for_human",
  "auto_accept",
  "auto_decline",
  "auto_accept_if_free",
  "delegate_to_llm",
];

const PRIORITY_OPTIONS: AutoReplyPriorityValue[] = ["high", "normal", "low", "background"];

function emptyProtocolAction(): DraftProtocolAction {
  return {
    enabled: false,
    action: "queue_for_human",
    min_trust_score: "",
    require_contact: false,
    priority_at_most: "",
    sender_in_allowlist: "",
    note_template: "",
  };
}

function draftFromPolicy(policy: AutoReplyPolicy | Record<string, never>): Draft {
  const normalised: AutoReplyPolicy = isAutoReplyPolicy(policy)
    ? policy
    : { v: 1, default_action: "queue_for_human" };
  return {
    default_action: normalised.default_action,
    schedule_propose: draftFromProtocolAction(
      normalised.protocols?.schedule_negotiation?.propose,
    ),
    task_delegate: draftFromProtocolAction(
      normalised.protocols?.task_delegation?.delegate,
    ),
  };
}

function draftFromProtocolAction(
  action: AutoReplyProtocolAction | undefined,
): DraftProtocolAction {
  if (!action) return emptyProtocolAction();
  return {
    enabled: true,
    action: action.action,
    min_trust_score:
      typeof action.conditions?.min_trust_score === "number"
        ? String(action.conditions.min_trust_score)
        : "",
    require_contact: action.conditions?.require_contact ?? false,
    priority_at_most: action.conditions?.priority_at_most ?? "",
    sender_in_allowlist: (action.conditions?.sender_in_allowlist ?? []).join("\n"),
    note_template: action.note_template ?? "",
  };
}

function protocolActionFromDraft(
  draft: DraftProtocolAction,
): AutoReplyProtocolAction | null {
  if (!draft.enabled) return null;
  const conditions: AutoReplyConditions = {};
  if (draft.min_trust_score.trim() !== "") {
    const n = Number(draft.min_trust_score);
    if (!Number.isFinite(n)) throw new Error("min_trust_score");
    conditions.min_trust_score = n;
  }
  if (draft.require_contact) conditions.require_contact = true;
  if (draft.priority_at_most) {
    conditions.priority_at_most = draft.priority_at_most;
  }
  const allowlist = draft.sender_in_allowlist
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (allowlist.length > 0) conditions.sender_in_allowlist = allowlist;
  const hasConditions = Object.keys(conditions).length > 0;
  const entry: AutoReplyProtocolAction = { action: draft.action };
  if (hasConditions) entry.conditions = conditions;
  if (draft.note_template.trim() !== "") {
    entry.note_template = draft.note_template;
  }
  return entry;
}

function policyFromDraft(draft: Draft): AutoReplyPolicy {
  const policy: AutoReplyPolicy = {
    v: 1,
    default_action: draft.default_action,
  };
  const schedule = protocolActionFromDraft(draft.schedule_propose);
  const task = protocolActionFromDraft(draft.task_delegate);
  if (schedule || task) {
    policy.protocols = {};
    if (schedule) {
      policy.protocols.schedule_negotiation = { propose: schedule };
    }
    if (task) {
      policy.protocols.task_delegation = { delegate: task };
    }
  }
  return policy;
}

function isAutoReplyPolicy(p: unknown): p is AutoReplyPolicy {
  if (!p || typeof p !== "object") return false;
  const obj = p as Record<string, unknown>;
  if (obj.v !== 1) return false;
  if (typeof obj.default_action !== "string") return false;
  return ACTION_OPTIONS.includes(obj.default_action as AutoReplyAction);
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function AutoReplyPolicyPanel({ agentId, masterEnabled }: Props) {
  const { t } = useTranslation();
  const query = useAutoReplyPolicyQuery(agentId);
  const updateMutation = useUpdateAutoReplyPolicyMutation(agentId);
  const deleteMutation = useDeleteAutoReplyPolicyMutation(agentId);

  const serverDraft = useMemo<Draft>(
    () => draftFromPolicy(query.data?.policy ?? {}),
    [query.data?.policy],
  );
  const [draft, setDraft] = useState<Draft>(serverDraft);
  const [status, setStatus] = useState<
    | { kind: "info" | "ok" | "error"; text: string }
    | null
  >(null);

  // Reset local draft whenever the query reloads (e.g. after a
  // successful save writes through via onSuccess).
  useEffect(() => {
    setDraft(serverDraft);
  }, [serverDraft]);

  const dirty = !deepEqual(draft, serverDraft);
  const revision = query.data?.revision ?? 0;
  const busy = updateMutation.isPending || deleteMutation.isPending;

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    setStatus(null);
    let policy: AutoReplyPolicy;
    try {
      policy = policyFromDraft(draft);
    } catch {
      setStatus({ kind: "error", text: t("agents.policyInvalidTrustScore") });
      return;
    }
    try {
      await updateMutation.mutateAsync({ policy, revision });
      setStatus({ kind: "ok", text: t("agents.policySaved") });
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setStatus({
          kind: "error",
          text: t("agents.policyConflict"),
        });
        void query.refetch();
      } else if (err instanceof ApiError) {
        setStatus({
          kind: "error",
          text: t("agents.policySaveFailed", { message: err.message }),
        });
      } else {
        setStatus({ kind: "error", text: t("agents.policySaveFailedGeneric") });
      }
    }
  };

  const handleReset = async () => {
    setStatus(null);
    if (typeof window !== "undefined" && !window.confirm(t("agents.policyResetConfirm"))) {
      return;
    }
    try {
      await deleteMutation.mutateAsync();
      setStatus({ kind: "ok", text: t("agents.policyReset") });
    } catch (err) {
      if (err instanceof ApiError) {
        setStatus({
          kind: "error",
          text: t("agents.policySaveFailed", { message: err.message }),
        });
      } else {
        setStatus({ kind: "error", text: t("agents.policySaveFailedGeneric") });
      }
    }
  };

  if (!agentId) return null;

  return (
    <form
      className="panel"
      style={{ marginTop: 10 }}
      onSubmit={(e) => void handleSave(e)}
      data-testid="auto-reply-policy-panel"
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <p className="item-title">{t("agents.policyTitle")}</p>
        <p className="item-sub">{t("agents.policyDesc")}</p>
      </div>

      {!masterEnabled ? (
        <p
          className="item-sub"
          style={{
            marginTop: 8,
            padding: 8,
            border: "1px dashed rgba(200,160,60,0.6)",
            borderRadius: 4,
          }}
          data-testid="auto-reply-policy-master-off-banner"
        >
          {t("agents.policyMasterOff")}
        </p>
      ) : null}

      {query.isLoading ? (
        <p className="item-sub">{t("common.loading")}</p>
      ) : query.isError ? (
        <p className="item-sub" style={{ color: "crimson" }}>
          {t("agents.policyLoadFailed")}
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 10 }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span className="item-title">{t("agents.policyDefaultAction")}</span>
            <select
              value={draft.default_action}
              onChange={(e) =>
                setDraft((d) => ({
                  ...d,
                  default_action: e.target.value as AutoReplyAction,
                }))
              }
              disabled={busy}
              data-testid="auto-reply-policy-default-action"
            >
              {ACTION_OPTIONS.map((a) => (
                <option value={a} key={a}>
                  {t(`agents.policyAction.${a}`)}
                </option>
              ))}
            </select>
            <span className="item-sub">{t("agents.policyDefaultActionDesc")}</span>
          </label>

          <ProtocolActionFieldset
            heading={t("agents.policyScheduleProposeTitle")}
            description={t("agents.policyScheduleProposeDesc")}
            value={draft.schedule_propose}
            disabled={busy}
            onChange={(next) => setDraft((d) => ({ ...d, schedule_propose: next }))}
            testIdPrefix="auto-reply-policy-schedule"
            t={t}
          />

          <ProtocolActionFieldset
            heading={t("agents.policyTaskDelegateTitle")}
            description={t("agents.policyTaskDelegateDesc")}
            value={draft.task_delegate}
            disabled={busy}
            onChange={(next) => setDraft((d) => ({ ...d, task_delegate: next }))}
            testIdPrefix="auto-reply-policy-task"
            t={t}
          />

          <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <button
              type="submit"
              className="btn"
              disabled={!dirty || busy}
              data-testid="auto-reply-policy-save"
            >
              {updateMutation.isPending ? t("common.saving") : t("common.save")}
            </button>
            <button
              type="button"
              className="btn"
              disabled={busy || revision === 0}
              onClick={() => void handleReset()}
              data-testid="auto-reply-policy-reset"
            >
              {t("agents.policyResetBtn")}
            </button>
            <span className="item-sub">
              {t("agents.policyRevisionLabel", { revision })}
            </span>
            {query.data?.updated_at ? (
              <span className="item-sub">
                {t("agents.policyUpdatedAt", {
                  time: new Date(query.data.updated_at).toLocaleString(),
                })}
              </span>
            ) : null}
          </div>

          {status ? (
            <p
              className="item-sub"
              style={{ color: status.kind === "error" ? "crimson" : undefined }}
              role="status"
              data-testid="auto-reply-policy-status"
            >
              {status.text}
            </p>
          ) : null}
        </div>
      )}
    </form>
  );
}

// ---------------------------------------------------------------------------
// Per-protocol-action fieldset
// ---------------------------------------------------------------------------

type FieldsetProps = {
  heading: string;
  description: string;
  value: DraftProtocolAction;
  disabled: boolean;
  onChange: (next: DraftProtocolAction) => void;
  testIdPrefix: string;
  t: ReturnType<typeof useTranslation>["t"];
};

function ProtocolActionFieldset({
  heading,
  description,
  value,
  disabled,
  onChange,
  testIdPrefix,
  t,
}: FieldsetProps) {
  return (
    <fieldset
      style={{
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 4,
        padding: 12,
      }}
      data-testid={`${testIdPrefix}-fieldset`}
    >
      <legend className="item-title" style={{ padding: "0 6px" }}>
        {heading}
      </legend>
      <p className="item-sub" style={{ marginTop: 0 }}>
        {description}
      </p>

      <label
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          marginTop: 8,
        }}
      >
        <input
          type="checkbox"
          checked={value.enabled}
          disabled={disabled}
          onChange={(e) => onChange({ ...value, enabled: e.target.checked })}
          data-testid={`${testIdPrefix}-enabled`}
        />
        <span>{t("agents.policyProtocolOverrideEnabled")}</span>
      </label>

      {value.enabled ? (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            marginTop: 12,
          }}
        >
          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span>{t("agents.policyActionFor", { section: heading })}</span>
            <select
              value={value.action}
              disabled={disabled}
              onChange={(e) =>
                onChange({ ...value, action: e.target.value as AutoReplyAction })
              }
              data-testid={`${testIdPrefix}-action`}
            >
              {ACTION_OPTIONS.map((a) => (
                <option value={a} key={a}>
                  {t(`agents.policyAction.${a}`)}
                </option>
              ))}
            </select>
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span>{t("agents.policyMinTrustScore")}</span>
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={value.min_trust_score}
              disabled={disabled}
              placeholder="0.5"
              onChange={(e) =>
                onChange({ ...value, min_trust_score: e.target.value })
              }
              data-testid={`${testIdPrefix}-trust-score`}
            />
          </label>

          <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={value.require_contact}
              disabled={disabled}
              onChange={(e) =>
                onChange({ ...value, require_contact: e.target.checked })
              }
              data-testid={`${testIdPrefix}-require-contact`}
            />
            <span>{t("agents.policyRequireContact")}</span>
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span>{t("agents.policyPriorityAtMost")}</span>
            <select
              value={value.priority_at_most}
              disabled={disabled}
              onChange={(e) =>
                onChange({
                  ...value,
                  priority_at_most: e.target.value as AutoReplyPriorityValue | "",
                })
              }
              data-testid={`${testIdPrefix}-priority`}
            >
              <option value="">{t("agents.policyPriorityAny")}</option>
              {PRIORITY_OPTIONS.map((p) => (
                <option value={p} key={p}>
                  {t(`agents.policyPriority.${p}`)}
                </option>
              ))}
            </select>
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span>{t("agents.policySenderAllowlist")}</span>
            <textarea
              rows={3}
              value={value.sender_in_allowlist}
              disabled={disabled}
              placeholder="did:key:zAlice\ndid:key:zBob"
              onChange={(e) =>
                onChange({ ...value, sender_in_allowlist: e.target.value })
              }
              data-testid={`${testIdPrefix}-allowlist`}
            />
            <span className="item-sub">{t("agents.policySenderAllowlistDesc")}</span>
          </label>

          <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span>{t("agents.policyNoteTemplate")}</span>
            <textarea
              rows={2}
              maxLength={2000}
              value={value.note_template}
              disabled={disabled}
              placeholder={t("agents.policyNoteTemplatePlaceholder")}
              onChange={(e) =>
                onChange({ ...value, note_template: e.target.value })
              }
              data-testid={`${testIdPrefix}-note`}
            />
          </label>
        </div>
      ) : null}
    </fieldset>
  );
}
