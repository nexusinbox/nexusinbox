-- Phase 4.4b: per-message auto-reply evaluator decision snapshot.
-- See docs/25b_auto_reply_evaluator_decision_model.md §5.4 for the
-- design decision.
--
-- Scope: these two columns cache the *last* decision that the
-- evaluator emitted for a recipient-side message_index row, so the
-- inbox list endpoint can surface a "policy suggests auto-accept"
-- badge without JOINing agent_audit_log on every page load.
--
-- Semantics:
--   NULL         — evaluator has not run for this row yet
--                  (pre-4.4b row, or AGENT_INBOX_AUTO_REPLY_EVALUATOR=off)
--   non-NULL     — most recent decision from whichever evaluator mode
--                  touched the row last (server_metadata_v1 in 4.4b;
--                  client_protocol_v1 / daemon_protocol_v1 in later phases
--                  may overwrite). The audit log keeps full history.
--
-- Rollback: ALTER TABLE message_index
--             DROP COLUMN auto_reply_reason,
--             DROP COLUMN auto_reply_decision;

ALTER TABLE message_index
    ADD COLUMN IF NOT EXISTS auto_reply_decision TEXT NULL,
    ADD COLUMN IF NOT EXISTS auto_reply_reason   TEXT NULL;

COMMENT ON COLUMN message_index.auto_reply_decision IS
    'Last evaluated auto-reply action enum value (queue_for_human | auto_accept | auto_decline | auto_accept_if_free | delegate_to_llm). NULL = not evaluated.';
COMMENT ON COLUMN message_index.auto_reply_reason IS
    'Short machine-readable reason code for the cached decision (e.g. master_off, trust_below_threshold, default_match). NULL when decision is NULL.';
