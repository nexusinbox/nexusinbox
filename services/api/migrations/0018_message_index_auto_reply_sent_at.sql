-- Phase 4.4c: executor idempotency column for the Mode B auto-reply path.
-- See docs/25c_auto_reply_executor_mode_b.md §3.2 for the design.
--
-- `auto_reply_sent_at` flips from NULL → NOW() the moment the browser
-- executor (or, later, the Mode A signer daemon) confirms that an
-- auto-reply has been dispatched for this recipient-side row. The
-- PATCH /messages/:id/auto-reply-sent handler predicates its UPDATE on
-- `WHERE auto_reply_sent_at IS NULL`, so multi-tab races and page
-- refreshes cannot produce duplicate replies.
--
-- Rollback:
--   ALTER TABLE message_index DROP COLUMN auto_reply_sent_at;
--   DROP INDEX IF EXISTS idx_message_index_auto_reply_pending;

ALTER TABLE message_index
    ADD COLUMN IF NOT EXISTS auto_reply_sent_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN message_index.auto_reply_sent_at IS
    'Timestamp the executor confirmed an auto-reply was dispatched. NULL = pending (evaluator suggested an action but executor has not run yet) or not applicable.';

-- Partial index for the executor's "what still needs a reply?" query.
-- Matches rows that the evaluator stamped an action on but no executor
-- has handled yet. Cheap because the partial predicate filters out
-- the overwhelming majority of rows (all pre-4.4b messages, plus the
-- human-handled ones).
CREATE INDEX IF NOT EXISTS idx_message_index_auto_reply_pending
    ON message_index(owner_user_id, created_at DESC)
    WHERE auto_reply_decision IS NOT NULL AND auto_reply_sent_at IS NULL;
