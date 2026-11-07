-- 0019_message_index_auto_reply_claimed_at.sql
--
-- At-most-once auto-replies (docs/29 §2.5). An executor (a browser tab
-- or the Agent Gateway) claims a row with a conditional UPDATE before it
-- sends, so two executors cannot both reply. A row that stays claimed
-- without auto_reply_sent_at was attempted but not confirmed; it drops
-- out of the pending list and is left to the human.

ALTER TABLE message_index
    ADD COLUMN IF NOT EXISTS auto_reply_claimed_at TIMESTAMPTZ;
