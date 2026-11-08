-- 0025_message_index_auto_reply_message_id.sql
--
-- Marking an auto-reply "sent" also covers rows an executor handled
-- without answering (not a request, a policy override, …), so the inbox
-- labelled those "auto-replied" too. Keep the id of the reply when there
-- is one; the inbox shows the label only then (docs/31 §5.6).
--
-- Older rows get it from the `auto_reply_sent` audit events, which have
-- carried `reply_message_id` all along. Rows whose events are gone keep
-- NULL and lose a label they may not have deserved.

ALTER TABLE message_index ADD COLUMN IF NOT EXISTS auto_reply_message_id UUID;

UPDATE message_index m
   SET auto_reply_message_id = (l.detail->>'reply_message_id')::uuid
  FROM agent_audit_log l
 WHERE m.auto_reply_message_id IS NULL
   AND m.auto_reply_sent_at IS NOT NULL
   AND l.event = 'auto_reply_sent'
   AND l.user_id = m.owner_user_id
   AND l.detail->>'message_id' = m.id::text
   AND l.detail->>'reply_message_id' ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';
