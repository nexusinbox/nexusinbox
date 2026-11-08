-- 0024_audit_auto_reply_aid.sql
--
-- `auto_reply_evaluated` and `auto_reply_sent` audit rows were written
-- without the agent's AID, so filtering the audit log by agent (the
-- settings page's decision history, the agent status card of docs/31)
-- never found them. The API now records it; this fills it in for older
-- rows from what each row already names: the agent id of an evaluation,
-- the recipient DID of a send. Only rows with no AID are touched.

UPDATE agent_audit_log l
   SET aid = ai.aid
  FROM agent_identities ai
 WHERE l.aid IS NULL
   AND l.event = 'auto_reply_evaluated'
   AND ai.agent_id::text = l.detail->>'agent_id';

UPDATE agent_audit_log l
   SET aid = k.aid
  FROM agent_identity_keys k
 WHERE l.aid IS NULL
   AND l.event = 'auto_reply_sent'
   AND k.did = l.detail->>'recipient_did';
