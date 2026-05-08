-- Production readiness: add missing indexes for common query patterns.

-- message_index: sender_did lookups (spam reporting, trust-score, outbox)
CREATE INDEX IF NOT EXISTS idx_message_index_sender_did
    ON message_index(sender_did);

-- message_index: status-based queries (pending_approval queue, folder filters)
CREATE INDEX IF NOT EXISTS idx_message_index_status
    ON message_index(status);

-- agent_tokens: refresh token lookup (used in POST /agent-auth/refresh)
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tokens_refresh_hash
    ON agent_tokens(refresh_hash)
    WHERE refresh_hash IS NOT NULL;

-- agent_audit_log: credential + event + time range (Policy L3 send count)
CREATE INDEX IF NOT EXISTS idx_audit_log_credential_event_time
    ON agent_audit_log(credential_id, event, created_at DESC)
    WHERE credential_id IS NOT NULL;
