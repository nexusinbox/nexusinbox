-- docs/38 §3 1: a computer's key stayed `active` after its credential was
-- revoked, shut down or marked compromised, so senders kept wrapping new
-- messages for it. The API now retires the key when the credential stops;
-- this applies the same rule to keys stopped before that change.
-- A key that an active credential still uses is left alone.
UPDATE agent_identity_keys k
SET status = CASE WHEN EXISTS (
        SELECT 1 FROM agent_credentials c
        WHERE c.aid = k.aid AND c.signing_public_key = k.signing_public_key
          AND c.status = 'compromised'
      ) THEN 'compromised' ELSE 'retired' END,
    retired_at = NOW()
WHERE k.status IN ('active', 'rotating')
  AND EXISTS (
    SELECT 1 FROM agent_credentials c
    WHERE c.aid = k.aid AND c.signing_public_key = k.signing_public_key
      AND c.status IN ('revoked', 'compromised')
  )
  AND NOT EXISTS (
    SELECT 1 FROM agent_credentials c
    WHERE c.aid = k.aid AND c.signing_public_key = k.signing_public_key
      AND c.status = 'active'
  );

-- docs/38 §3 2: rotating a computer's credential also marked the agent's
-- own creation key (the browser's) `rotating`, which stopped it receiving
-- and sending. Rotation now touches only that credential's key; put the
-- creation keys caught by the old behaviour back.
UPDATE agent_identity_keys k
SET status = 'active'
FROM agent_identities i
JOIN agents a ON a.id = i.agent_id
WHERE i.aid = k.aid
  AND a.did = k.did
  AND k.status = 'rotating';
