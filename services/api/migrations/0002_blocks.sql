-- Hierarchical block list (L1/L2/L3). Owned by the recipient user.
--   level 'l1_did'      — silent drop a specific sender DID
--   level 'l2_identity' — ban a sender World ID entirely
--   level 'l3_stealth'  — L2 + DID resolution stealth
CREATE TABLE IF NOT EXISTS blocks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  level TEXT NOT NULL CHECK (level IN ('l1_did', 'l2_identity', 'l3_stealth')),
  target_did TEXT,
  target_world_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT blocks_target_shape CHECK (
    (level = 'l1_did' AND target_did IS NOT NULL AND target_world_id IS NULL)
    OR (level IN ('l2_identity', 'l3_stealth') AND target_world_id IS NOT NULL AND target_did IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_blocks_owner ON blocks(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_blocks_target_did ON blocks(target_did) WHERE target_did IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_blocks_target_world_id ON blocks(target_world_id) WHERE target_world_id IS NOT NULL;
