-- Split the single `deleted_at` flag into two lifecycle timestamps:
--   deleted_at — the row was marked for deletion (user DELETE /attachments/:id,
--                or cleanup-job expiring an unused intent)
--   purged_at  — the R2 object was confirmed removed
--
-- Before this migration `deleted_at` did double duty: it was only set after
-- a successful R2 delete, and a NULL value meant "still needs R2 cleanup".
-- That conflation made the cleanup driver query implicit (it looked for
-- status in ('expired','deleted') AND deleted_at IS NULL as a proxy for
-- "needs purge"). Splitting the two gives us a clear contract:
--   cleanup candidate  := deleted_at IS NOT NULL AND purged_at IS NULL
--   fully reclaimed    := purged_at IS NOT NULL
--   user intent only   := deleted_at set, purged_at NULL (retry on next pass)
--
-- Backfill: any row whose legacy `deleted_at` is set means we historically
-- believed the R2 object was gone. Treat those as purged — copy deleted_at
-- into purged_at so the cleanup driver doesn't pick them up again.

ALTER TABLE attachment_uploads
    ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ;

UPDATE attachment_uploads
SET purged_at = deleted_at
WHERE deleted_at IS NOT NULL AND purged_at IS NULL;

-- Re-target the orphan-cleanup scan index: we now find candidates by
-- "deleted but not yet purged". The old status-based index stays useful
-- for other queries.
CREATE INDEX IF NOT EXISTS idx_attachment_uploads_needs_purge
    ON attachment_uploads (deleted_at)
    WHERE deleted_at IS NOT NULL AND purged_at IS NULL;
