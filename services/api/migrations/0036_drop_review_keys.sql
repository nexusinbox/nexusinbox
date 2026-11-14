-- 0036_drop_review_keys.sql
--
-- Drafts are read by the devices on the agent's list since v0.7.0 (docs/40
-- §16.3): the computer wraps a draft's content key to each of them. The
-- separate list of review browsers (review_keys) and the wraps made for it
-- (agent_drafts.review_wraps) are no longer used. Drafts made by computers
-- before v0.7.0 relied on them; drafts expire after 7 days.

ALTER TABLE agent_drafts DROP COLUMN IF EXISTS review_wraps;
DROP TABLE IF EXISTS review_keys;
