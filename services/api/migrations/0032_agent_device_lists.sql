-- Signed device lists (docs/40 §4.2): the agent's root key (the browser key
-- it was created with, agents.did) signs the whole list of devices that may
-- read the agent's messages. The server stores and returns the signed list;
-- it cannot produce one. Every version is kept so a message signed by a
-- device that was later removed can still be checked (docs/40 §4.4).

CREATE TABLE IF NOT EXISTS agent_device_lists (
    aid         TEXT NOT NULL REFERENCES agent_identities(aid) ON DELETE CASCADE,
    version     BIGINT NOT NULL CHECK (version > 0),
    root_did    TEXT NOT NULL,
    jws         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (aid, version)
);
