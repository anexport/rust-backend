ALTER TABLE user_sessions
    ADD COLUMN family_id UUID,
    ADD COLUMN replaced_by UUID REFERENCES user_sessions(id),
    ADD COLUMN revoked_reason TEXT,
    ADD COLUMN created_ip TEXT,
    ADD COLUMN last_seen_at TIMESTAMPTZ;

UPDATE user_sessions
SET family_id = id
WHERE family_id IS NULL;

ALTER TABLE user_sessions
    ALTER COLUMN family_id SET NOT NULL;

DROP INDEX IF EXISTS idx_sessions_refresh_token_hash;
CREATE INDEX idx_sessions_refresh_token_hash
    ON user_sessions(refresh_token_hash);

CREATE INDEX idx_sessions_family_active
    ON user_sessions(family_id)
    WHERE revoked_at IS NULL;
