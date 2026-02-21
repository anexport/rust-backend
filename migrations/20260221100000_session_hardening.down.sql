DROP INDEX IF EXISTS idx_sessions_family_active;
DROP INDEX IF EXISTS idx_sessions_refresh_token_hash;
CREATE INDEX idx_sessions_refresh_token_hash
    ON user_sessions(refresh_token_hash)
    WHERE revoked_at IS NULL;

ALTER TABLE user_sessions
    DROP COLUMN IF EXISTS last_seen_at,
    DROP COLUMN IF EXISTS created_ip,
    DROP COLUMN IF EXISTS revoked_reason,
    DROP COLUMN IF EXISTS replaced_by,
    DROP COLUMN IF EXISTS family_id;
