-- Update the CHECK constraint to include auth0 provider
ALTER TABLE auth_identities
    DROP CONSTRAINT IF EXISTS auth_identities_check;

ALTER TABLE auth_identities
    ADD CONSTRAINT auth_identities_check
    CHECK (
        (provider = 'email' AND provider_id IS NULL AND password_hash IS NOT NULL)
        OR
        (provider IN ('google', 'github', 'auth0') AND provider_id IS NOT NULL AND password_hash IS NULL)
    );
