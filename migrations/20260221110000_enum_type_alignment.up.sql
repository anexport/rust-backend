-- Align database column types with sqlx enum mappings in Rust domain models.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'role') THEN
        CREATE TYPE role AS ENUM ('renter', 'owner', 'admin');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'condition') THEN
        CREATE TYPE condition AS ENUM ('new', 'excellent', 'good', 'fair');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'auth_provider') THEN
        CREATE TYPE auth_provider AS ENUM ('email', 'google', 'github');
    END IF;
END $$;

ALTER TABLE profiles
    DROP CONSTRAINT IF EXISTS profiles_role_check;

ALTER TABLE equipment
    DROP CONSTRAINT IF EXISTS equipment_condition_check;

ALTER TABLE auth_identities
    DROP CONSTRAINT IF EXISTS auth_identities_provider_check;

ALTER TABLE auth_identities
    DROP CONSTRAINT IF EXISTS auth_identities_check;

ALTER TABLE profiles
    ALTER COLUMN role TYPE role
    USING role::role;

ALTER TABLE equipment
    ALTER COLUMN condition TYPE condition
    USING condition::condition;

ALTER TABLE auth_identities
    ALTER COLUMN provider TYPE auth_provider
    USING provider::auth_provider;

ALTER TABLE auth_identities
    ADD CONSTRAINT auth_identities_check
    CHECK (
        (provider = 'email' AND provider_id IS NULL AND password_hash IS NOT NULL)
        OR
        (provider IN ('google', 'github') AND provider_id IS NOT NULL AND password_hash IS NULL)
    );
