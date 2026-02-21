ALTER TABLE auth_identities
    DROP CONSTRAINT IF EXISTS auth_identities_check;

ALTER TABLE auth_identities
    ALTER COLUMN provider TYPE TEXT
    USING provider::text;

ALTER TABLE equipment
    ALTER COLUMN condition TYPE TEXT
    USING condition::text;

ALTER TABLE profiles
    ALTER COLUMN role TYPE TEXT
    USING role::text;

ALTER TABLE profiles
    ADD CONSTRAINT profiles_role_check
    CHECK (role IN ('renter', 'owner', 'admin'));

ALTER TABLE equipment
    ADD CONSTRAINT equipment_condition_check
    CHECK (condition IN ('new', 'excellent', 'good', 'fair'));

ALTER TABLE auth_identities
    ADD CONSTRAINT auth_identities_provider_check
    CHECK (provider IN ('email', 'google', 'github'));

ALTER TABLE auth_identities
    ADD CONSTRAINT auth_identities_check
    CHECK (
        (provider = 'email' AND provider_id IS NULL AND password_hash IS NOT NULL)
        OR
        (provider IN ('google', 'github') AND provider_id IS NOT NULL AND password_hash IS NULL)
    );

DROP TYPE IF EXISTS auth_provider;
DROP TYPE IF EXISTS condition;
DROP TYPE IF EXISTS role;
