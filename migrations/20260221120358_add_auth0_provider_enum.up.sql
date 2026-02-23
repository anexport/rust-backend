-- Add auth0 value to auth_provider enum
-- This must be in its own migration because ALTER TYPE ADD VALUE
-- cannot run in a transaction with other statements
ALTER TYPE auth_provider ADD VALUE IF NOT EXISTS 'auth0';
