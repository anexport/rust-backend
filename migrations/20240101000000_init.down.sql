-- Drop triggers
DROP TRIGGER IF EXISTS update_conversations_updated_at ON conversations;
DROP TRIGGER IF EXISTS update_equipment_updated_at ON equipment;
DROP TRIGGER IF EXISTS update_profiles_updated_at ON profiles;
DROP TRIGGER IF EXISTS ensure_message_sender_is_participant_trigger ON messages;

-- Drop functions
DROP FUNCTION IF EXISTS update_updated_at();
DROP FUNCTION IF EXISTS ensure_message_sender_is_participant();

-- Drop tables (indexes are dropped automatically with tables)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS conversation_participants;
DROP TABLE IF EXISTS conversations;
DROP TABLE IF EXISTS equipment_photos;
DROP TABLE IF EXISTS equipment;
DROP TABLE IF EXISTS categories;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS auth_identities;
DROP TABLE IF EXISTS renter_profiles;
DROP TABLE IF EXISTS owner_profiles;
DROP TABLE IF EXISTS profiles;

-- Drop extensions
DROP EXTENSION IF EXISTS postgis;
DROP EXTENSION IF EXISTS pgcrypto;
