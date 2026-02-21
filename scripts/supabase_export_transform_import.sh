#!/usr/bin/env bash
set -euo pipefail

MODE=${1:-dry-run}
EXPORT_DIR=${EXPORT_DIR:-./tmp/supabase-export}
SUPABASE_DB_URL=${SUPABASE_DB_URL:-}
TARGET_DB_URL=${TARGET_DB_URL:-${DATABASE_URL:-}}
NOW_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ "${MODE}" != "dry-run" && "${MODE}" != "apply" ]]; then
  echo "Usage: $0 [dry-run|apply]" >&2
  exit 1
fi

if [[ -z "${SUPABASE_DB_URL}" ]]; then
  echo "SUPABASE_DB_URL is required" >&2
  exit 1
fi

if [[ -z "${TARGET_DB_URL}" ]]; then
  echo "TARGET_DB_URL or DATABASE_URL is required" >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required in PATH" >&2
  exit 1
fi

mkdir -p "${EXPORT_DIR}"

echo "[1/4] Exporting Supabase tables to ${EXPORT_DIR}"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, email, role, username, full_name, avatar_url, created_at, updated_at FROM public.profiles) TO '${EXPORT_DIR}/profiles.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, owner_id, category_id, title, description, daily_rate, condition, location, coordinates::text AS coordinates, is_available, created_at, updated_at FROM public.equipment) TO '${EXPORT_DIR}/equipment.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM public.equipment_photos) TO '${EXPORT_DIR}/equipment_photos.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, parent_id, name, description, icon_name, sort_order, created_at FROM public.categories) TO '${EXPORT_DIR}/categories.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, created_at, updated_at FROM public.conversations) TO '${EXPORT_DIR}/conversations.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, conversation_id, profile_id, last_read_at, created_at FROM public.conversation_participants) TO '${EXPORT_DIR}/conversation_participants.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, conversation_id, sender_id, content, created_at FROM public.messages) TO '${EXPORT_DIR}/messages.csv' WITH (FORMAT csv, HEADER true)"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id, email, email_confirmed_at, created_at FROM auth.users) TO '${EXPORT_DIR}/auth_users.csv' WITH (FORMAT csv, HEADER true)"

echo "[2/4] Transforming Supabase auth users -> auth_identities"
psql "${SUPABASE_DB_URL}" -v ON_ERROR_STOP=1 -c "\copy (SELECT id AS id, id AS user_id, 'email'::text AS provider, NULL::text AS provider_id, NULL::text AS password_hash, (email_confirmed_at IS NOT NULL) AS verified, COALESCE(created_at, '${NOW_UTC}'::timestamptz) AS created_at FROM auth.users) TO '${EXPORT_DIR}/auth_identities.csv' WITH (FORMAT csv, HEADER true)"

echo "[3/4] Importing data into target Postgres (${MODE})"
if [[ "${MODE}" == "apply" ]]; then
  psql "${TARGET_DB_URL}" -v ON_ERROR_STOP=1 <<SQL
BEGIN;
TRUNCATE TABLE
  messages,
  conversation_participants,
  conversations,
  equipment_photos,
  equipment,
  auth_identities,
  categories,
  profiles
RESTART IDENTITY CASCADE;

\copy profiles (id, email, role, username, full_name, avatar_url, created_at, updated_at) FROM '${EXPORT_DIR}/profiles.csv' WITH (FORMAT csv, HEADER true);
\copy categories (id, parent_id, name, description, icon_name, sort_order, created_at) FROM '${EXPORT_DIR}/categories.csv' WITH (FORMAT csv, HEADER true);
\copy equipment (id, owner_id, category_id, title, description, daily_rate, condition, location, coordinates, is_available, created_at, updated_at) FROM '${EXPORT_DIR}/equipment.csv' WITH (FORMAT csv, HEADER true);
\copy equipment_photos (id, equipment_id, photo_url, is_primary, order_index, created_at) FROM '${EXPORT_DIR}/equipment_photos.csv' WITH (FORMAT csv, HEADER true);
\copy conversations (id, created_at, updated_at) FROM '${EXPORT_DIR}/conversations.csv' WITH (FORMAT csv, HEADER true);
\copy conversation_participants (id, conversation_id, profile_id, last_read_at, created_at) FROM '${EXPORT_DIR}/conversation_participants.csv' WITH (FORMAT csv, HEADER true);
\copy messages (id, conversation_id, sender_id, content, created_at) FROM '${EXPORT_DIR}/messages.csv' WITH (FORMAT csv, HEADER true);
\copy auth_identities (id, user_id, provider, provider_id, password_hash, verified, created_at) FROM '${EXPORT_DIR}/auth_identities.csv' WITH (FORMAT csv, HEADER true);
COMMIT;
SQL
else
  echo "Dry-run mode: import skipped (artifacts generated at ${EXPORT_DIR})"
fi

echo "[4/4] Running validation checks"
SOURCE_DB_URL="${SUPABASE_DB_URL}" ./scripts/validate_migration.sh "${TARGET_DB_URL}"

echo "Done"
