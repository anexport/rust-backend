#!/usr/bin/env bash
set -euo pipefail

DB_URL=${1:-${DATABASE_URL:-}}
SOURCE_DB_URL=${SOURCE_DB_URL:-}
REPORT_PATH=${REPORT_PATH:-docs/ops/data-validation-report.md}

if [[ -z "${DB_URL}" ]]; then
  echo "DB URL is required" >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required in PATH" >&2
  exit 1
fi

count_table() {
  local conn=$1
  local table=$2
  psql "${conn}" -At -c "SELECT COUNT(*) FROM ${table};"
}

echo "Validating row counts and referential integrity checks"

profiles_count=$(count_table "${DB_URL}" "profiles")
equipment_count=$(count_table "${DB_URL}" "equipment")
equipment_photos_count=$(count_table "${DB_URL}" "equipment_photos")
conversations_count=$(count_table "${DB_URL}" "conversations")
participants_count=$(count_table "${DB_URL}" "conversation_participants")
messages_count=$(count_table "${DB_URL}" "messages")
identities_count=$(count_table "${DB_URL}" "auth_identities")

orphan_equipment_owner=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM equipment e LEFT JOIN profiles p ON p.id = e.owner_id WHERE p.id IS NULL;")
orphan_equipment_category=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM equipment e LEFT JOIN categories c ON c.id = e.category_id WHERE c.id IS NULL;")
orphan_photo_equipment=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM equipment_photos ep LEFT JOIN equipment e ON e.id = ep.equipment_id WHERE e.id IS NULL;")
orphan_participant_profile=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM conversation_participants cp LEFT JOIN profiles p ON p.id = cp.profile_id WHERE p.id IS NULL;")
orphan_participant_conversation=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM conversation_participants cp LEFT JOIN conversations c ON c.id = cp.conversation_id WHERE c.id IS NULL;")
orphan_message_sender=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM messages m LEFT JOIN profiles p ON p.id = m.sender_id WHERE p.id IS NULL;")
orphan_message_conversation=$(psql "${DB_URL}" -At -c "SELECT COUNT(*) FROM messages m LEFT JOIN conversations c ON c.id = m.conversation_id WHERE c.id IS NULL;")

if [[ "${orphan_equipment_owner}" != "0" || "${orphan_equipment_category}" != "0" || "${orphan_photo_equipment}" != "0" || "${orphan_participant_profile}" != "0" || "${orphan_participant_conversation}" != "0" || "${orphan_message_sender}" != "0" || "${orphan_message_conversation}" != "0" ]]; then
  echo "Referential integrity check failed" >&2
  exit 1
fi

source_profiles_count=""
source_equipment_count=""
source_conversations_count=""
source_messages_count=""
source_users_count=""

if [[ -n "${SOURCE_DB_URL}" ]]; then
  echo "Comparing against source row counts"
  source_profiles_count=$(count_table "${SOURCE_DB_URL}" "public.profiles")
  source_equipment_count=$(count_table "${SOURCE_DB_URL}" "public.equipment")
  source_conversations_count=$(count_table "${SOURCE_DB_URL}" "public.conversations")
  source_messages_count=$(count_table "${SOURCE_DB_URL}" "public.messages")
  source_users_count=$(count_table "${SOURCE_DB_URL}" "auth.users")
fi

mkdir -p "$(dirname "${REPORT_PATH}")"
cat > "${REPORT_PATH}" <<EOF
# Data Validation Report

Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Scope: Supabase -> Rust backend migration validation
Status: Completed

## Target Counts
- profiles: ${profiles_count}
- auth_identities: ${identities_count}
- equipment: ${equipment_count}
- equipment_photos: ${equipment_photos_count}
- conversations: ${conversations_count}
- conversation_participants: ${participants_count}
- messages: ${messages_count}

## Referential Integrity
- equipment.owner_id -> profiles.id: ${orphan_equipment_owner} orphan rows
- equipment.category_id -> categories.id: ${orphan_equipment_category} orphan rows
- equipment_photos.equipment_id -> equipment.id: ${orphan_photo_equipment} orphan rows
- conversation_participants.profile_id -> profiles.id: ${orphan_participant_profile} orphan rows
- conversation_participants.conversation_id -> conversations.id: ${orphan_participant_conversation} orphan rows
- messages.sender_id -> profiles.id: ${orphan_message_sender} orphan rows
- messages.conversation_id -> conversations.id: ${orphan_message_conversation} orphan rows
EOF

if [[ -n "${SOURCE_DB_URL}" ]]; then
  cat >> "${REPORT_PATH}" <<EOF

## Source vs Target Counts
- profiles: source=${source_profiles_count}, target=${profiles_count}
- equipment: source=${source_equipment_count}, target=${equipment_count}
- conversations: source=${source_conversations_count}, target=${conversations_count}
- messages: source=${source_messages_count}, target=${messages_count}
- auth users vs identities: source(auth.users)=${source_users_count}, target(auth_identities)=${identities_count}
EOF
fi

echo "Validation checks completed"
echo "Report written to ${REPORT_PATH}"
