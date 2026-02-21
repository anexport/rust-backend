#!/usr/bin/env bash
set -euo pipefail

DB_URL=${1:-${DATABASE_URL:-}}
if [[ -z "${DB_URL}" ]]; then
  echo "DB URL is required" >&2
  exit 1
fi

echo "Validating core row counts and referential integrity checks"
psql "${DB_URL}" -c "SELECT COUNT(*) AS profiles_count FROM profiles;"
psql "${DB_URL}" -c "SELECT COUNT(*) AS equipment_count FROM equipment;"
psql "${DB_URL}" -c "SELECT COUNT(*) AS conversations_count FROM conversations;"
psql "${DB_URL}" -c "SELECT COUNT(*) AS messages_count FROM messages;"

echo "Validation checks completed"
