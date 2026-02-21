#!/usr/bin/env bash
set -euo pipefail

APP_BASE_URL=${APP_BASE_URL:-}
GOOGLE_CODE=${GOOGLE_CODE:-}
GITHUB_CODE=${GITHUB_CODE:-}
STATE=${STATE:-staging-oauth-state}

if [[ -z "${APP_BASE_URL}" ]]; then
  echo "APP_BASE_URL is required (example: https://staging-api.example.com)" >&2
  exit 1
fi

if [[ -z "${GOOGLE_CODE}" && -z "${GITHUB_CODE}" ]]; then
  echo "At least one of GOOGLE_CODE or GITHUB_CODE must be set." >&2
  exit 1
fi

run_probe() {
  local provider=$1
  local code=$2

  echo "== ${provider} callback =="
  curl -sS -i \
    -H "Content-Type: application/json" \
    --cookie "oauth_state=${STATE}" \
    -X POST "${APP_BASE_URL}/api/auth/oauth/${provider}" \
    --data "{\"code\":\"${code}\",\"state\":\"${STATE}\"}"
  echo
}

if [[ -n "${GOOGLE_CODE}" ]]; then
  run_probe "google" "${GOOGLE_CODE}"
fi

if [[ -n "${GITHUB_CODE}" ]]; then
  run_probe "github" "${GITHUB_CODE}"
fi
