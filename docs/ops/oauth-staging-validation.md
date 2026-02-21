# OAuth Staging Validation

Date: February 21, 2026

## Prerequisites

- Staging backend deployed and reachable.
- Google OAuth app configured with staging callback origin.
- GitHub OAuth app configured with staging callback origin.
- Staging env vars set:
  - `OAUTH__GOOGLE_CLIENT_ID`
  - `OAUTH__GOOGLE_CLIENT_SECRET`
  - `OAUTH__GITHUB_CLIENT_ID`
  - `OAUTH__GITHUB_CLIENT_SECRET`

## Validation Cases

1. Google login creates user + identity:
   - First login with a new Google account.
   - Expect 200, access token in body, refresh/csrf cookies set.
2. Google login on existing email links account:
   - Existing email/password user logs in with same Google email.
   - Expect no duplicate profile; new provider identity attached.
3. GitHub login creates user + identity:
   - First login with a new GitHub account.
4. GitHub login on existing email links account:
   - Existing email/password user logs in with same GitHub email.
5. OAuth state protection:
   - Missing or mismatched `state` is rejected with 401.

## DB Checks (staging)

- `profiles` has no duplicate email rows.
- `auth_identities` contains expected provider rows:
  - `provider in ('google', 'github')`
  - `provider_id` non-null for OAuth identities.

## API Probe Script

Use `/Users/mykolborghese/rust-backend/scripts/validate_oauth_staging.sh` for callback checks once you obtain real provider auth codes.
