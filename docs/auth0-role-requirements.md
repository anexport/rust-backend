# Auth0 Role Requirements For Equipment Listing

`POST /api/equipment` is protected by role authorization in the backend.

## Required Role

To create equipment listings, the authenticated user must have role:
- `owner`, or
- `admin`

If the token role resolves to `renter` (or is missing), the API returns `403 Forbidden`.

## Where Backend Reads Role

The backend checks role from Auth0 token claims via:
- `src/utils/auth0_claims.rs` (`map_auth0_role`)
- `src/api/routes/equipment.rs` (`create_equipment`)

Supported claim keys:
- `https://<AUTH0_DOMAIN>/roles` (array or string)
- `https://<AUTH0_DOMAIN>/role` (string)
- `roles`
- `role`

If none are present, backend defaults role to `renter`.

## Auth0 Setup Checklist

1. Create role `owner` in Auth0 (`User Management -> Roles`).
2. Assign `owner` role to target user (`User Management -> Users -> <user> -> Roles`).
3. Add a Post-Login Action that injects role claims into the **access token**.
4. Deploy and attach that Action to the Login Flow.
5. Log out and log back in to mint a new token with updated claims.

## Quick Verify

Call `GET /api/auth/me` from the logged-in frontend session and confirm `"role": "owner"` (or `"admin"`).
