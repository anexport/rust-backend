# Role Requirements For Equipment Listing

`POST /api/equipment` is protected by role authorization in the backend.

## Required Role

To create equipment listings, the authenticated user must have role:
- `owner`, or
- `admin`

If the user's database role is `renter` (or missing), the API returns `403 Forbidden`.

## Role Architecture

**Roles are stored in the database as the single source of truth.**

The backend no longer uses Auth0 token claims for role authorization. Instead:

1. **Database Lookup**: All role checks query the database directly via the `users` table
2. **Default Assignment**: When a new user first authenticates, `map_auth0_role` in `src/utils/auth0_claims.rs` provides a default role (`renter`) for initial user record creation
3. **Admin Promotion**: Admin users can promote others via the admin panel - no Auth0 configuration or re-login required

### Backend Role Check Location

- `src/api/routes/equipment.rs` (`create_equipment`)

## Promoting a User to Admin

1. An existing admin logs in
2. Navigate to the admin panel
3. Select the target user and change their role to `owner` or `admin`
4. The user's permissions update immediately - no re-login needed

## Quick Verify

Call `GET /api/auth/me` from the logged-in frontend session and confirm `"role": "owner"` (or `"admin"`).

## Legacy Auth0 Setup (Optional)

Auth0 roles and Post-Login Actions are **no longer required** for role authorization. They may still be used for other purposes, but the `map_auth0_role` function only serves as a default value for new user records.
