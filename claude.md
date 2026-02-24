# Claude Notes

## Auth0 Role Requirement For Equipment Creation

`POST /api/equipment` requires Auth0 role `owner` or `admin` in the access token.

If role claims are missing, backend role resolution defaults to `renter`, and equipment creation returns `403 Forbidden`.

For setup steps and claim keys, see:
- `docs/auth0-role-requirements.md`
