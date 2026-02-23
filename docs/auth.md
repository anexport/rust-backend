# Auth0 Authentication Architecture

This service uses Auth0 as the primary authentication provider. All user credentials and authentication flows are managed by Auth0, with the backend serving as a resource server that validates Auth0 access tokens.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Authentication Flow                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Email/Password Flow:                                                       │
│  ┌──────────┐      ┌──────────────┐      ┌──────────────┐      ┌────────┐  │
│  │  Client  │ ───> │ Auth0 API    │ ───> │ Auth0 DB     │ ───> │ Access │  │
│  │ (Frontend)│      │ (OAuth2)     │      │ (Users)      │      │ Token  │  │
│  └──────────┘      └──────────────┘      └──────────────┘      └────────┘  │
│       │                                                                 │
│       └───────────────────────────────────────────────────────────────────┘
│                   │                                            │
│                   ▼                                            ▼
│            ┌──────────────┐      ┌──────────────┐      ┌──────────────────┐
│            │ Backend      │ ───> │ Auth0 JWKS   │ ───> │ Token Validation │
│            │ API Routes   │      │ (Public Key) │      │ (RS256)         │
│            └──────────────┘      └──────────────┘      └──────────────────┘
│                                                                             │
│  OAuth Providers (Google, GitHub):                                         │
│  ┌──────────┐      ┌──────────────┐      ┌──────────────┐                 │
│  │  Client  │ ───> │ Auth0 OAuth  │ ───> │ Provider     │ ───> same flow   │
│  │ (Frontend)│      │ (OIDC)       │      │ (Google/GH)  │ ───> above      │
│  └──────────┘      └──────────────┘      └──────────────┘                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Storage                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Auth0 (Identity Provider):                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ • User credentials (email/password) stored in Auth0 Database        │   │
│  │ • OAuth provider tokens stored in Auth0                            │   │
│  │ • All authentication logic managed by Auth0                        │   │
│  │ • User's "sub" claim is the authoritative user identifier          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Local Database (Application Data):                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ profiles        │ Application user data (role, username, etc.)    │   │
│  │ auth_identities │ Links Auth0 users to local profiles             │   │
│  │ user_sessions   │ Local refresh token sessions (legacy/compat)    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  Relationship:                                                              │
│  profiles.id  <──  auth_identities.user_id  ──>  Auth0 user.sub (provider_id)│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Principles

1. **Auth0 is the Identity Provider**: All user credentials, password hashing, and authentication logic are handled by Auth0.

2. **Backend is a Resource Server**: The backend validates Auth0 access tokens and authorizes API requests.

3. **Just-In-Time Provisioning**: Local user profiles are created automatically on first login with a valid Auth0 token.

4. **No Local Password Storage**: Passwords are never stored locally. All email/password authentication goes through Auth0's Database Connection.

5. **Provider-Agnostic**: The backend treats all providers (email/password, Google, GitHub) uniformly via the Auth0 `sub` claim.

## Database Schema

### profiles
Application-specific user data (NOT credentials).

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key, generated locally |
| email | TEXT | User's email address |
| role | ENUM | `renter`, `owner`, or `admin` |
| username | TEXT | Optional display username |
| full_name | TEXT | Optional full name |
| avatar_url | TEXT | Optional avatar URL |
| created_at | TIMESTAMPTZ | Timestamp when profile was created |
| updated_at | TIMESTAMPTZ | Timestamp when profile was last updated |

### auth_identities
Links Auth0 users to local profiles.

| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| user_id | UUID | Foreign key to profiles.id |
| provider | ENUM | `email`, `google`, `github`, `auth0` |
| provider_id | TEXT | Auth0 user `sub` claim |
| password_hash | TEXT | NULL - no local password storage |
| verified | BOOLEAN | Whether the identity is verified |
| created_at | TIMESTAMPTZ | Timestamp when identity was linked |

**Constraints:**
- For `email` provider: `provider_id` is NULL (legacy), `password_hash` is NULL
- For `google`, `github`, `auth0`: `provider_id` is Auth0 `sub`, `password_hash` is NULL
- UNIQUE(user_id, provider) - one identity per provider per user

## Runtime Model

### Authentication Flow

1. **User Registration/Login (Email/Password)**:
   - Frontend calls Auth0 Authentication API
   - Auth0 Database Connection validates credentials
   - Auth0 issues an access token
   - Frontend sends access token to backend
   - Backend validates token against Auth0 JWKS
   - Backend provisions/links local profile via JIT provisioning

2. **OAuth Login (Google/GitHub)**:
   - Frontend redirects to Auth0 OAuth endpoint
   - User authenticates with provider
   - Auth0 issues an access token
   - Frontend sends access token to backend
   - Backend validates token against Auth0 JWKS
   - Backend provisions/links local profile via JIT provisioning

### API Authentication

- API routes use `Auth0AuthenticatedUser` extractor for bearer token authentication
- Access tokens are validated as `RS256` against Auth0 JWKS
- Claims are mapped into local `Auth0UserContext`
- Local user rows are provisioned/linked on-demand from Auth0 `sub` (JIT provisioning)

### JWT Token Structure

**Auth0 Access Token (validated by backend):**
```json
{
  "sub": "auth0|user123",           // Auth0 user identifier
  "aud": "https://api.your-app.example",
  "iss": "https://your-tenant.us.auth0.com/",
  "exp": 1234567890,
  "https://your-tenant.us.auth0.com/roles": ["renter"]
}
```

**Note:** The backend does NOT generate JWT tokens for API authentication. All access tokens must be issued by Auth0.

## Required Environment Variables

### Core Auth0 Configuration

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AUTH0_DOMAIN` | Yes | Auth0 tenant domain | `your-tenant.us.auth0.com` |
| `AUTH0_AUDIENCE` | Yes | API audience configured in Auth0 | `https://api.your-app.example` |
| `AUTH0_ISSUER` | No | Explicit issuer URL (derived from domain if not set) | `https://your-tenant.us.auth0.com/` |
| `AUTH0_JWKS_CACHE_TTL_SECS` | No | JWKS cache TTL (default: 3600) | `3600` |

### Auth0 Database Connection Configuration

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Yes (for email/password flow) | Auth0 Client ID for your application | `your-client-id` |
| `AUTH0_CLIENT_SECRET` | Yes (for password grant flow) | Auth0 Client Secret for your application | `your-client-secret` |
| `AUTH0_CONNECTION` | No | Auth0 connection name (default: Username-Password-Authentication) | `Username-Password-Authentication` |

### Legacy Configuration (OAuth Flow Only)

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | For local JWT token generation (OAuth flow only) |
| `JWT_KID` | No | JWT key ID (default: "v1") |
| `PREVIOUS_JWT_SECRETS` | No | Previous JWT secrets for rotation |
| `PREVIOUS_JWT_KIDS` | No | Previous JWT key IDs for rotation |

**Important:** The legacy `JWT_SECRET` is only used for issuing local JWT tokens during OAuth callbacks. For API authentication, all bearer tokens must be Auth0 access tokens.

## Claims and Role Mapping

Role resolution order (highest to lowest priority):

1. `https://{namespace}/roles` (array of strings)
2. `roles` (array of strings)
3. `https://{namespace}/role` (single string)
4. `role` (single string)
5. fallback: `renter`

Namespace currently uses the configured Auth0 domain when available.

Example Auth0 Action for adding roles:
```javascript
exports.onExecutePostLogin = async (event) => {
  const namespace = 'https://your-tenant.us.auth0.com';
  event.accessToken[`${namespace}/roles`] = [event.authorization.roles];
};
```

## WebSocket Authentication

- WebSocket upgrade accepts bearer token from:
  - `Authorization: Bearer ...` header
  - `Sec-WebSocket-Protocol: bearer, <token>` protocol
- WS auth validates Auth0 tokens and provisions the user context
- No separate WebSocket authentication mechanism

## Registration Flow (Email/Password)

### Frontend Implementation

```javascript
// 1. Register user via Auth0 Authentication API
const response = await fetch(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET, // Required for server-side signup
    email: 'user@example.com',
    password: 'SecurePassword123!',
    connection: 'Username-Password-Authentication'
  })
});

// 2. Login to get access token
const loginResponse = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'password',
    username: 'user@example.com',
    password: 'SecurePassword123!',
    audience: AUTH0_AUDIENCE,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET, // Required for password grant
    connection: 'Username-Password-Authentication'
  })
});

const { access_token, refresh_token } = await loginResponse.json();

// 3. Use access token with backend API
const apiResponse = await fetch('https://api.example.com/api/auth/me', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});
```

### Backend API (Optional Proxy)

For client-side applications that cannot safely store the client secret, you can proxy requests through the backend:

```rust
// POST /api/auth/register - Proxy to Auth0 signup
async fn register_proxy(
    state: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> AppResult<HttpResponse> {
    let response = state.auth0_client.signup(payload.into_inner()).await?;
    Ok(HttpResponse::Created().json(response))
}

// POST /api/auth/login - Proxy to Auth0 password grant
async fn login_proxy(
    state: web::Data<AppState>,
    payload: web::Json<LoginRequest>,
) -> AppResult<HttpResponse> {
    let tokens = state.auth0_client.password_grant(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(tokens))
}
```

### Backend Implementation

The backend validates the access token and provisions a local profile:

```rust
// User profile is automatically created on first access
// via the Auth0AuthenticatedUser extractor
async fn me(auth: Auth0AuthenticatedUser) -> AppResult<HttpResponse> {
    let result = state.auth_service.me(auth.0.user_id).await?;
    Ok(HttpResponse::Ok().json(result))
}
```

## Login Flow (Email/Password)

### Frontend Implementation

```javascript
// 1. Login via Auth0 Authentication API
const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'password',
    username: 'user@example.com',
    password: 'SecurePassword123!',
    audience: AUTH0_AUDIENCE,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET,
    connection: 'Username-Password-Authentication'
  })
});

const { access_token, refresh_token } = await response.json();

// 2. Use access token with backend API
```

### Token Refresh

```javascript
// Refresh token via Auth0
const response = await fetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'refresh_token',
    refresh_token: stored_refresh_token,
    client_id: AUTH0_CLIENT_ID,
    client_secret: AUTH0_CLIENT_SECRET
  })
});
```

## OAuth Flow (Google/GitHub)

**Important:** OAuth providers (Google, GitHub) should now be configured entirely in Auth0, not in the backend. The backend no longer handles OAuth callbacks directly.

### Configuration in Auth0

1. Configure Google/GitHub OAuth applications in Auth0 Dashboard
2. Enable the social connections in Auth0
3. Set the callback URL to your Auth0 tenant, not the backend
4. Frontend uses Auth0 Universal Login or Auth0 SDK
5. Auth0 handles the entire OAuth flow and issues tokens
6. Frontend uses Auth0 access token with backend API

### Why Auth0 for OAuth?

- **Simplified configuration**: Manage all OAuth providers in one place (Auth0 Dashboard)
- **Reduced complexity**: Backend doesn't need to handle OAuth callback state, token exchange, etc.
- **Consistent token format**: All access tokens are Auth0 tokens
- **Unified authentication**: Email/password and OAuth follow the same flow
- **Enhanced security**: Auth0 handles provider-specific security concerns

### Frontend Implementation (Auth0 SDK)

```javascript
import auth0 from 'auth0-js';

const auth0Client = new auth0.WebAuth({
  domain: AUTH0_DOMAIN,
  clientID: AUTH0_CLIENT_ID,
  redirectUri: window.location.origin,
  audience: AUTH0_AUDIENCE,
  responseType: 'token id_token',
  scope: 'openid profile email'
});

// Login with Google
auth0Client.authorize({
  connection: 'google-oauth2'
});

// Login with GitHub
auth0Client.authorize({
  connection: 'github'
});

// Handle callback and get tokens
auth0Client.parseHash((err, authResult) => {
  if (authResult && authResult.accessToken) {
    // Use authResult.accessToken with backend API
  }
});
```

## API Endpoints

### Auth0-Protected Routes (Bearer Token Required)

All API endpoints require a valid Auth0 access token:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/me` | Get current user profile |
| GET | `/api/users/:id` | Get user by ID |
| POST | `/api/equipment` | Create equipment listing |
| etc. | ... | All other API endpoints |

### Legacy Routes (for backward compatibility)

The following routes are maintained for backward compatibility with existing OAuth flows:

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Legacy registration (local flow) |
| POST | `/api/auth/login` | Legacy login (local flow) |
| POST | `/api/auth/logout` | Legacy logout |
| POST | `/api/auth/refresh` | Legacy token refresh |
| POST | `/api/auth/oauth/google` | Legacy Google OAuth callback |
| POST | `/api/auth/oauth/github` | Legacy GitHub OAuth callback |

**Note:** These legacy endpoints issue local JWT tokens for compatibility but do not support bearer token authentication for API routes. New applications should use Auth0 directly.

## Migration Guide

### For Existing Email/Password Users

If you have existing users with email/password credentials stored locally:

1. **Export existing users**: Query your local database for user credentials
2. **Import to Auth0**: Use Auth0 Management API or CSV import
3. **Update local auth_identities**: Update `provider` to `auth0`, `provider_id` to Auth0 `sub`
4. **Drop local password hashes**: Delete or nullify `password_hash` column

Example migration SQL:

```sql
-- Step 1: Prepare migration mapping table
CREATE TEMP TABLE user_migration AS
SELECT
  u.id,
  u.email,
  ai.password_hash
FROM profiles u
JOIN auth_identities ai ON ai.user_id = u.id
WHERE ai.provider = 'email';

-- Step 2: After importing to Auth0, update auth_identities
UPDATE auth_identities
SET
  provider = 'auth0',
  provider_id = 'auth0|' || email,  -- Replace with actual Auth0 sub
  password_hash = NULL
WHERE user_id IN (SELECT id FROM user_migration)
  AND provider = 'email';

-- Step 3: Remove password_hash column (optional)
ALTER TABLE auth_identities DROP COLUMN IF EXISTS password_hash;
```

### Frontend Migration Checklist

- [ ] Replace local `/register` endpoint with Auth0 `dbconnections/signup`
- [ ] Replace local `/login` endpoint with Auth0 `oauth/token` (password grant)
- [ ] Update token storage to use Auth0 tokens
- [ ] Update all API calls to use Auth0 access tokens
- [ ] Handle token expiration and refresh via Auth0
- [ ] Update OAuth buttons to use Auth0 Universal Login or SDK

### Backend Migration Checklist

- [ ] Deploy Auth0 JWKS validation middleware
- [ ] Update all API routes to use `Auth0AuthenticatedUser`
- [ ] Disable local JWT generation (optional, for compatibility)
- [ ] Remove local password storage
- [ ] Update documentation

## Security Considerations

1. **Never store passwords locally**: All password storage is Auth0's responsibility
2. **Always validate Auth0 tokens**: Use JWKS endpoint for token verification
3. **Use HTTPS**: All Auth0 communication requires HTTPS
4. **Implement rate limiting**: Auth0 provides rate limiting, but backend should too
5. **Rotate secrets**: Regularly rotate Auth0 client secrets (if used)
6. **Monitor suspicious activity**: Use Auth0 logs and anomaly detection
7. **Implement MFA**: Configure Auth0 Multi-Factor Authentication for enhanced security

## Troubleshooting

### Common Issues

**Issue**: "Invalid token" error
- Check `AUTH0_DOMAIN` and `AUTH0_AUDIENCE` configuration
- Verify the token hasn't expired
- Ensure the token audience matches `AUTH0_AUDIENCE`

**Issue**: User not found after Auth0 login
- This is expected on first login; JIT provisioning will create the profile
- Check that the Auth0 `sub` claim is being extracted correctly

**Issue**: Role not mapped correctly
- Verify the role claim namespace matches your Auth0 configuration
- Check that Auth0 Actions or Rules are adding the role claim

**Issue**: JWKS validation fails
- Verify network connectivity to `https://{AUTH0_DOMAIN}/.well-known/jwks.json`
- Check that `AUTH0_DOMAIN` is correct and accessible
- Consider increasing `AUTH0_JWKS_CACHE_TTL_SECS` for slow networks

## Additional Resources

- [Auth0 Documentation](https://auth0.com/docs)
- [Auth0 Database Connection](https://auth0.com/docs/connections/database)
- [Auth0 Management API](https://auth0.com/docs/api/management/v2)
- [Auth0 Universal Login](https://auth0.com/docs/universal-login)
- [RS256 vs HS256](https://auth0.com/docs/tokens/guides/rotate-keys)
