src/config/auth0_config.rs
Comment on lines +25 to +38 #[derive(Debug, Deserialize, Clone, Default)]
pub struct Auth0Config {
pub auth0_domain: Option<String>,
pub auth0_audience: Option<String>,
pub auth0_issuer: Option<String>, #[serde(default = "crate::config::defaults::default_jwks_cache_ttl_secs")]
pub jwks_cache_ttl_secs: u64, #[serde(default)]
pub auth0_client_id: Option<String>, #[serde(default)]
pub auth0_client_secret: Option<String>, #[serde(default = "crate::config::defaults::default_auth0_connection")]
pub auth0_connection: String,
}
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

🧩 Analysis chain
Remove derive(Default) and provide a manual impl Default that respects serde defaults.

Auth0Config::default() currently returns jwks_cache_ttl_secs: 0 and auth0_connection: "" instead of the intended defaults (3600 seconds and "Username-Password-Authentication"). This silently breaks the JWKS cache when used in struct update syntax (e.g., tests/core_api/equipment_extended/mod.rs:238), where an enabled config gets a zero-second cache TTL. The config loading normalization only applies to deserialized configs and does not protect programmatically constructed instances.

Suggested fix
📝 Committable suggestion
🤖 Prompt for AI Agents
@anexport Reply...
src/infrastructure/auth0/dtos.rs
Comment on lines +72 to +76
error!(
code = %self.code,
description = %description,
"Auth0 API error"
);
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

Avoid logging raw Auth0 error descriptions.

Lines 72-76 log external description directly, which can leak sensitive identifiers in logs. Also, logging self.code can miss the effective error code when error is used instead.

🛡️ Proposed fix
🤖 Prompt for AI Agents
@anexport Reply...
src/infrastructure/repositories/equipment/photo.rs
Comment on lines +7 to +67
let created = sqlx::query*as::<*, EquipmentPhoto>(
r#"
INSERT INTO equipment_photos (id, equipment_id, photo_url, is_primary, order_index, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, equipment_id, photo_url, is_primary, order_index, created_at
"#
)
.bind(photo.id)
.bind(photo.equipment_id)
.bind(&photo.photo_url)
.bind(photo.is_primary)
.bind(photo.order_index)
.bind(photo.created_at)
.fetch_one(pool)
.await?;
Ok(created)
}

pub async fn find*photos(pool: &PgPool, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
let photos = sqlx::query_as::<*, EquipmentPhoto>(
"SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE equipment_id = $1 ORDER BY order_index"
)
.bind(equipment_id)
.fetch_all(pool)
.await?;
Ok(photos)
}

pub async fn find*photo_by_id(pool: &PgPool, photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>> {
let photo = sqlx::query_as::<*, EquipmentPhoto>(
"SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE id = $1"
)
.bind(photo_id)
.fetch_optional(pool)
.await?;
Ok(photo)
}

pub async fn update*photo(pool: &PgPool, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
let updated = sqlx::query_as::<*, EquipmentPhoto>(
r#"
UPDATE equipment_photos
SET photo_url = $1, is_primary = $2, order_index = $3
WHERE id = $4
RETURNING id, equipment_id, photo_url, is_primary, order_index, created_at
"#,
)
.bind(&photo.photo_url)
.bind(photo.is_primary)
.bind(photo.order_index)
.bind(photo.id)
.fetch_one(pool)
.await?;
Ok(updated)
}

pub async fn delete_photo(pool: &PgPool, photo_id: Uuid) -> AppResult<()> {
sqlx::query("DELETE FROM equipment_photos WHERE id = $1")
.bind(photo_id)
.execute(pool)
.await?;
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

🧩 Analysis chain
Switch repository SQL to SQLx compile-time macros.

This module uses runtime-checked builders (sqlx::query*as::<*, EquipmentPhoto> and sqlx::query) instead of compile-time checked SQLx macros. Migrate to query_as! (for queries returning rows) and query! (for non-row statements) to enable schema-checked queries at compile time.

Per coding guidelines: "Database queries must use parameterized queries with SQLx query_as! macro."

🤖 Prompt for AI Agents
@anexport Reply...
src/security/login_throttle.rs
Comment on lines +24 to +26
pub fn key(email: &str, ip: Option<&str>) -> String {
format!("{email}|{}", ip.unwrap_or("unknown"))
}
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

Normalize throttle key inputs to prevent easy bypass.

Using raw email allows case/whitespace variants to produce different keys and evade per-user throttling. Canonicalize email (trim + lowercase) before key construction.

Suggested fix
🤖 Prompt for AI Agents
@anexport Reply...
src/security/rate_limit.rs
Comment on lines +35 to +40
let requests_per_millisecond = (60_000 / rate_limit_per_minute) as u64;
let governor_config = GovernorConfigBuilder::default()
.per_millisecond(requests_per_millisecond)
.burst_size(burst_size)
.finish()
.expect("Failed to build governor config");
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟡 Minor

🧩 Analysis chain
Rename variable and use non-deprecated method — per_millisecond() is deprecated and variable naming is inverted.

The variable requests_per_millisecond is semantically backwards; the calculation 60_000 / rate_limit_per_minute produces the replenishment interval in milliseconds (e.g., 200 ms per request for 300 req/min), not a rate. Additionally, per_millisecond() has been deprecated since actix-governor 0.6.0 in favor of milliseconds_per_request(), which has identical semantics but clearer naming.

Suggested fix:

Rename variable to milliseconds_per_request
Replace .per_millisecond() with .milliseconds_per_request()
🤖 Prompt for AI Agents
@anexport Reply...
tests/auth_middleware/jwt_validation.rs
Comment on lines +59 to +86
async fn create_token_with_wrong_issuer() {
let exp = (Utc::now() + Duration::hours(1)).timestamp();

    let claims = Auth0Claims {
        iss: "https://wrong-issuer.com/".to_string(),
        sub: "auth0|wrong-iss".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("wrongiss@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Wrong Issuer".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    assert!(!token.is_empty());

}
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

create_token_with_wrong_issuer doesn’t actually verify issuer rejection.

Right now it only checks that encoding produced a token string. Without a validation/assertion step, this test will pass even if issuer checks regress.

🤖 Prompt for AI Agents
@anexport Reply...
tests/auth_middleware/jwt_validation.rs
Comment on lines +89 to +123
async fn create_token_not_yet_valid() {
let exp = (Utc::now() + Duration::hours(2)).timestamp();

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|future".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        email: Some("future@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Future User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-key-id".to_string());

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("test-secret".as_bytes()),
    )
    .expect("Failed to encode test token");

    // Token should fail nbf validation
    let decoded = jsonwebtoken::decode::<Auth0Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret("test-secret".as_bytes()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    );

    assert!(decoded.is_err());

}
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟡 Minor

Clarify and tighten the “not yet valid” test intent.

The test comment mentions nbf behavior, but the setup changes only iat and then checks only generic is_err(). Make the claim under test explicit and assert the expected failure reason to avoid false positives.

🤖 Prompt for AI Agents
@anexport Reply...
tests/auth0_endpoints.rs
Comment on lines +111 to +117
pub fn generate_mock_rs256_token(&self) -> String {
let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0";
// Payload: {"iss":"https://test.auth0.com/","sub":"test-user","aud":"https://api.test.com","exp":1757680000,"iat":1757680000}
let payload = "eyJpc3MiOiJodHRwczovL3Rlc3QuYXV0aDAuY29tLyIsInN1YiI6InRlc3QtdXNlciIsImF1ZCI6Imh0dHBzOi8vYXBpLnRlc3QuY29tIiwiZXhwIjoxNzU3NjgwMDAwLCJpYXQiOjE3NTc2ODAwMDB9";
let signature = "bX9ja2stcnMyNTYtc2lnbmF0dXJl";
format!("{}.{}.{}", header, payload, signature)
}
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟡 Minor

Avoid hard-coded expired JWT claims in the mock token helper.

Line 114 hardcodes exp=1757680000 (September 12, 2025 UTC), which is already past as of February 27, 2026. This makes tests time-fragile when claims are validated.

🛠️ Proposed fix
🤖 Prompt for AI Agents
@anexport Reply...
tests/auth0*endpoints.rs
Comment on lines +251 to +253
let database_url = std::env::var("TEST_DATABASE_URL")
.or_else(|*| std::env::var("DATABASE*URL"))
.unwrap_or_else(|*| "postgres://postgres:postgres@127.0.0.1:5432/test_db".to_string());
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

Do not fall back to DATABASE_URL for test pool initialization.

Lines 251-253 can route tests to a non-test DB when TEST_DATABASE_URL is missing. That is a high-risk safety footgun.

🛡️ Proposed fix
📝 Committable suggestion
🤖 Prompt for AI Agents
@anexport Reply...
tests/common/auth0*test_helpers.rs
Comment on lines +91 to +101
let * = auth_repo
.create_identity(&rust_backend::domain::AuthIdentity {
id: Uuid::new_v4(),
user_id: user.id,
provider: rust_backend::domain::AuthProvider::Auth0,
provider_id: Some(sub.clone()),
password_hash: None,
verified: claims.email_verified.unwrap_or(false),
created_at: Utc::now(),
})
.await;
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

Don’t suppress identity-link persistence errors.

let \_ = auth_repo.create_identity(...).await; hides failures and can return success with inconsistent auth state. Propagate unexpected errors (optionally tolerate only duplicate/conflict).

Suggested fix
📝 Committable suggestion
🤖 Prompt for AI Agents
@anexport Reply...
tests/common/mocks/user_repo.rs
Comment on lines +59 to +73
async fn update(&self, user: &User) -> AppResult<User> {
let mut users = self.users.lock().expect("users mutex poisoned");
if let Some(existing) = users.iter_mut().find(|existing| existing.id == user.id) {
\*existing = user.clone();
}
Ok(user.clone())
}

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .retain(|user| user.id != id);
        Ok(())
    }

@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟠 Major

🧩 Analysis chain
Fix update() to error on missing users; delete() behavior is correct.

The update() method hides missing-user scenarios, but delete() correctly mirrors production behavior as a no-op.

The real UserRepositoryImpl.update() uses fetch_one() which errors when the user doesn't exist. The mock currently returns Ok(user.clone()) regardless, allowing tests to pass when production would fail.

The delete() method is actually correct—the integration test user_repository_delete_non_existent_id_is_noop() confirms deletion of a non-existent user is intentionally a no-op in production.

Align update() to error on missing users.

🤖 Prompt for AI Agents
@anexport Reply...
tests/common/mocks/utils.rs
Comment on lines +5 to +8
let a = (d_lat / 2.0).sin().powi(2) + lat1.to_radians().cos() _ lat2.to_radians().cos() _ (d_lng / 2.0).sin().powi(2);
let c = 2.0 _ a.sqrt().atan2((1.0 - a).sqrt());
r _ c
@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟡 Minor

Clamp a to avoid rare NaN from floating-point drift.

Line 7 can produce sqrt(negative) when a is slightly above 1.0 due to precision error.

🔢 Suggested fix
📝 Committable suggestion
🤖 Prompt for AI Agents
@anexport Reply...
tests/core_api/user/equipment.rs
Comment on lines +94 to +100
let resp = actix_test::call_service(&app, req).await;
let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;

    // Should be newest first
    assert_eq!(items[0]["title"], "Equipment 2");
    assert_eq!(items[1]["title"], "Equipment 1");
    assert_eq!(items[2]["title"], "Equipment 0");

@coderabbitai
coderabbitai bot
9 minutes ago
⚠️ Potential issue | 🟡 Minor

Guard indexed assertions with status and length checks first.

This test indexes items[0..2] without asserting 200 OK and expected item count first, which can panic before showing the real failure.
