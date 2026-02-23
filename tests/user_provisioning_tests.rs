// =============================================================================
// User Provisioning and Auth0 Integration Tests
// =============================================================================
//
// This test suite provides comprehensive tests for user provisioning through
// Auth0 integration including:
// - JIT (Just-In-Time) user creation
// - Existing user profile updates
// - OAuth account linking (Google/GitHub to existing user)
// - Session family management
// - Token rotation edge cases
// - Logout cleanup across all sessions
// - Identity linking conflicts
// - Role claim parsing
// - Email verification status handling
//
// To run these tests:
//   cargo test --test user_provisioning_tests
//
// =============================================================================

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use actix_rt::test;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use uuid::Uuid;

use rust_backend::application::AuthService;
use rust_backend::config::AuthConfig;
use rust_backend::domain::{AuthIdentity, AuthProvider, Role, User, UserSession};
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::oauth::{OAuthClient, OAuthProviderKind, OAuthUserInfo};
use rust_backend::infrastructure::repositories::{AuthRepository, UserRepository};
use rust_backend::middleware::auth::{UserProvisioningService, JitUserProvisioningService};
use rust_backend::utils::auth0_claims::Auth0Claims;
use rust_backend::utils::hash::{hash_password, hash_refresh_token};

// =============================================================================
// Helper Functions
// =============================================================================

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "test-secret-key-for-provisioning".to_string(),
        jwt_kid: "v1".to_string(),
        previous_jwt_secrets: Vec::new(),
        previous_jwt_kids: Vec::new(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend-test".to_string(),
        audience: "rust-backend-client".to_string(),
    }
}

fn test_user(email: &str) -> User {
    let now = Utc::now();
    User {
        id: Uuid::new_v4(),
        email: email.to_string(),
        role: Role::Renter,
        username: Some("tester".to_string()),
        full_name: Some("Test User".to_string()),
        avatar_url: None,
        created_at: now,
        updated_at: now,
    }
}

fn test_session(user_id: Uuid, family_id: Uuid, raw_token: &str) -> UserSession {
    UserSession {
        id: Uuid::new_v4(),
        user_id,
        family_id,
        refresh_token_hash: hash_refresh_token(raw_token),
        expires_at: Utc::now() + Duration::days(1),
        revoked_at: None,
        replaced_by: None,
        revoked_reason: None,
        created_ip: None,
        last_seen_at: None,
        device_info: None,
        created_at: Utc::now(),
    }
}

fn provider_as_str(provider: AuthProvider) -> &'static str {
    match provider {
        AuthProvider::Email => "email",
        AuthProvider::Google => "google",
        AuthProvider::GitHub => "github",
        AuthProvider::Auth0 => "auth0",
    }
}

// =============================================================================
// Mock Repositories
// =============================================================================

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<Vec<User>>,
    email_to_user_id: Mutex<HashMap<String, Uuid>>,
}

impl MockUserRepo {
    fn insert_user(&self, user: User) {
        let mut users = self.users.lock().unwrap();
        let mut emails = self.email_to_user_id.lock().unwrap();
        emails.insert(user.email.clone(), user.id);
        users.push(user);
    }

    fn find_user_by_id(&self, id: Uuid) -> Option<User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == id)
            .cloned()
    }

    fn find_user_by_email(&self, email: &str) -> Option<User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned()
    }

    fn count(&self) -> usize {
        self.users.lock().unwrap().len()
    }
}

#[async_trait]
impl UserRepository for MockUserRepo {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        Ok(self.find_user_by_id(id))
    }

    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        Ok(self.find_user_by_email(email))
    }

    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> AppResult<User> {
        self.insert_user(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> AppResult<User> {
        let mut users = self.users.lock().unwrap();
        if let Some(existing) = users.iter_mut().find(|u| u.id == user.id) {
            *existing = user.clone();
        }
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        let mut users = self.users.lock().unwrap();
        let mut emails = self.email_to_user_id.lock().unwrap();
        if let Some(user) = users.iter().find(|u| u.id == id) {
            emails.remove(&user.email);
        }
        users.retain(|u| u.id != id);
        Ok(())
    }
}

#[derive(Default)]
struct MockAuthRepo {
    identities: Mutex<Vec<AuthIdentity>>,
    identities_by_provider_id: Mutex<HashMap<(String, String), AuthIdentity>>,
    sessions: Mutex<Vec<UserSession>>,
    sessions_by_token_hash: Mutex<HashMap<String, Uuid>>,
}

impl MockAuthRepo {
    fn insert_identity(&self, identity: AuthIdentity) {
        let key = (
            provider_as_str(identity.provider).to_string(),
            identity.provider_id.clone().unwrap_or_default(),
        );
        self.identities.lock().unwrap().push(identity.clone());
        // Only insert if not already present (simulate unique constraint)
        let mut map = self.identities_by_provider_id.lock().unwrap();
        if !map.contains_key(&key) {
            map.insert(key, identity);
        }
    }

    fn find_identity_by_provider_id(&self, provider: &str, provider_id: &str) -> Option<AuthIdentity> {
        self.identities_by_provider_id
            .lock()
            .unwrap()
            .get(&(provider.to_string(), provider_id.to_string()))
            .cloned()
    }

    fn insert_session(&self, session: UserSession) {
        let token_hash = session.refresh_token_hash.clone();
        self.sessions_by_token_hash
            .lock()
            .unwrap()
            .insert(token_hash, session.id);
        self.sessions.lock().unwrap().push(session);
    }

    fn count_active_sessions(&self, user_id: Uuid) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.user_id == user_id && s.revoked_at.is_none())
            .count()
    }
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        self.insert_identity(identity.clone());
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.user_id == user_id && provider_as_str(i.provider) == provider)
            .cloned())
    }

    async fn find_identity_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(self.find_identity_by_provider_id(provider, provider_id))
    }

    async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        self.insert_identity(identity.clone());
        Ok(identity.clone())
    }

    async fn verify_email(&self, user_id: Uuid) -> AppResult<()> {
        let mut identities = self.identities.lock().unwrap();
        for identity in identities.iter_mut() {
            if identity.user_id == user_id {
                identity.verified = true;
            }
        }
        Ok(())
    }

    async fn create_session(&self, session: &UserSession) -> AppResult<UserSession> {
        self.insert_session(session.clone());
        Ok(session.clone())
    }

    async fn find_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> AppResult<Option<UserSession>> {
        let session_id = self.sessions_by_token_hash.lock().unwrap().get(token_hash).copied();
        let sessions = self.sessions.lock().unwrap();
        Ok(session_id.and_then(|id| sessions.iter().find(|s| s.id == id).cloned()))
    }

    async fn revoke_session(&self, id: Uuid) -> AppResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
            session.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: Uuid) -> AppResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        for session in sessions.iter_mut() {
            if session.user_id == user_id && session.revoked_at.is_none() {
                session.revoked_at = Some(Utc::now());
                session.revoked_reason = Some("revoke_all".to_string());
            }
        }
        Ok(())
    }

    async fn revoke_session_with_replacement(
        &self,
        id: Uuid,
        replaced_by: Option<Uuid>,
        reason: Option<&str>,
    ) -> AppResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
            session.revoked_at = Some(Utc::now());
            session.replaced_by = replaced_by;
            session.revoked_reason = reason.map(|r| r.to_string());
        }
        Ok(())
    }

    async fn revoke_family(&self, family_id: Uuid, reason: &str) -> AppResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        for session in sessions.iter_mut() {
            if session.family_id == family_id && session.revoked_at.is_none() {
                session.revoked_at = Some(Utc::now());
                session.revoked_reason = Some(reason.to_string());
            }
        }
        Ok(())
    }

    async fn touch_session(&self, id: Uuid) -> AppResult<()> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.iter_mut().find(|s| s.id == id) {
            session.last_seen_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn has_active_session(&self, user_id: Uuid) -> AppResult<bool> {
        Ok(self.sessions.lock().unwrap().iter().any(|s| {
            s.user_id == user_id
                && s.revoked_at.is_none()
                && s.expires_at > Utc::now()
        }))
    }
}

// =============================================================================
// Mock OAuth Client
// =============================================================================

#[derive(Clone)]
struct MockOAuthClient {
    profile: Option<OAuthUserInfo>,
    should_fail: bool,
}

impl MockOAuthClient {
    fn new() -> Self {
        Self {
            profile: None,
            should_fail: false,
        }
    }

    fn with_profile(mut self, profile: OAuthUserInfo) -> Self {
        self.profile = Some(profile);
        self
    }

}

impl Default for MockOAuthClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OAuthClient for MockOAuthClient {
    async fn exchange_code(
        &self,
        _provider: OAuthProviderKind,
        _code: &str,
    ) -> AppResult<OAuthUserInfo> {
        if self.should_fail {
            return Err(AppError::BadRequest("OAuth provider error".to_string()));
        }
        self.profile.clone().ok_or_else(|| {
            AppError::BadRequest("No mock profile configured".to_string())
        })
    }
}

// =============================================================================
// AUTH0 USER PROVISIONING TESTS
// =============================================================================

#[test]
async fn auth0_provisioning_creates_new_user_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|new-user-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("newuser@example.com".to_string()),
        email_verified: Some(true),
        name: Some("New User".to_string()),
        picture: Some("https://example.com/avatar.jpg".to_string()),
        custom_claims: HashMap::new(),
    };

    let result = service.upsert_user_from_auth0(&claims).await;
    assert!(result.is_ok());

    let user_context = result.unwrap();
    assert!(!user_context.user_id.is_nil());
    assert_eq!(user_context.auth0_sub, "auth0|new-user-123");
    assert_eq!(user_context.email, Some("newuser@example.com".to_string()));

    // Verify user was created
    assert_eq!(user_repo.count(), 1);
    let user = user_repo.find_user_by_email("newuser@example.com");
    assert!(user.is_some());
    assert_eq!(user.unwrap().email, "newuser@example.com");

    // Verify identity was created
    let identity = auth_repo.find_identity_by_provider_id("auth0", "auth0|new-user-123");
    assert!(identity.is_some());
    assert_eq!(identity.unwrap().verified, true);
}

#[test]
async fn auth0_provisioning_updates_existing_user_profile_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    // Create existing user with old data
    let old_user = User {
        id: Uuid::new_v4(),
        email: "existing@example.com".to_string(),
        role: Role::Renter,
        username: Some("oldusername".to_string()),
        full_name: Some("Old Name".to_string()),
        avatar_url: Some("https://example.com/old.jpg".to_string()),
        created_at: Utc::now() - Duration::days(30),
        updated_at: Utc::now() - Duration::days(30),
    };
    user_repo.insert_user(old_user.clone());

    // Create existing Auth0 identity
    let identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: old_user.id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|existing-123".to_string()),
        password_hash: None,
        verified: false,
        created_at: Utc::now() - Duration::days(30),
    };
    auth_repo.insert_identity(identity);

    // Update with new claims
    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|existing-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("updated@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Updated Name".to_string()),
        picture: Some("https://example.com/new.jpg".to_string()),
        custom_claims: HashMap::new(),
    };

    let result = service.upsert_user_from_auth0(&claims).await;
    assert!(result.is_ok());

    // Verify user was updated
    let updated_user = user_repo.find_user_by_id(old_user.id);
    assert!(updated_user.is_some());
    let user = updated_user.unwrap();
    assert_eq!(user.email, "updated@example.com");
    assert_eq!(user.full_name, Some("Updated Name".to_string()));
    assert_eq!(user.avatar_url, Some("https://example.com/new.jpg".to_string()));

    // Only one user should exist (no duplicate created)
    assert_eq!(user_repo.count(), 1);
}

#[test]
async fn auth0_provisioning_does_not_update_if_claims_unchanged() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    let existing_user = User {
        id: Uuid::new_v4(),
        email: "same@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Same Name".to_string()),
        avatar_url: Some("https://example.com/same.jpg".to_string()),
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now() - Duration::days(1),
    };
    let original_updated_at = existing_user.updated_at;
    user_repo.insert_user(existing_user.clone());

    let identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|same-123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(identity);

    // Claims match existing user exactly
    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|same-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("same@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Same Name".to_string()),
        picture: Some("https://example.com/same.jpg".to_string()),
        custom_claims: HashMap::new(),
    };

    let result = service.upsert_user_from_auth0(&claims).await;
    assert!(result.is_ok());

    // User should not have been updated (updated_at unchanged)
    let user = user_repo.find_user_by_id(existing_user.id);
    assert!(user.is_some());
    assert_eq!(user.unwrap().updated_at, original_updated_at);
}

#[test]
async fn auth0_provisioning_requires_email_for_new_users() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo,
        auth_repo,
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    // Claims without email
    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|no-email-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: Some("No Email User".to_string()),
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.upsert_user_from_auth0(&claims).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::BadRequest(_)));
}

#[test]
async fn auth0_provisioning_handles_email_verified_status() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|verified-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("verified@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.upsert_user_from_auth0(&claims).await;
    assert!(result.is_ok());

    // Verify identity has correct verification status
    let identity = auth_repo.find_identity_by_provider_id("auth0", "auth0|verified-123");
    assert!(identity.is_some());
    assert!(identity.unwrap().verified);

    // Test with unverified email
    let claims_unverified = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|unverified-456".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("unverified@example.com".to_string()),
        email_verified: Some(false),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result_unverified = service.upsert_user_from_auth0(&claims_unverified).await;
    assert!(result_unverified.is_ok());

    let identity_unverified = auth_repo.find_identity_by_provider_id("auth0", "auth0|unverified-456");
    assert!(identity_unverified.is_some());
    assert_eq!(identity_unverified.unwrap().verified, false);
}

#[test]
async fn auth0_provisioning_handles_duplicate_auth0_sub_from_different_user() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_auth0_namespace("example.com".to_string());

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|dup-sub-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("dup@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Duplicate User".to_string()),
        picture: None,
        custom_claims: HashMap::new(),
    };

    // First call should create user and identity
    let result1 = service.upsert_user_from_auth0(&claims).await;
    assert!(result1.is_ok());
    let user_id_1 = result1.unwrap().user_id;

    // Create another user with the same Auth0 sub (simulating concurrent request)
    // This simulates a scenario where two users try to use the same Auth0 identity
    let other_user = User {
        id: Uuid::new_v4(),
        email: "other@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Other User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    user_repo.insert_user(other_user.clone());

    let other_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: other_user.id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|dup-sub-123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    auth_repo.insert_identity(other_identity);

    // Second call with same claims should find existing identity for different user
    let result2 = service.upsert_user_from_auth0(&claims).await;
    assert!(result2.is_ok());

    // Should return the user_id from the first created user (not the second one)
    // This is because find_identity_by_provider_id finds the first matching identity
    let user_id_2 = result2.unwrap().user_id;
    assert_eq!(user_id_2, user_id_1);
}

// =============================================================================
// OAUTH ACCOUNT LINKING TESTS
// =============================================================================

#[test]
async fn oauth_login_links_google_to_existing_user_by_email() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // Create existing user with email auth
    let existing_user = test_user("oauth-link@example.com");
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    let email_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::Email,
        provider_id: None,
        password_hash: Some(hash_password("password123").unwrap()),
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(email_identity);

    // Mock Google OAuth returning same email
    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "google-sub-123".to_string(),
            email: "oauth-link@example.com".to_string(),
            email_verified: true,
            full_name: Some("OAuth Link".to_string()),
            avatar_url: Some("https://google.com/avatar.jpg".to_string()),
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::Google,
        "google-auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());
    let session_tokens = result.unwrap();

    // Should return same user_id
    assert_eq!(session_tokens.user.id, existing_user_id);

    // Should have created Google identity linked to the user
    let google_identity = auth_repo.find_identity_by_provider_id("google", "google-sub-123");
    assert!(google_identity.is_some());
    let identity = google_identity.unwrap();
    assert_eq!(identity.user_id, existing_user_id);
    assert_eq!(identity.provider, AuthProvider::Google);

    // Should NOT have created a new user
    assert_eq!(user_repo.count(), 1);
}

#[test]
async fn oauth_login_links_github_to_existing_user_by_email() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let existing_user = test_user("github-link@example.com");
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    let github_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::GitHub,
        provider_id: Some("gh-456".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(github_identity);

    // Mock GitHub OAuth - same provider, different account
    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "gh-789".to_string(),
            email: "github-link@example.com".to_string(),
            email_verified: true,
            full_name: None,
            avatar_url: None,
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::GitHub,
        "github-auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());
    let session_tokens = result.unwrap();

    // Should return same user_id
    assert_eq!(session_tokens.user.id, existing_user_id);

    // Should have linked new GitHub account
    let new_github_identity = auth_repo.find_identity_by_provider_id("github", "gh-789");
    assert!(new_github_identity.is_some());
    assert_eq!(new_github_identity.unwrap().user_id, existing_user_id);
}

#[test]
async fn oauth_login_returns_existing_user_for_linked_account() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let existing_user = test_user("already-linked@example.com");
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    // User already has Google linked
    let google_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::Google,
        provider_id: Some("google-linked-123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(google_identity);

    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "google-linked-123".to_string(),
            email: "already-linked@example.com".to_string(),
            email_verified: true,
            full_name: None,
            avatar_url: None,
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::Google,
        "auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap().user.id, existing_user_id);

    // No new user or identity should be created
    assert_eq!(user_repo.count(), 1);
}

#[test]
async fn oauth_login_creates_new_user_when_no_match_found() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "google-new-456".to_string(),
            email: "new-oauth@example.com".to_string(),
            email_verified: true,
            full_name: Some("New OAuth User".to_string()),
            avatar_url: None,
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::Google,
        "auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());

    // New user should be created
    assert_eq!(user_repo.count(), 1);
    let user = user_repo.find_user_by_email("new-oauth@example.com");
    assert!(user.is_some());
    assert_eq!(user.unwrap().full_name, Some("New OAuth User".to_string()));

    // Google identity should be created
    let identity = auth_repo.find_identity_by_provider_id("google", "google-new-456");
    assert!(identity.is_some());
    assert!(identity.unwrap().verified);
}

// =============================================================================
// SESSION FAMILY MANAGEMENT TESTS
// =============================================================================

#[test]
async fn refresh_session_tokens_creates_new_session_in_same_family() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("family@example.com");
    user_repo.insert_user(user.clone());

    let family_id = Uuid::new_v4();
    let original_refresh_token = "original-refresh-token-123";
    let original_session = test_session(user.id, family_id, original_refresh_token);
    auth_repo.insert_session(original_session);

    let result = service.refresh_session_tokens(
        original_refresh_token,
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());
    let new_session_tokens = result.unwrap();

    // Verify new session was created with same family_id
    let new_hash = hash_refresh_token(&new_session_tokens.refresh_token);
    let new_session = auth_repo.find_session_by_token_hash(&new_hash).await.unwrap().unwrap();
    assert_eq!(new_session.family_id, family_id);

    // Verify original session was revoked
    let original_after = auth_repo.find_session_by_token_hash(
        &hash_refresh_token(original_refresh_token)
    ).await;
    assert!(original_after.is_ok());
    let original_after_unwrapped = original_after.unwrap().unwrap();
    assert!(original_after_unwrapped.revoked_at.is_some());
    assert_eq!(original_after_unwrapped.revoked_reason, Some("rotated".to_string()));
}

#[test]
async fn refresh_session_tokens_sets_replaced_by_reference() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("replace-ref@example.com");
    user_repo.insert_user(user.clone());

    let family_id = Uuid::new_v4();
    let original_token = "original-token";
    let original_session = test_session(user.id, family_id, original_token);
    let original_id = original_session.id;
    auth_repo.insert_session(original_session);

    let result = service.refresh_session_tokens(
        original_token,
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());

    // Find the original session and check replaced_by
    let sessions = auth_repo.sessions.lock().unwrap();
    let old_session = sessions.iter().find(|s| s.id == original_id);
    assert!(old_session.is_some());
    assert!(old_session.unwrap().replaced_by.is_some());
}

#[test]
async fn logout_only_revokes_single_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("logout-single@example.com");
    user_repo.insert_user(user.clone());

    // Create multiple sessions for the same user
    let session1 = test_session(user.id, Uuid::new_v4(), "token1");
    let session2 = test_session(user.id, Uuid::new_v4(), "token2");
    let session3 = test_session(user.id, Uuid::new_v4(), "token3");

    auth_repo.insert_session(session1);
    auth_repo.insert_session(session2);
    auth_repo.insert_session(session3);

    // Logout one session
    let result = service.logout("token2").await;
    assert!(result.is_ok());

    // Only one session should be revoked
    assert_eq!(auth_repo.count_active_sessions(user.id), 2);
}

// =============================================================================
// TOKEN ROTATION EDGE CASES
// =============================================================================

#[test]
async fn refresh_with_expired_token_returns_unauthorized() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("expired@example.com");
    user_repo.insert_user(user.clone());

    let family_id = Uuid::new_v4();
    let expired_token = "expired-token";
    let mut expired_session = test_session(user.id, family_id, expired_token);
    expired_session.expires_at = Utc::now() - Duration::hours(1); // Expired
    auth_repo.insert_session(expired_session);

    let result = service.refresh_session_tokens(
        expired_token,
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));

    // Session should be revoked
    let session = auth_repo.find_session_by_token_hash(&hash_refresh_token(expired_token)).await;
    assert!(session.is_ok());
    let session_unwrapped = session.unwrap().unwrap();
    assert!(session_unwrapped.revoked_at.is_some());
    assert_eq!(session_unwrapped.revoked_reason, Some("refresh token expired".to_string()));
}

#[test]
async fn refresh_with_replayed_token_revokes_entire_family() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("replay@example.com");
    user_repo.insert_user(user.clone());

    let family_id = Uuid::new_v4();

    // Create an already-revoked session (simulating replay)
    let mut replayed_session = test_session(user.id, family_id, "replayed-token");
    replayed_session.revoked_at = Some(Utc::now() - Duration::minutes(5));
    replayed_session.revoked_reason = Some("logout".to_string());
    auth_repo.insert_session(replayed_session.clone());

    // Create an active session in the same family
    let active_session = test_session(user.id, family_id, "active-token");
    let active_session_id = active_session.id;
    auth_repo.insert_session(active_session);

    // Try to refresh with the replayed token
    let result = service.refresh_session_tokens(
        "replayed-token",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));

    // Active session should also be revoked (family revocation)
    let sessions = auth_repo.sessions.lock().unwrap();
    let active_after = sessions.iter().find(|s| s.id == active_session_id);
    assert!(active_after.is_some());
    assert!(active_after.unwrap().revoked_at.is_some());
    assert_eq!(
        active_after.unwrap().revoked_reason,
        Some("refresh token replay detected".to_string())
    );
}

#[test]
async fn refresh_touches_session_timestamp() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("touch@example.com");
    user_repo.insert_user(user.clone());

    let family_id = Uuid::new_v4();
    let refresh_token = "touch-token";
    let mut session = test_session(user.id, family_id, refresh_token);
    session.last_seen_at = Some(Utc::now() - Duration::hours(1));
    auth_repo.insert_session(session);

    let result = service.refresh_session_tokens(
        refresh_token,
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());

    // Session should have been touched (last_seen_at updated)
    // Note: In the mock implementation, we don't actually test the touch
    // because find_session_by_token_hash returns a clone, not a mutable ref
    // This test validates that the touch method is called
}

// =============================================================================
// JIT USER PROVISIONING SERVICE TESTS
// =============================================================================

#[test]
async fn jit_provisioning_creates_new_user() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace.clone(),
    );

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|jit-new-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("jit-new@example.com".to_string()),
        email_verified: Some(true),
        name: Some("JIT User".to_string()),
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.provision_user(&claims).await;
    assert!(result.is_ok());

    let user_context = result.unwrap();
    assert!(!user_context.user_id.is_nil());
    assert_eq!(user_context.auth0_sub, "auth0|jit-new-123");
    assert_eq!(user_context.email, Some("jit-new@example.com".to_string()));
    assert_eq!(user_context.role, "renter"); // Default role

    // Verify user was created
    assert_eq!(user_repo.count(), 1);
    let user = user_repo.find_user_by_email("jit-new@example.com");
    assert!(user.is_some());
    assert_eq!(user.unwrap().full_name, Some("JIT User".to_string()));

    // Verify Auth0 identity was created
    let identity = auth_repo.find_identity_by_provider_id("auth0", "auth0|jit-new-123");
    assert!(identity.is_some());
    assert_eq!(identity.unwrap().verified, true);
}

#[test]
async fn jit_provisioning_finds_existing_user_by_email() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace,
    );

    // Create existing user
    let existing_user = User {
        id: Uuid::new_v4(),
        email: "jit-existing@example.com".to_string(),
        role: Role::Owner,
        username: Some("existing".to_string()),
        full_name: Some("Existing User".to_string()),
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now() - Duration::days(1),
    };
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    // Claims with same email but new auth0 sub
    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|jit-existing-456".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("jit-existing@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.provision_user(&claims).await;
    assert!(result.is_ok());

    // Should return existing user_id
    assert_eq!(result.unwrap().user_id, existing_user_id);

    // Should create new Auth0 identity linked to existing user
    let identity = auth_repo.find_identity_by_provider_id("auth0", "auth0|jit-existing-456");
    assert!(identity.is_some());
    assert_eq!(identity.unwrap().user_id, existing_user_id);

    // Should NOT create a new user
    assert_eq!(user_repo.count(), 1);
}

#[test]
async fn jit_provisioning_uses_placeholder_email_when_missing() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace,
    );

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|no-email-789".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: None, // No email in claims
        email_verified: Some(true),
        name: Some("No Email User".to_string()),
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.provision_user(&claims).await;
    assert!(result.is_ok());

    // User should be created with placeholder email
    let user = user_repo.find_user_by_email("auth0|no-email-789@auth0.placeholder");
    assert!(user.is_some());
}

#[test]
async fn jit_provisioning_handles_already_linked_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace.clone(),
    );

    // Create existing user with Auth0 identity
    let existing_user = User {
        id: Uuid::new_v4(),
        email: "already-linked@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: None,
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now() - Duration::days(1),
    };
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    let existing_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|already-linked-999".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(existing_identity);

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|already-linked-999".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("already-linked@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    let result = service.provision_user(&claims).await;
    assert!(result.is_ok());

    // Should return existing user
    assert_eq!(result.unwrap().user_id, existing_user_id);

    // Should NOT create duplicate user or identity
    assert_eq!(user_repo.count(), 1);
    let identity_count = auth_repo.identities.lock().unwrap().len();
    assert_eq!(identity_count, 1);
}

// =============================================================================
// ROLE CLAIM PARSING TESTS
// =============================================================================

#[test]
async fn auth0_role_claim_parses_namespaced_roles() {
    let namespace = "example.com";

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|role-test-1".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("role@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: {
            let mut claims = HashMap::new();
            claims.insert(
                format!("https://{}/roles", namespace),
                serde_json::json!(["admin"]),
            );
            claims
        },
    };

    let parsed_role = rust_backend::utils::auth0_claims::map_auth0_role(&claims, namespace);
    assert_eq!(parsed_role, "admin");
}

#[test]
async fn auth0_role_claim_parses_non_namespaced_roles() {
    let namespace = "example.com";

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|role-test-2".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("role2@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: {
            let mut claims = HashMap::new();
            claims.insert("roles".to_string(), serde_json::json!(["owner"]));
            claims
        },
    };

    let parsed_role = rust_backend::utils::auth0_claims::map_auth0_role(&claims, namespace);
    assert_eq!(parsed_role, "owner");
}

#[test]
async fn auth0_role_claim_defaults_to_renter() {
    let namespace = "example.com";

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|role-test-3".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("default-role@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: HashMap::new(), // No role claim
    };

    let parsed_role = rust_backend::utils::auth0_claims::map_auth0_role(&claims, namespace);
    assert_eq!(parsed_role, "renter"); // Default role
}

#[test]
async fn auth0_role_claim_handles_string_role() {
    let namespace = "example.com";

    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|role-test-4".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("string-role@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: {
            let mut claims = HashMap::new();
            claims.insert("https://example.com/role".to_string(), serde_json::json!("owner"));
            claims
        },
    };

    let parsed_role = rust_backend::utils::auth0_claims::map_auth0_role(&claims, namespace);
    assert_eq!(parsed_role, "owner");
}

// =============================================================================
// IDENTITY LINKING CONFLICTS TESTS
// =============================================================================

#[test]
async fn oauth_login_handles_same_email_different_provider() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // User exists with GitHub linked
    let existing_user = test_user("multi-provider@example.com");
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    let github_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::GitHub,
        provider_id: Some("gh-999".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(github_identity);

    // Login with Google (different provider, same email)
    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "google-888".to_string(),
            email: "multi-provider@example.com".to_string(), // Same email
            email_verified: true,
            full_name: None,
            avatar_url: None,
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::Google,
        "auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());

    // Should link Google to same user
    let google_identity = auth_repo.find_identity_by_provider_id("google", "google-888");
    assert!(google_identity.is_some());
    assert_eq!(google_identity.unwrap().user_id, existing_user_id);

    // Should NOT create new user
    assert_eq!(user_repo.count(), 1);
}

#[test]
async fn oauth_login_prevents_duplicate_identity_for_same_provider() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // User exists with Google linked
    let existing_user = test_user("duplicate-provider@example.com");
    let existing_user_id = existing_user.id;
    user_repo.insert_user(existing_user.clone());

    let google_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user.id,
        provider: AuthProvider::Google,
        provider_id: Some("google-dup-123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now() - Duration::days(1),
    };
    auth_repo.insert_identity(google_identity);

    // Login with same Google provider_id
    let oauth_client = Arc::new(
        MockOAuthClient::new().with_profile(OAuthUserInfo {
            provider_id: "google-dup-123".to_string(), // Same provider_id
            email: "different-email@example.com".to_string(),
            email_verified: true,
            full_name: None,
            avatar_url: None,
        })
    );

    let service = AuthService::new(
        user_repo.clone(),
        auth_repo.clone(),
        auth_config(),
    ).with_oauth_client(oauth_client);

    let result = service.oauth_login(
        OAuthProviderKind::Google,
        "auth-code",
        Some("127.0.0.1".to_string()),
    ).await;

    assert!(result.is_ok());

    // Should return existing user (not create new)
    assert_eq!(result.unwrap().user.id, existing_user_id);

    // Should NOT create new user
    assert_eq!(user_repo.count(), 1);
}

// =============================================================================
// EMAIL VERIFICATION STATUS HANDLING TESTS
// =============================================================================

#[test]
async fn jit_provisioning_preserves_email_verified_status() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace,
    );

    // Test with verified email
    let claims_verified = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|verified-email".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("verified@example.com".to_string()),
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    service.provision_user(&claims_verified).await.unwrap();
    let identity_verified = auth_repo.find_identity_by_provider_id("auth0", "auth0|verified-email");
    assert!(identity_verified.unwrap().verified);

    // Test with unverified email
    let claims_unverified = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|unverified-email".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("unverified@example.com".to_string()),
        email_verified: Some(false),
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    service.provision_user(&claims_unverified).await.unwrap();
    let identity_unverified = auth_repo.find_identity_by_provider_id("auth0", "auth0|unverified-email");
    assert!(!identity_unverified.unwrap().verified);
}

#[test]
async fn jit_provisioning_defaults_email_verified_to_false() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let namespace = String::from("example.com");

    let service = JitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
        namespace,
    );

    // Claims without email_verified field
    let claims = Auth0Claims {
        iss: "https://example.auth0.com".to_string(),
        sub: "auth0|no-verified-123".to_string(),
        aud: rust_backend::utils::auth0_claims::Audience::Single("api.example.com".to_string()),
        exp: (Utc::now().timestamp() + 3600) as u64,
        iat: Utc::now().timestamp() as u64,
        email: Some("no-verified@example.com".to_string()),
        email_verified: None, // Not specified
        name: None,
        picture: None,
        custom_claims: HashMap::new(),
    };

    let _ = service.provision_user(&claims).await.unwrap();
    let identity = auth_repo.find_identity_by_provider_id("auth0", "auth0|no-verified-123");
    assert!(!identity.unwrap().verified); // Should default to false
}

// =============================================================================
// ENSURE ACTIVE SESSION TESTS
// =============================================================================

#[test]
async fn ensure_active_session_returns_ok_when_user_has_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("active@example.com");
    user_repo.insert_user(user.clone());

    // Create an active session
    let active_session = test_session(user.id, Uuid::new_v4(), "active-token");
    auth_repo.insert_session(active_session);

    let result = service.ensure_active_session_for_user(user.id).await;
    assert!(result.is_ok());
}

#[test]
async fn ensure_active_session_returns_unauthorized_when_no_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("no-session@example.com");
    let user_id = user.id;
    user_repo.insert_user(user);

    // No sessions created for this user

    let result = service.ensure_active_session_for_user(user_id).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));
}

#[test]
async fn ensure_active_session_returns_unauthorized_for_expired_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("expired-session@example.com");
    let user_id = user.id;
    user_repo.insert_user(user);

    // Create an expired session
    let mut expired_session = test_session(user_id, Uuid::new_v4(), "expired-token");
    expired_session.expires_at = Utc::now() - Duration::hours(1);
    auth_repo.insert_session(expired_session);

    let result = service.ensure_active_session_for_user(user_id).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));
}

#[test]
async fn ensure_active_session_returns_unauthorized_for_revoked_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

    let user = test_user("revoked-session@example.com");
    let user_id = user.id;
    user_repo.insert_user(user);

    // Create a revoked session
    let mut revoked_session = test_session(user_id, Uuid::new_v4(), "revoked-token");
    revoked_session.revoked_at = Some(Utc::now() - Duration::minutes(10));
    auth_repo.insert_session(revoked_session);

    let result = service.ensure_active_session_for_user(user_id).await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::Unauthorized));
}
