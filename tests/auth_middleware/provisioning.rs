use super::*;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::{Duration, Utc};
use rust_backend::domain::*;
use rust_backend::error::AppError;
use rust_backend::middleware::auth::*;
use rust_backend::utils::auth0_claims::*;
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn user_provisioning_with_existing_identity_reuses_user() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // Create an existing user and identity
    let existing_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: existing_user_id,
        email: "existing@example.com".to_string(),
        role: Role::Owner,
        username: Some("existing-user".to_string()),
        full_name: Some("Existing User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let existing_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: existing_user_id,
        provider: AuthProvider::Auth0,
        provider_id: Some("auth0|existing123".to_string()),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };

    auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned")
        .push(existing_identity);

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|existing123".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("existing@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Existing User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should find existing identity");

    assert_eq!(user_context.user_id, existing_user_id);
    assert_eq!(user_context.auth0_sub, "auth0|existing123");
}

#[actix_rt::test]
async fn user_provisioning_with_existing_email_creates_new_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    // Create an existing user with email (but no Auth0 identity)
    let existing_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: existing_user_id,
        email: "existing@example.com".to_string(),
        role: Role::Renter,
        username: Some("existing-email-user".to_string()),
        full_name: Some("Existing Email User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|new-identity".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("existing@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Existing Email User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should create new identity for existing user");

    assert_eq!(user_context.user_id, existing_user_id);
    assert_eq!(user_context.auth0_sub, "auth0|new-identity");

    // Verify the new identity was created
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(
        identities[0].provider_id,
        Some("auth0|new-identity".to_string())
    );
}

#[actix_rt::test]
async fn user_provisioning_creates_new_user_when_none_exist() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|brand-new".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("brandnew@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Brand New User".to_string()),
        picture: Some("https://example.com/avatar.jpg".to_string()),
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should create new user and identity");

    assert_eq!(user_context.auth0_sub, "auth0|brand-new");
    assert_eq!(user_context.role, "renter"); // Default role

    // Verify the new user was created
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "brandnew@example.com");
    assert_eq!(users[0].role, Role::Renter);
    assert_eq!(users[0].full_name, Some("Brand New User".to_string()));
    assert_eq!(
        users[0].avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );

    // Verify the new identity was created
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].provider, AuthProvider::Auth0);
    assert_eq!(
        identities[0].provider_id,
        Some("auth0|brand-new".to_string())
    );
    assert!(identities[0].verified);
}

#[actix_rt::test]
async fn user_provisioning_without_email_returns_bad_request() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    // Create claims without email
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|no-email".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: Some("No Email User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let result = provisioning_service.provision_user(&claims).await;
    assert!(matches!(
        result,
        Err(AppError::BadRequest(message)) if message == "Email is required from Auth0"
    ));

    // Verify no user was created when email is missing.
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert!(users.is_empty());
}

#[actix_rt::test]
async fn user_provisioning_with_custom_role_maps_correctly() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/roles".to_string(),
        serde_json::json!(["owner", "admin"]),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|role-test".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("owner@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Owner User".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with role");

    assert_eq!(user_context.role, "owner");
}

#[actix_rt::test]
async fn user_provisioning_with_non_namespaced_role_maps_correctly() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("roles".to_string(), serde_json::json!(["admin"]));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|non-namespaced".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("admin@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Admin User".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with non-namespaced role");

    assert_eq!(user_context.role, "admin");
}

#[actix_rt::test]
async fn user_provisioning_defaults_to_renter_when_no_role_claim() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|no-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("norole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("No Role User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with default role");

    assert_eq!(user_context.role, "renter");
}

// ============================================================================
// TEST: Auth0 Claims validation tests
// ============================================================================

#[actix_rt::test]
async fn user_provisioning_with_verified_email_creates_verified_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|verified".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("verified@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Verified User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with verified email");

    // Verify the identity was created as verified
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert!(identities[0].verified);
}

#[actix_rt::test]
async fn user_provisioning_with_unverified_email_creates_unverified_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|unverified".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("unverified@example.com".to_string()),
        email_verified: Some(false), // Explicitly unverified
        name: Some("Unverified User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with unverified email");

    // Verify the identity was created as unverified
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert!(!identities[0].verified);
}

// ============================================================================
// TEST: User attributes from claims
// ============================================================================

#[actix_rt::test]
async fn user_provisioning_copies_name_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|with-name".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("withname@example.com".to_string()),
        email_verified: Some(true),
        name: Some("John Doe".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with name");

    // Verify the user was created with the name
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].full_name, Some("John Doe".to_string()));
}

#[actix_rt::test]
async fn user_provisioning_copies_avatar_from_claims() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|with-avatar".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("withavatar@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Avatar User".to_string()),
        picture: Some("https://cdn.auth0.com/avatar.jpg".to_string()),
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with avatar");

    // Verify the user was created with the avatar
    let users = user_repo.users.lock().expect("users mutex poisoned");
    assert_eq!(users.len(), 1);
    assert_eq!(
        users[0].avatar_url,
        Some("https://cdn.auth0.com/avatar.jpg".to_string())
    );
}

// ============================================================================
// TEST: Identity provider attribute validation
// ============================================================================

#[actix_rt::test]
async fn user_provisioning_sets_auth0_provider() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|provider-test".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("provider@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Provider Test".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should provision user with Auth0 provider");

    // Verify the identity was created with Auth0 provider
    let identities = auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].provider, AuthProvider::Auth0);
    assert!(identities[0].password_hash.is_none()); // OAuth identities don't have passwords
}

// ============================================================================
// TEST: Custom claims handling
// ============================================================================

#[actix_rt::test]
async fn user_provisioning_with_non_standard_custom_claim() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/roles".to_string(),
        serde_json::json!("renter"),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|custom-claim".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("custom@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Custom Claim".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle custom claims");

    // Role should be extracted from custom claims
    assert_eq!(user_context.role, "renter");
}

// ============================================================================
// TEST: Multiple custom role claim formats
// ============================================================================

#[actix_rt::test]
async fn user_provisioning_with_role_as_single_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-app.com/role".to_string(),
        serde_json::json!("admin"),
    );

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|single-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("singlerole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Single Role".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle single string role");

    assert_eq!(user_context.role, "admin");
}

#[actix_rt::test]
async fn user_provisioning_with_non_namespaced_role_as_single_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(JitUserProvisioningService::new(
            user_repo.clone(),
            auth_repo.clone(),
            "test-app.com".to_string(),
        ));

    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("role".to_string(), serde_json::json!("owner"));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: "auth0|non-ns-role".to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some("nonnsrole@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Non Namespaced Role".to_string()),
        picture: None,
        custom_claims,
    };

    let user_context = provisioning_service
        .provision_user(&claims)
        .await
        .expect("Should handle non-namespaced single role");

    assert_eq!(user_context.role, "owner");
}

// ============================================================================
// TEST: Auth0AuthenticatedUser extractor branches
// ============================================================================
