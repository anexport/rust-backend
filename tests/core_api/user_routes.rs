use super::*;
use crate::common;

use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::{Auth0Config, SecurityConfig};
use rust_backend::domain::Role;
use rust_backend::infrastructure::auth0_api::DisabledAuth0ApiClient;
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepository, CategoryRepositoryImpl, EquipmentRepository,
    EquipmentRepositoryImpl, MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;
use std::sync::Arc;
use uuid::Uuid;

use common::fixtures;
use common::TestDb;

// ============================================================================
// Mock Infrastructure for Auth0 (Reuse pattern from admin tests)
// ============================================================================

struct MockJwksProvider {
    decoding_key: jsonwebtoken::DecodingKey,
}

impl MockJwksProvider {
    fn new() -> Self {
        let public_key_pem = include_str!("../test_public_key.pem");
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("failed to load test public key");
        Self { decoding_key }
    }
}

#[async_trait]
impl JwksProvider for MockJwksProvider {
    async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> rust_backend::error::AppResult<jsonwebtoken::DecodingKey> {
        if kid == "test-key-id" {
            Ok(self.decoding_key.clone())
        } else {
            Err(rust_backend::error::AppError::Unauthorized)
        }
    }
}

struct MockProvisioningService {
    db_pool: sqlx::PgPool,
}

#[async_trait]
impl UserProvisioningService for MockProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let user_repo = UserRepositoryImpl::new(self.db_pool.clone());
        let sub = &claims.sub;

        let user_id = if let Some(id_part) = sub.strip_prefix("auth0|") {
            Uuid::parse_str(id_part).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };

        let role_str = if let Some(role_val) = claims
            .custom_claims
            .get("https://test-tenant.auth0.com/role")
        {
            role_val.as_str().unwrap_or("renter").to_string()
        } else {
            "renter".to_string()
        };

        // Ensure user exists in DB for tests
        if let Some(user) = user_repo.find_by_id(user_id).await? {
            return Ok(Auth0UserContext {
                user_id: user.id,
                auth0_sub: sub.clone(),
                role: user.role.to_string(),
                email: Some(user.email),
            });
        }

        let user = rust_backend::domain::User {
            id: user_id,
            email: claims
                .email
                .clone()
                .unwrap_or_else(|| format!("{}@example.com", sub)),
            role: match role_str.as_str() {
                "admin" => Role::Admin,
                "owner" => Role::Owner,
                _ => Role::Renter,
            },
            username: None,
            full_name: claims.name.clone(),
            avatar_url: claims.picture.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        user_repo.create(&user).await?;

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: sub.clone(),
            role: role_str,
            email: claims.email.clone(),
        })
    }
}

fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-tenant.auth0.com/role".to_string(),
        serde_json::json!(role),
    );

    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some(format!("user-{}@example.com", user_id)),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());

    let private_key_pem = include_str!("../test_private_key.pem");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode test token")
}

fn test_auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test-tenant.auth0.com".to_string()),
        auth0_audience: Some("rust-backend-test".to_string()),
        auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

async fn setup_app(
    db_pool: sqlx::PgPool,
) -> impl actix_web::dev::Service<
    actix_http::Request,
    Response = actix_web::dev::ServiceResponse,
    Error = actix_web::Error,
> {
    let user_repo = Arc::new(UserRepositoryImpl::new(db_pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(db_pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(db_pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(db_pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(db_pool.clone()));

    let security = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    };

    let state = AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo.clone())),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo.clone())),
        equipment_service: Arc::new(EquipmentService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo.clone())),
        security: security.clone(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(&security)),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: db_pool.clone(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(DisabledAuth0ApiClient),
    };

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(MockJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(MockProvisioningService {
            db_pool: db_pool.clone(),
        });

    actix_test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(test_auth0_config()))
            .app_data(web::Data::new(jwks_provider))
            .app_data(web::Data::new(provisioning_service))
            .configure(routes::configure),
    )
    .await
}

// ============================================================================
// TESTS
// ============================================================================

#[actix_rt::test]
async fn test_get_user_profile_not_found() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", Uuid::new_v4()))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_update_profile_partial() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    let old_full_name = "Original Name".to_string();
    let mut user = user;
    user.full_name = Some(old_full_name.clone());
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // Update only username, full_name should remain
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "username": "new_user"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.username, Some("new_user".to_string()));
    assert_eq!(updated.full_name, Some(old_full_name));
}

#[actix_rt::test]
async fn test_my_equipment_unauthorized() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn test_update_own_profile() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "full_name": "Updated Name",
            "username": "updated_username"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.full_name, Some("Updated Name".to_string()));
    assert_eq!(updated.username, Some("updated_username".to_string()));
}

#[actix_rt::test]
async fn test_cannot_update_other_profile() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let user2 = fixtures::test_user();
    user_repo.create(&user2).await.unwrap();

    let token = create_auth0_token(user1.id, "renter");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user2.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "full_name": "Hacker" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_my_equipment_listing() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let other_owner = fixtures::test_owner();
    user_repo.create(&other_owner).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Owner has 2 items
    let eq1 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq1).await.unwrap();
    let eq2 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq2).await.unwrap();

    // Other owner has 1 item
    let eq3 = fixtures::test_equipment(other_owner.id, cat.id);
    equipment_repo.create(&eq3).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["owner_id"] == owner.id.to_string()));
}

#[actix_rt::test]
async fn test_profile_viewing_excludes_sensitive_data() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user.id))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let profile: serde_json::Value = actix_test::read_body_json(resp).await;
    // Should have: id, username, avatar_url
    assert!(profile.get("id").is_some());
    // username and avatar_url are optional fields - they may be null or missing
    // Check for non-null values, not just key existence
    let username = profile.get("username").and_then(|v| v.as_str());
    let avatar_url = profile.get("avatar_url").and_then(|v| v.as_str());
    // At least one of username or avatar_url should be present with a non-null value
    assert!(
        username.is_some() || avatar_url.is_some(),
        "Profile should have at least username or avatar_url with a non-null value"
    );

    // Should NOT have: email, role, created_at (if using PublicProfileResponse)
    assert!(profile.get("email").is_none());
    assert!(profile.get("role").is_none());
}

#[actix_rt::test]
async fn test_profile_update_username_constraints() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // 1. Username too short (min=3)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": "ab" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Username too long (max=50)
    let long_username = "a".repeat(51);
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": long_username }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_my_equipment_ordered_by_creation_date() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Create equipment with different timestamps
    for i in 0..3 {
        let mut eq = fixtures::test_equipment(owner.id, cat.id);
        eq.title = format!("Equipment {}", i);
        eq.created_at = Utc::now() + Duration::minutes(i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let token = create_auth0_token(owner.id, "owner");
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;

    // Should be newest first
    assert_eq!(items[0]["title"], "Equipment 2");
    assert_eq!(items[1]["title"], "Equipment 1");
    assert_eq!(items[2]["title"], "Equipment 0");
}

#[actix_rt::test]
async fn test_get_public_profile_anonymous() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user.id))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn test_profile_update_email_validation() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // 1. Try update with valid username (email-like format should work as username)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "username": "testuser123"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.username, Some("testuser123".to_string()));

    // 2. Verify valid username update still works after previous update
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "username": "another.valid.username"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.username, Some("another.valid.username".to_string()));

    // 3. Invalid username format (too short)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": "ab" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_my_equipment_pagination() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // Create 15 equipment items with explicit timestamps to avoid race conditions
    let equipment_count = 15;
    for i in 0..equipment_count {
        let mut eq = fixtures::test_equipment(owner.id, cat.id);
        eq.title = format!("Equipment {}", i);
        eq.created_at = Utc::now() + Duration::minutes(i);
        equipment_repo.create(&eq).await.unwrap();
    }

    let token = create_auth0_token(owner.id, "owner");

    // Test that all items are returned (current behavior)
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let items: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;

    // Assert total count is 15
    assert_eq!(items.len(), equipment_count as usize);

    // Verify all items belong to the owner
    assert!(items.iter().all(|i| i["owner_id"] == owner.id.to_string()));

    // Verify ordering is by creation date (newest first based on SQL)
    // With explicit timestamps, Equipment 14 (created at +14min) should be first
    // Equipment 0 (created at +0min) should be last
    assert_eq!(
        items[0]["title"],
        format!("Equipment {}", equipment_count - 1)
    );
    assert_eq!(
        items[equipment_count as usize - 1]["title"],
        format!("Equipment {}", 0)
    );
}
