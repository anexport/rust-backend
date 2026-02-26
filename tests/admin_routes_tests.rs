mod common;

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
    AuthRepository, AuthRepositoryImpl, CategoryRepository, CategoryRepositoryImpl,
    EquipmentRepository, EquipmentRepositoryImpl, MessageRepositoryImpl, UserRepository,
    UserRepositoryImpl,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;
use std::sync::Arc;
use uuid::Uuid;

use common::fixtures;
use common::TestDb;

// ============================================================================
// Mock Infrastructure for Auth0
// ============================================================================

struct MockJwksProvider {
    decoding_key: jsonwebtoken::DecodingKey,
}

impl MockJwksProvider {
    fn new() -> Self {
        let public_key_pem = include_str!("test_public_key.pem");
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
        let auth_repo = AuthRepositoryImpl::new(self.db_pool.clone());

        let sub = &claims.sub;

        // Try to find existing identity
        if let Some(identity) = auth_repo.find_identity_by_provider_id("auth0", sub).await? {
            let user = user_repo.find_by_id(identity.user_id).await?.unwrap();
            return Ok(Auth0UserContext {
                user_id: user.id,
                auth0_sub: sub.clone(),
                role: user.role.to_string(),
                email: Some(user.email),
            });
        }

        // Otherwise use the role from claims or default to renter
        let role_str = if let Some(role_val) = claims
            .custom_claims
            .get("https://test-tenant.auth0.com/role")
        {
            role_val.as_str().unwrap_or("renter").to_string()
        } else {
            "renter".to_string()
        };

        // This is a simplification for tests: we expect the user to already exist in the DB
        // if we are testing with a specific UUID in the sub.
        // If sub is "auth0|uuid", we use that UUID.
        let user_id = if let Some(id_part) = sub.strip_prefix("auth0|") {
            Uuid::parse_str(id_part).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: sub.clone(),
            role: role_str,
            email: claims.email.clone(),
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

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

    let private_key_pem = include_str!("test_private_key.pem");
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
async fn test_admin_stats_authorization() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    // 1. Unauthenticated (401)
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Authenticated as Renter (403)
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();
    let token = create_auth0_token(renter.id, "renter");

    let routes = vec![
        "/api/v1/admin/stats",
        "/api/v1/admin/users",
        "/api/v1/admin/equipment",
        "/api/v1/admin/categories",
    ];

    for route in routes {
        let req = actix_test::TestRequest::get()
            .uri(route)
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Route {} should be forbidden for renter",
            route
        );
    }
}

#[actix_rt::test]
async fn test_admin_cannot_demote_self() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // Try to demote self to renter
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", admin.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "renter" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Verify still admin
    let user = user_repo.find_by_id(admin.id).await.unwrap().unwrap();
    assert_eq!(user.role, Role::Admin);
}

#[actix_rt::test]
async fn test_admin_update_role_owner_to_admin() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", owner.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "admin" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(owner.id).await.unwrap().unwrap();
    assert_eq!(updated.role, Role::Admin);
}

#[actix_rt::test]
async fn test_get_stats_empty_db() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let stats: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(stats["total_users"], 1); // Only admin
    assert_eq!(stats["total_equipment"], 0);
    assert_eq!(stats["total_categories"], 0);
}

#[actix_rt::test]
async fn test_admin_category_hierarchy_validation() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let parent_cat = fixtures::test_category();
    category_repo.create(&parent_cat).await.unwrap();

    // 1. Create child with parent
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "name": "Child Category",
            "parent_id": parent_cat.id
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let child: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(child["parent_id"], parent_cat.id.to_string());

    // 2. Prevent self-parenting
    let child_id = child["id"].as_str().unwrap();
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/categories/{}", child_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "name": "Self Parent",
            "parent_id": child_id
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_admin_toggle_foreign_equipment_availability() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/equipment/{}/availability", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "is_available": false }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_eq = equipment_repo.find_by_id(eq.id).await.unwrap().unwrap();
    assert!(!updated_eq.is_available);
}

#[actix_rt::test]
async fn test_user_management_flow() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();

    // 1. List users
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let list: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(list["total"], 2);

    // 2. Update role (renter -> owner)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "role": "owner" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_user = user_repo.find_by_id(renter.id).await.unwrap().unwrap();
    assert_eq!(updated_user.role, Role::Owner);

    // 3. Delete user
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/users/{}", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_user = user_repo.find_by_id(renter.id).await.unwrap();
    assert!(deleted_user.is_none());
}

#[actix_rt::test]
async fn test_equipment_management_flow() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    // 1. Toggle availability
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/equipment/{}/availability", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "is_available": false }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_eq = equipment_repo.find_by_id(eq.id).await.unwrap().unwrap();
    assert!(!updated_eq.is_available);

    // 2. Force delete equipment
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/equipment/{}", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_eq = equipment_repo.find_by_id(eq.id).await.unwrap();
    assert!(deleted_eq.is_none());
}

#[actix_rt::test]
async fn test_category_management_flow() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // 1. Create category
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "name": "New Category" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created: serde_json::Value = actix_test::read_body_json(resp).await;
    let cat_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    // 2. Update category
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/categories/{}", cat_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "name": "Updated Category" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated_cat = category_repo.find_by_id(cat_id).await.unwrap().unwrap();
    assert_eq!(updated_cat.name, "Updated Category");

    // 3. Delete category
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/categories/{}", cat_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let deleted_cat = category_repo.find_by_id(cat_id).await.unwrap();
    assert!(deleted_cat.is_none());
}

#[actix_rt::test]
async fn test_stats_includes_available_equipment_count() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // 2 available, 1 not
    let mut eq1 = fixtures::test_equipment(owner.id, cat.id);
    eq1.is_available = true;
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(owner.id, cat.id);
    eq2.is_available = true;
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(owner.id, cat.id);
    eq3.is_available = false;
    equipment_repo.create(&eq3).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let stats: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(stats["total_equipment"], 3);
    assert_eq!(stats["available_equipment"], 2);
}

#[actix_rt::test]
async fn test_get_user_detail_by_id() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();

    // Get user detail
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/admin/users/{}", renter.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let detail: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(detail["id"], renter.id.to_string());
    assert_eq!(detail["email"], renter.email);

    // Non-existent user
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/admin/users/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_user_list_pagination() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    // Create 11 more users (total 12)
    for _ in 0..11 {
        let u = fixtures::test_user();
        user_repo.create(&u).await.unwrap();
    }

    // Page 1
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=1&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page1: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page1["users"].as_array().unwrap().len(), 5);
    assert_eq!(page1["total"], 12);

    // Page 2
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=2&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page2: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page2["users"].as_array().unwrap().len(), 5);

    // Page 3
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/users?page=3&per_page=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let page3: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(page3["users"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn test_delete_user_cascades_to_equipment() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    // Delete user
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/admin/users/{}", owner.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let status = resp.status();
    if status != StatusCode::NO_CONTENT {
        let body: serde_json::Value = actix_test::read_body_json(resp).await;
        panic!("Delete user failed with status {}: {:?}", status, body);
    }
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify equipment is also gone
    let deleted_eq = equipment_repo.find_by_id(eq.id).await.unwrap();
    assert!(deleted_eq.is_none());
}

#[actix_rt::test]
async fn test_category_list_with_hierarchy() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let mut parent = fixtures::test_category();
    parent.name = "Parent".to_string();
    category_repo.create(&parent).await.unwrap();

    let mut child = fixtures::test_category();
    child.name = "Child".to_string();
    child.parent_id = Some(parent.id);
    category_repo.create(&child).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/categories")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert!(list.len() >= 2);

    let child_entry = list
        .iter()
        .find(|c| c["id"] == child.id.to_string())
        .unwrap();
    assert_eq!(child_entry["parent_id"], parent.id.to_string());
}

#[actix_rt::test]
async fn test_admin_can_demote_other_admin_role() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin1 = fixtures::test_admin();
    user_repo.create(&admin1).await.unwrap();
    let admin2 = fixtures::test_admin();
    user_repo.create(&admin2).await.unwrap();

    let token1 = create_auth0_token(admin1.id, "admin");

    // Try to change admin2's role to renter
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/admin/users/{}/role", admin2.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({ "role": "renter" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(admin2.id).await.unwrap().unwrap();
    assert_eq!(updated.role, Role::Renter);
}
