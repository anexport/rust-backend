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

        if user_repo.find_by_id(user_id).await?.is_none() {
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
        }

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
async fn test_equipment_photo_authorization() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    let other_user = fixtures::test_user();
    let admin = fixtures::test_admin();
    user_repo.create(&owner).await.unwrap();
    user_repo.create(&other_user).await.unwrap();
    user_repo.create(&admin).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let owner_token = create_auth0_token(owner.id, "owner");
    let other_token = create_auth0_token(other_user.id, "renter");
    let admin_token = create_auth0_token(admin.id, "admin");

    // 1. Other user cannot add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", other_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/hacker.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 2. Owner can add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/owner.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let photo: serde_json::Value = actix_test::read_body_json(resp).await;
    let photo_id = Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap();

    // 3. Admin can add photo
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/admin.jpg",
            "is_primary": false
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. Other user cannot delete photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", other_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // 5. Owner can delete photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", owner_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn test_equipment_multiple_photos() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add 3 photos
    for i in 1..=3 {
        let req = actix_test::TestRequest::post()
            .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(serde_json::json!({
                "photo_url": format!("https://example.com/p{}.jpg", i),
                "is_primary": i == 1
            }))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 3);
}

#[actix_rt::test]
async fn test_admin_photo_management() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(test_db.pool().clone());
    let category_repo = CategoryRepositoryImpl::new(test_db.pool().clone());

    let owner = fixtures::test_owner();
    let admin = fixtures::test_admin();
    user_repo.create(&owner).await.unwrap();
    user_repo.create(&admin).await.unwrap();

    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let admin_token = create_auth0_token(admin.id, "admin");

    // Admin adds photo to owner's equipment
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/admin_added.jpg",
            "is_primary": false
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let photo: serde_json::Value = actix_test::read_body_json(resp).await;
    let photo_id = Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap();

    // Admin deletes photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq.id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", admin_token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn test_photo_persistence_verification() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");
    let photo_url = "https://example.com/persistence_test.jpg";

    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "photo_url": photo_url,
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify in DB
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 1);
    assert_eq!(photos[0].photo_url, photo_url);
}

#[actix_rt::test]
async fn test_photo_associated_with_correct_equipment() {
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

    let eq1 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq1).await.unwrap();
    let eq2 = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq2).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add photo to eq1
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq1.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/eq1.jpg",
            "is_primary": true
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify eq2 has NO photos
    let photos2 = equipment_repo.find_photos(eq2.id).await.unwrap();
    assert!(photos2.is_empty());
}

#[actix_rt::test]
async fn test_delete_equipment_cascades_to_photos() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add 3 photos
    for i in 1..=3 {
        let req = actix_test::TestRequest::post()
            .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(serde_json::json!({
                "photo_url": format!("https://example.com/cascade{}.jpg", i),
                "is_primary": i == 1
            }))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    // Delete equipment
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify photos are gone from DB
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert!(photos.is_empty());
}

#[actix_rt::test]
async fn test_delete_photo_leaves_other_photos_intact() {
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
    let eq = fixtures::test_equipment(owner.id, cat.id);
    equipment_repo.create(&eq).await.unwrap();

    let token = create_auth0_token(owner.id, "owner");

    // Add 3 photos
    let mut photo_ids = Vec::new();
    for i in 1..=3 {
        let req = actix_test::TestRequest::post()
            .uri(&format!("/api/v1/equipment/{}/photos", eq.id))
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(serde_json::json!({
                "photo_url": format!("https://example.com/intact{}.jpg", i),
                "is_primary": i == 1
            }))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        let photo: serde_json::Value = actix_test::read_body_json(resp).await;
        photo_ids.push(Uuid::parse_str(photo["id"].as_str().unwrap()).unwrap());
    }

    // Delete 1 photo
    let req = actix_test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/equipment/{}/photos/{}",
            eq.id, photo_ids[0]
        ))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify 2 remaining
    let photos = equipment_repo.find_photos(eq.id).await.unwrap();
    assert_eq!(photos.len(), 2);
    assert!(!photos.iter().any(|p| p.id == photo_ids[0]));
    assert!(photos.iter().any(|p| p.id == photo_ids[1]));
    assert!(photos.iter().any(|p| p.id == photo_ids[2]));
}
