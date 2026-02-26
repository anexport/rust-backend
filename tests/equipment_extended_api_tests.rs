#![allow(clippy::type_complexity)]
#![allow(unused_imports)]
use std::sync::{Arc, Mutex};

mod common;

use crate::common::mocks::{
    MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};

// actix_rt::test is used via #[actix_rt::test] attribute
#[allow(unused_imports)]
use actix_rt::test;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::config::Auth0Config;
use rust_backend::domain::{Condition, Equipment, EquipmentPhoto, Role, User};
use rust_backend::infrastructure::repositories::{
    CategoryRepository, EquipmentRepository, UserRepository,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

// =============================================================================
// Mocks (Reusing from core_api_tests.rs logic)
// =============================================================================

// =============================================================================
// Helpers
// =============================================================================

fn test_user(id: Uuid, role: Role, email: &str) -> User {
    User {
        id,
        email: email.to_string(),
        role,
        username: Some(format!("user-{}", id)),
        full_name: None,
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_equipment(id: Uuid, owner_id: Uuid) -> Equipment {
    Equipment {
        id,
        owner_id,
        category_id: Uuid::new_v4(),
        title: "Test Equipment".to_string(),
        description: None,
        daily_rate: Decimal::new(1000, 2),
        condition: Condition::Good,
        location: None,
        coordinates: None,
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn security_config() -> rust_backend::config::SecurityConfig {
    rust_backend::config::SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    }
}

#[derive(Clone)]
struct MockAuth0ApiClient;
#[async_trait]
impl rust_backend::infrastructure::auth0_api::Auth0ApiClient for MockAuth0ApiClient {
    async fn signup(
        &self,
        _e: &str,
        _p: &str,
        _u: Option<&str>,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0SignupResponse>
    {
        Err(rust_backend::error::AppError::Unauthorized)
    }
    async fn password_grant(
        &self,
        _e: &str,
        _p: &str,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0TokenResponse>
    {
        Err(rust_backend::error::AppError::Unauthorized)
    }
}

#[derive(Clone)]
struct MockJitUserProvisioningService {
    _user_repo: Arc<MockUserRepo>,
}
#[async_trait]
impl UserProvisioningService for MockJitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let user_id = claims
            .sub
            .split('|')
            .nth(1)
            .and_then(|raw| Uuid::parse_str(raw).ok())
            .unwrap_or_else(Uuid::new_v4);
        Ok(Auth0UserContext {
            user_id,
            auth0_sub: claims.sub.clone(),
            role: "owner".to_string(),
            email: claims.email.clone(),
        })
    }
}

struct MockJwksClient {
    decoding_keys: Mutex<std::collections::HashMap<String, jsonwebtoken::DecodingKey>>,
}
impl MockJwksClient {
    fn new() -> Self {
        let mut keys = std::collections::HashMap::new();
        let public_key_pem = include_str!("test_public_key.pem");
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("Failed to load test_public_key.pem - ensure the file exists and contains a valid RSA public key");
        keys.insert("test-key-id".to_string(), key);
        Self {
            decoding_keys: Mutex::new(keys),
        }
    }
}
#[async_trait]
impl rust_backend::utils::auth0_jwks::JwksProvider for MockJwksClient {
    async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> rust_backend::error::AppResult<jsonwebtoken::DecodingKey> {
        self.decoding_keys
            .lock()
            .unwrap()
            .get(kid)
            .cloned()
            .ok_or(rust_backend::error::AppError::Unauthorized)
    }
}

fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("role".to_string(), serde_json::json!(role));
    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());
    let private_key_pem = include_str!("test_private_key.pem");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
    encode(&header, &claims, &encoding_key).unwrap()
}

fn app_with_auth0_data(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(MockJitUserProvisioningService {
            _user_repo: user_repo.clone(),
        });
    let jwks_provider: Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider> =
        Arc::new(MockJwksClient::new());
    let state = AppState {
        auth_service: Arc::new(rust_backend::application::AuthService::new(
            user_repo.clone(),
            auth_repo,
        )),
        admin_service: Arc::new(rust_backend::application::AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(rust_backend::application::UserService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        category_service: Arc::new(rust_backend::application::CategoryService::new(
            category_repo,
        )),
        equipment_service: Arc::new(rust_backend::application::EquipmentService::new(
            user_repo.clone(),
            equipment_repo,
        )),
        message_service: Arc::new(rust_backend::application::MessageService::new(
            user_repo,
            message_repo,
        )),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: PgPoolOptions::new()
            .connect_lazy("postgres://localhost/test")
            .unwrap(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(MockAuth0ApiClient),
    };
    (
        web::Data::new(state),
        web::Data::new(Auth0Config {
            auth0_domain: Some("test-tenant.auth0.com".to_string()),
            auth0_audience: Some("rust-backend-test".to_string()),
            auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
            ..Auth0Config::default()
        }),
        web::Data::new(jwks_provider),
        web::Data::new(provisioning_service),
    )
}

// =============================================================================
// Tests
// =============================================================================

#[actix_rt::test]
async fn update_equipment_401_unauthorized() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(user_repo, equipment_repo);
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn update_equipment_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn update_equipment_404_not_found() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn delete_equipment_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn add_photo_success() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"photo_url": "http://example.com/p.jpg", "is_primary": true}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[actix_rt::test]
async fn delete_photo_success() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let eq_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    equipment_repo.photos.lock().unwrap().push(EquipmentPhoto {
        id: photo_id,
        equipment_id: eq_id,
        photo_url: "u".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    });
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq_id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[actix_rt::test]
async fn delete_equipment_404_not_found() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);
    let owner_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn add_photo_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", eq_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(
            serde_json::json!({"photo_url": "http://example.com/other.jpg", "is_primary": true}),
        )
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn delete_photo_403_forbidden() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks, provisioning) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());
    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo.push(test_user(owner_id, Role::Owner, "o@e.c"));
    user_repo.push(test_user(other_id, Role::Owner, "other@e.c"));
    let eq_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .unwrap()
        .push(test_equipment(eq_id, owner_id));
    equipment_repo.photos.lock().unwrap().push(EquipmentPhoto {
        id: photo_id,
        equipment_id: eq_id,
        photo_url: "u".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    });
    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}/photos/{}", eq_id, photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
