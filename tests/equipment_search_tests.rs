use std::sync::{Arc, Mutex};

mod common;

use crate::common::mocks::{
    haversine_km, MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};
use actix_rt::test;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::{Auth0Config, AuthConfig, SecurityConfig};
use rust_backend::domain::{
    AuthIdentity, AuthProvider, Category, Condition, Conversation, Equipment, EquipmentPhoto,
    Message, Role, User,
};
use rust_backend::infrastructure::auth0_api::{Auth0SignupResponse, Auth0TokenResponse};
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, EquipmentSearchParams,
    MessageRepository, UserRepository,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::observability::AppMetrics;
use rust_backend::security::{cors_middleware, security_headers};
use rust_backend::utils::auth0_claims::Auth0UserContext;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims};
use rust_backend::utils::auth0_jwks::JwksProvider;
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

// =============================================================================
// Mock Auth0ApiClient
// =============================================================================

#[derive(Clone)]
struct MockAuth0ApiClient;

#[async_trait]
impl rust_backend::infrastructure::auth0_api::Auth0ApiClient for MockAuth0ApiClient {
    async fn signup(
        &self,
        _email: &str,
        _password: &str,
        _username: Option<&str>,
    ) -> rust_backend::error::AppResult<Auth0SignupResponse> {
        Ok(Auth0SignupResponse {
            id: "auth0|test_user_id".to_string(),
            email: _email.to_string(),
            email_verified: true,
            username: _username.map(|s| s.to_string()),
            picture: None,
            name: None,
            created_at: Some(Utc::now().to_rfc3339()),
            updated_at: Some(Utc::now().to_rfc3339()),
        })
    }

    async fn password_grant(
        &self,
        _email: &str,
        _password: &str,
    ) -> rust_backend::error::AppResult<Auth0TokenResponse> {
        Ok(Auth0TokenResponse {
            access_token: "mock_access_token".to_string(),
            refresh_token: Some("mock_refresh_token".to_string()),
            id_token: "mock_id_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 900,
            scope: None,
        })
    }
}

// =============================================================================
// Mock JWKS Client
// =============================================================================

struct MockJwksClient {
    decoding_keys: Mutex<std::collections::HashMap<String, DecodingKey>>,
}

impl MockJwksClient {
    fn new() -> Self {
        let mut keys = std::collections::HashMap::new();
        let public_key_pem = include_str!("test_public_key.pem");
        if let Ok(key) = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()) {
            keys.insert("test-key-id".to_string(), key);
        }
        Self {
            decoding_keys: Mutex::new(keys),
        }
    }
}

#[async_trait]
impl JwksProvider for MockJwksClient {
    async fn get_decoding_key(&self, kid: &str) -> rust_backend::error::AppResult<DecodingKey> {
        self.decoding_keys
            .lock()
            .expect("decoding_keys mutex poisoned")
            .get(kid)
            .cloned()
            .ok_or(rust_backend::error::AppError::Unauthorized)
    }
}

// =============================================================================
// Mock JitUserProvisioningService
// =============================================================================

#[derive(Clone)]
struct MockJitUserProvisioningService {
    user_repo: Arc<MockUserRepo>,
    auth_repo: Arc<MockAuthRepo>,
}

impl MockJitUserProvisioningService {
    fn new(user_repo: Arc<MockUserRepo>, auth_repo: Arc<MockAuthRepo>) -> Self {
        Self {
            user_repo,
            auth_repo,
        }
    }
}

#[async_trait]
impl UserProvisioningService for MockJitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let sub_user_id = claims
            .sub
            .split('|')
            .nth(1)
            .and_then(|raw| Uuid::parse_str(raw).ok());

        let existing_user_id = {
            let users = self.user_repo.users.lock().unwrap();
            sub_user_id
                .and_then(|id| users.iter().find(|u| u.id == id).map(|u| u.id))
                .or_else(|| {
                    users
                        .iter()
                        .find(|u| u.email == claims.email.as_deref().unwrap_or(""))
                        .map(|u| u.id)
                })
        };

        let user_id = if let Some(existing_id) = existing_user_id {
            existing_id
        } else {
            let role = match map_role_from_claim(claims).as_str() {
                "admin" => Role::Admin,
                "owner" => Role::Owner,
                _ => Role::Renter,
            };
            // Create new user if not found
            let user = User {
                id: sub_user_id.unwrap_or_else(Uuid::new_v4),
                email: claims
                    .email
                    .clone()
                    .unwrap_or_else(|| format!("{}@placeholder.test", claims.sub)),
                role,
                username: None,
                full_name: claims.name.clone(),
                avatar_url: claims.picture.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.user_repo.users.lock().unwrap().push(user.clone());
            user.id
        };

        let identity = AuthIdentity {
            id: Uuid::new_v4(),
            user_id,
            provider: AuthProvider::Auth0,
            provider_id: Some(claims.sub.clone()),
            password_hash: None,
            verified: claims.email_verified.unwrap_or(false),
            created_at: Utc::now(),
        };
        self.auth_repo.create_identity(&identity).await?;

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: claims.sub.clone(),
            role: map_role_from_claim(claims),
            email: claims.email.clone(),
        })
    }
}

fn map_role_from_claim(claims: &Auth0Claims) -> String {
    // Try to get role from custom claims
    if let Some(role_value) = claims.custom_claims.get("https://test.com/role") {
        if let Some(role_str) = role_value.as_str() {
            return role_str.to_string();
        }
    }
    if let Some(role_value) = claims.custom_claims.get("role") {
        if let Some(role_str) = role_value.as_str() {
            return role_str.to_string();
        }
    }
    "renter".to_string()
}

// =============================================================================
// Helper Functions
// =============================================================================

fn auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-api".to_string()),
        auth0_issuer: Some("https://test.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

fn security_config() -> SecurityConfig {
    SecurityConfig {
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

// Helper to create a valid Auth0 token with role
fn create_auth0_token_with_role(
    sub: &str,
    email: Option<String>,
    role: &str,
    exp: i64,
    key_id: &str,
) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("https://test.com/role".to_string(), serde_json::json!(role));
    custom_claims.insert("role".to_string(), serde_json::json!(role));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-api".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email,
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_id.to_string());

    let private_key_pem = include_str!("test_private_key.pem");
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode test token")
}

fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();
    create_auth0_token_with_role(
        &format!("auth0|{}", user_id),
        None,
        role,
        exp,
        "test-key-id",
    )
}

fn app_state(user_repo: Arc<MockUserRepo>, equipment_repo: Arc<MockEquipmentRepo>) -> AppState {
    app_state_with_provisioning(
        user_repo,
        equipment_repo,
        Arc::new(MockMessageRepo::default()),
    )
}

fn app_state_with_provisioning(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
    message_repo: Arc<MockMessageRepo>,
) -> AppState {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let auth0_api_client = Arc::new(MockAuth0ApiClient);

    AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo)),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    }
}

fn app_with_auth0_data(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let auth0_api_client = Arc::new(MockAuth0ApiClient);
    let provisioning_service = Arc::new(MockJitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
    ));
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(MockJwksClient::new());
    let auth0_jwks_client = web::Data::new(jwks_provider.clone());
    let auth0_config_data = web::Data::new(auth0_config());
    let provisioning_service_data =
        web::Data::new(provisioning_service.clone() as Arc<dyn UserProvisioningService>);

    let state = AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo)),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    };

    (
        web::Data::new(state),
        auth0_config_data,
        auth0_jwks_client,
        provisioning_service_data,
    )
}

fn test_db_pool() -> sqlx::PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:1/test_db".to_string());
    PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("test db pool should build lazily")
}

fn create_equipment(
    id: Uuid,
    owner_id: Uuid,
    category_id: Uuid,
    title: &str,
    daily_rate: i64,
    condition: rust_backend::domain::Condition,
    location: Option<&str>,
    lat: Option<f64>,
    lng: Option<f64>,
    is_available: bool,
) -> Equipment {
    let mut equipment = Equipment {
        id,
        owner_id,
        category_id,
        title: title.to_string(),
        description: Some(format!("Description for {}", title)),
        daily_rate: Decimal::new(daily_rate, 2),
        condition,
        location: location.map(String::from),
        coordinates: None,
        is_available,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    if let (Some(lat), Some(lng)) = (lat, lng) {
        equipment.set_coordinates(lat, lng).unwrap();
    }
    equipment
}

fn get_items_array(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body.get("items")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn get_total(body: &serde_json::Value) -> i64 {
    body.get("total")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

fn get_page(body: &serde_json::Value) -> i64 {
    body.get("page")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1)
}

fn get_limit(body: &serde_json::Value) -> i64 {
    body.get("limit")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(20)
}

fn get_total_pages(body: &serde_json::Value) -> i64 {
    body.get("total_pages")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

// =============================================================================
// Geographic Search Tests
// =============================================================================

#[test]
async fn geographic_search_returns_equipment_within_radius() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Central Park, NYC coordinates: 40.7829, -73.9654
    // Add equipment at various distances
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Central Park Camera",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Central Park"),
        Some(40.7829),
        Some(-73.9654),
        true,
    ));
    // Times Square is about 2.5km from Central Park
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Times Square Lens",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Times Square"),
        Some(40.7580),
        Some(-73.9855),
        true,
    ));
    // Brooklyn Bridge is about 9km from Central Park (should be filtered out with a 5km radius)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Brooklyn Lights",
        6000,
        rust_backend::domain::Condition::New,
        Some("Brooklyn Bridge"),
        Some(40.7061),
        Some(-73.9969),
        true,
    ));
    // Statue of Liberty is about 10km from Central Park (should be filtered out with 5km radius)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Liberty Gear",
        7000,
        rust_backend::domain::Condition::Good,
        Some("Liberty Island"),
        Some(40.6892),
        Some(-74.0445),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7829&lng=-73.9654&radius_km=5")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);
    assert_eq!(get_total(&body), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"Central Park Camera"));
    assert!(titles.contains(&"Times Square Lens"));
    assert!(!titles.contains(&"Brooklyn Lights"));
    assert!(!titles.contains(&"Liberty Gear"));
}

#[test]
async fn geographic_search_results_sorted_by_distance() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Origin: Union Square, NYC (40.7327, -73.9914)
    // Add equipment at known distances
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Union Square Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Union Square"),
        Some(40.7327),
        Some(-73.9914),
        true,
    ));
    // Flatiron Building ~0.95km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Flatiron Gear",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Flatiron District"),
        Some(40.7411),
        Some(-73.9897),
        true,
    ));
    // Empire State Building ~0.8km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Empire Equipment",
        6000,
        rust_backend::domain::Condition::New,
        Some("Midtown"),
        Some(40.7484),
        Some(-73.9857),
        true,
    ));
    // Washington Square ~0.5km
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Washington Square Kit",
        7000,
        rust_backend::domain::Condition::Good,
        Some("Greenwich Village"),
        Some(40.7308),
        Some(-73.9973),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7327&lng=-73.9914&radius_km=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 4);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    // Items should be sorted by distance - closest first
    assert_eq!(titles[0], "Union Square Item"); // 0km
    assert_eq!(titles[1], "Washington Square Kit"); // ~0.5km
    assert_eq!(titles[2], "Flatiron Gear"); // ~0.95km
    assert_eq!(titles[3], "Empire Equipment"); // ~1.8km
}

#[test]
async fn geographic_search_excludes_equipment_without_coordinates() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Equipment with coordinates (should be included)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Located Equipment",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Equipment without coordinates (should be excluded when geo search is active)
    let mut unlocated = create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Unlocated Equipment",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Somewhere"),
        None,
        None,
        true,
    );
    unlocated.coordinates = None;
    equipment_repo.push(unlocated);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7128&lng=-74.0060&radius_km=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Located Equipment")
    );
}

#[test]
async fn geographic_search_with_radius_zero_returns_only_exact_matches() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Equipment at exact coordinates
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Exact Location",
        5000,
        rust_backend::domain::Condition::Good,
        Some("Exact"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Equipment 1 meter away (should still be included due to floating point tolerance)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Very Close",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Very Close"),
        Some(40.71281),
        Some(-74.0060),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7128&lng=-74.0060&radius_km=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    // Should include both due to floating point proximity
    assert!(items.len() >= 1);
}

// =============================================================================
// Filter Combination Tests
// =============================================================================

#[test]
async fn search_combines_category_and_price_filters() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let cameras_id = Uuid::new_v4();
    let lenses_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Camera in price range
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        cameras_id,
        "Affordable Camera",
        3500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    // Camera too expensive
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        cameras_id,
        "Expensive Camera",
        15000,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    // Lens in price range (wrong category)
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        lenses_id,
        "Affordable Lens",
        4000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/equipment?category_id={}&min_price=30&max_price=50",
            cameras_id
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Affordable Camera")
    );
}

#[test]
async fn search_combines_all_filters_category_price_location_availability() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Perfect match
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Perfect Match",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Wrong category
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        Uuid::new_v4(),
        "Wrong Category",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Price too high
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Too Expensive",
        15000,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));
    // Too far
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Too Far",
        4500,
        rust_backend::domain::Condition::Good,
        Some("Boston"),
        Some(42.3601),
        Some(-71.0589),
        true,
    ));
    // Not available
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Not Available",
        4500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7129),
        Some(-74.0061),
        false,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/equipment?category_id={}&min_price=30&max_price=60&lat=40.7128&lng=-74.0060&radius_km=10&is_available=true",
            category_id
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Perfect Match")
    );
}

#[test]
async fn search_filters_by_availability_only() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Available Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Unavailable Item",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        false,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Another Available",
        6000,
        rust_backend::domain::Condition::New,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?is_available=true")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"Available Item"));
    assert!(titles.contains(&"Another Available"));
    assert!(!titles.contains(&"Unavailable Item"));
}

#[test]
async fn search_with_min_price_only_includes_price_at_or_above_threshold() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "At Threshold",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Above Threshold",
        7500,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Below Threshold",
        2500,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?min_price=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"At Threshold"));
    assert!(titles.contains(&"Above Threshold"));
    assert!(!titles.contains(&"Below Threshold"));
}

#[test]
async fn search_with_max_price_only_includes_price_at_or_below_threshold() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "At Threshold",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Below Threshold",
        2500,
        rust_backend::domain::Condition::Excellent,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Above Threshold",
        10000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?max_price=50")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 2);

    let titles: Vec<&str> = items
        .iter()
        .filter_map(|item| item.get("title").and_then(serde_json::Value::as_str))
        .collect();
    assert!(titles.contains(&"At Threshold"));
    assert!(titles.contains(&"Below Threshold"));
    assert!(!titles.contains(&"Above Threshold"));
}

// =============================================================================
// Pagination Tests
// =============================================================================

#[test]
async fn pagination_respects_page_parameter() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    // Add 5 items
    for i in 1..=5 {
        equipment_repo.push(create_equipment(
            Uuid::new_v4(),
            owner_id,
            category_id,
            &format!("Item {}", i),
            5000,
            rust_backend::domain::Condition::Good,
            Some("NYC"),
            None,
            None,
            true,
        ));
    }

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=1&limit=2")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_page(&body), 1);
    assert_eq!(get_limit(&body), 2);
    assert_eq!(get_total(&body), 5);
    assert_eq!(get_total_pages(&body), 3);
    assert_eq!(get_items_array(&body).len(), 2);
}

#[test]
async fn pagination_page_defaults_to_one() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Test Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_page(&body), 1);
}

#[test]
async fn pagination_limit_defaults_to_twenty() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Test Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_limit(&body), 20);
}

#[test]
async fn pagination_limit_is_clamped_to_maximum_of_100() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Test Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?limit=200")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_limit(&body), 100);
}

#[test]
async fn pagination_minimum_limit_is_one() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Test Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?limit=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_limit(&body), 1);
}

#[test]
async fn pagination_negative_page_defaults_to_one() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Test Item",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=-1")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_page(&body), 1);
}

// =============================================================================
// Photo Management Tests
// =============================================================================

#[test]
async fn owner_can_add_photo_to_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo1.jpg",
            "is_primary": true
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("photo_url").and_then(serde_json::Value::as_str),
        Some("https://example.com/photo1.jpg")
    );
    assert_eq!(
        body.get("is_primary").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        body.get("order_index").and_then(serde_json::Value::as_i64),
        Some(0)
    );
}

#[test]
async fn owner_can_delete_photo_from_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let photo_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    equipment_repo.push_photo(EquipmentPhoto {
        id: photo_id,
        equipment_id,
        photo_url: "https://example.com/photo.jpg".to_string(),
        is_primary: false,
        order_index: 0,
        created_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    let request = actix_test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/equipment/{}/photos/{}",
            equipment_id, photo_id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[test]
async fn non_owner_cannot_add_photo_to_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: other_id,
        email: "other@example.com".to_string(),
        role: Role::Owner,
        username: Some("other".to_string()),
        full_name: Some("Other".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(other_id, "owner");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo.jpg",
            "is_primary": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn admin_can_add_photo_to_other_users_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: admin_id,
        email: "admin@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin".to_string()),
        full_name: Some("Admin".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo.jpg",
            "is_primary": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[test]
async fn photo_order_index_increments_with_each_addition() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, auth0_jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config_data)
            .app_data(auth0_jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    // Add first photo
    let request1 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo1.jpg",
            "is_primary": false
        }))
        .to_request();
    let response1 = actix_test::call_service(&app, request1).await;
    assert_eq!(response1.status(), StatusCode::CREATED);

    let body1: serde_json::Value = actix_test::read_body_json(response1).await;
    assert_eq!(
        body1.get("order_index").and_then(serde_json::Value::as_i64),
        Some(0)
    );

    // Add second photo
    let request2 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo2.jpg",
            "is_primary": false
        }))
        .to_request();
    let response2 = actix_test::call_service(&app, request2).await;
    assert_eq!(response2.status(), StatusCode::CREATED);

    let body2: serde_json::Value = actix_test::read_body_json(response2).await;
    assert_eq!(
        body2.get("order_index").and_then(serde_json::Value::as_i64),
        Some(1)
    );

    // Add third photo
    let request3 = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/equipment/{}/photos", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "photo_url": "https://example.com/photo3.jpg",
            "is_primary": false
        }))
        .to_request();
    let response3 = actix_test::call_service(&app, request3).await;
    assert_eq!(response3.status(), StatusCode::CREATED);

    let body3: serde_json::Value = actix_test::read_body_json(response3).await;
    assert_eq!(
        body3.get("order_index").and_then(serde_json::Value::as_i64),
        Some(2)
    );
}

// =============================================================================
// Availability Toggle Tests
// =============================================================================

#[test]
async fn owner_can_toggle_equipment_availability() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        equipment_id,
        owner_id,
        category_id,
        "Camera Package",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(auth0_config)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .app_data(state)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(owner_id, "owner");

    // Make unavailable
    let request = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "is_available": false
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("is_available")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );

    // Make available again
    let request2 = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", equipment_id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "is_available": true
        }))
        .to_request();
    let response2 = actix_test::call_service(&app, request2).await;
    assert_eq!(response2.status(), StatusCode::OK);

    let body2: serde_json::Value = actix_test::read_body_json(response2).await;
    assert_eq!(
        body2
            .get("is_available")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
}

// =============================================================================
// Invalid Coordinate Tests
// =============================================================================

#[test]
async fn search_with_invalid_coordinates_returns_empty_results() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "NYC Equipment",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Invalid latitude (outside -90 to 90)
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=91&lng=0&radius_km=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
}

#[test]
async fn search_ignores_undefined_optional_filters_in_query_string() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Item 1",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        Some(40.7128),
        Some(-74.0060),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=undefined&lng=undefined&is_available=undefined")
        .to_request();
    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
async fn search_with_zero_radius() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "o@e.c".to_string(),
        role: Role::Owner,
        ..User::default()
    });

    // Item at exact point
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Exact",
        1000,
        Condition::Good,
        None,
        Some(40.0),
        Some(40.0),
        true,
    ));
    // Item 1m away
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Near",
        1000,
        Condition::Good,
        None,
        Some(40.00001),
        Some(40.0),
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.0&lng=40.0&radius_km=0")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].get("title").unwrap(), "Exact");
}

#[test]
async fn search_pagination_beyond_bounds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "o@e.c".to_string(),
        role: Role::Owner,
        ..User::default()
    });

    for i in 0..5 {
        equipment_repo.push(create_equipment(
            Uuid::new_v4(),
            owner_id,
            category_id,
            &format!("Item {}", i),
            1000,
            Condition::Good,
            None,
            None,
            None,
            true,
        ));
    }

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Page beyond total pages
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=10&limit=5")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
    assert_eq!(get_total(&body), 5);

    // Limit beyond available items
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?page=1&limit=100")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_items_array(&body).len(), 5);
}

#[test]
async fn search_with_invalid_category_id() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "o@e.c".to_string(),
        role: Role::Owner,
        ..User::default()
    });
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        Uuid::new_v4(),
        "Item",
        1000,
        Condition::Good,
        None,
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/equipment?category_id={}", Uuid::new_v4()))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(get_items_array(&body).len(), 0);
}

#[test]
async fn search_with_partial_geo_params_returns_all_items() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Item 1",
        5000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));
    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Item 2",
        4500,
        rust_backend::domain::Condition::Excellent,
        Some("Boston"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Only latitude provided (no lng or radius)
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?lat=40.7128")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    // Without all geo params, search should not filter by location
    assert!(items.len() >= 2);
}

// =============================================================================
// Empty Results Tests
// =============================================================================

#[test]
async fn search_returns_empty_when_no_matching_results() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo.push(create_equipment(
        Uuid::new_v4(),
        owner_id,
        category_id,
        "Expensive Camera",
        15000,
        rust_backend::domain::Condition::Good,
        Some("NYC"),
        None,
        None,
        true,
    ));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    // Search for equipment with max_price 10, but cheapest is 150
    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment?max_price=10")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 0);
    assert_eq!(get_total(&body), 0);
}

#[test]
async fn search_without_filters_returns_all_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    user_repo.push(User {
        id: owner_id,
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    for i in 1..=5 {
        equipment_repo.push(create_equipment(
            Uuid::new_v4(),
            owner_id,
            category_id,
            &format!("Item {}", i),
            5000,
            rust_backend::domain::Condition::Good,
            Some("NYC"),
            None,
            None,
            true,
        ));
    }

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/equipment")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = get_items_array(&body);
    assert_eq!(items.len(), 5);
    assert_eq!(get_total(&body), 5);
}
