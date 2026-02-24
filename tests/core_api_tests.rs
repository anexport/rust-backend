use std::sync::{Arc, Mutex};

use actix_rt::test;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::config::{Auth0Config, AuthConfig};
use rust_backend::domain::{
    AuthIdentity, AuthProvider, Category, Conversation, Equipment, EquipmentPhoto, Message, Role,
    User,
};
use rust_backend::infrastructure::auth0_api::Auth0ApiClient;
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, EquipmentSearchParams,
    MessageRepository, UserRepository,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::security::{cors_middleware, security_headers};
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<Vec<User>>,
}

impl MockUserRepo {
    fn push(&self, user: User) {
        self.users.lock().expect("users mutex poisoned").push(user);
    }
}

#[async_trait]
impl UserRepository for MockUserRepo {
    async fn find_by_id(&self, id: Uuid) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.id == id)
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.email == email)
            .cloned())
    }

    async fn find_by_username(
        &self,
        username: &str,
    ) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> rust_backend::error::AppResult<User> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> rust_backend::error::AppResult<User> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        if let Some(existing) = users.iter_mut().find(|existing| existing.id == user.id) {
            *existing = user.clone();
        }
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .retain(|user| user.id != id);
        Ok(())
    }
}

#[derive(Default)]
struct MockAuthRepo {
    identities: Mutex<Vec<AuthIdentity>>,
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .expect("identities mutex poisoned")
            .iter()
            .find(|identity| {
                identity.user_id == user_id
                    && identity.provider == AuthProvider::Auth0
                    && provider == "auth0"
            })
            .cloned())
    }

    async fn find_identity_by_provider_id(
        &self,
        _provider: &str,
        _provider_id: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn upsert_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
        Ok(identity.clone())
    }
}

#[derive(Default)]
struct MockEquipmentRepo {
    equipment: Mutex<Vec<Equipment>>,
}

#[async_trait]
impl EquipmentRepository for MockEquipmentRepo {
    async fn find_by_id(&self, id: Uuid) -> rust_backend::error::AppResult<Option<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .find(|equipment| equipment.id == id)
            .cloned())
    }

    async fn find_all(
        &self,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone())
    }

    async fn search(
        &self,
        params: &EquipmentSearchParams,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Equipment>> {
        let mut rows: Vec<Equipment> = self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone()
            .into_iter()
            .filter(|item| {
                params
                    .category_id
                    .is_none_or(|category_id| item.category_id == category_id)
            })
            .filter(|item| params.min_price.is_none_or(|min| item.daily_rate >= min))
            .filter(|item| params.max_price.is_none_or(|max| item.daily_rate <= max))
            .filter(|item| {
                params
                    .is_available
                    .is_none_or(|available| item.is_available == available)
            })
            .collect();

        if let Some(((lat, lng), radius_km)) =
            params.latitude.zip(params.longitude).zip(params.radius_km)
        {
            rows.retain(|item| {
                item.coordinates_tuple()
                    .is_some_and(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng) <= radius_km)
            });
            rows.sort_by(|left, right| {
                let left_distance = left
                    .coordinates_tuple()
                    .map(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng))
                    .unwrap_or(f64::MAX);
                let right_distance = right
                    .coordinates_tuple()
                    .map(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng))
                    .unwrap_or(f64::MAX);
                left_distance.total_cmp(&right_distance)
            });
        }

        Ok(rows)
    }

    async fn find_by_owner(
        &self,
        owner_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .filter(|equipment| equipment.owner_id == owner_id)
            .cloned()
            .collect())
    }

    async fn create(&self, equipment: &Equipment) -> rust_backend::error::AppResult<Equipment> {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .push(equipment.clone());
        Ok(equipment.clone())
    }

    async fn update(&self, equipment: &Equipment) -> rust_backend::error::AppResult<Equipment> {
        let mut rows = self.equipment.lock().expect("equipment mutex poisoned");
        if let Some(existing) = rows.iter_mut().find(|existing| existing.id == equipment.id) {
            *existing = equipment.clone();
        }
        Ok(equipment.clone())
    }

    async fn delete(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .retain(|equipment| equipment.id != id);
        Ok(())
    }

    async fn add_photo(
        &self,
        photo: &EquipmentPhoto,
    ) -> rust_backend::error::AppResult<EquipmentPhoto> {
        Ok(photo.clone())
    }

    async fn find_photos(
        &self,
        _equipment_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<EquipmentPhoto>> {
        Ok(Vec::new())
    }

    async fn delete_photo(&self, _photo_id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

#[derive(Default)]
struct MockMessageRepo {
    conversations: Mutex<Vec<Conversation>>,
    messages: Mutex<Vec<Message>>,
    participants: Mutex<Vec<(Uuid, Uuid)>>, // (conversation_id, user_id)
}

impl MockMessageRepo {
    fn add_conversation(&self, conv: Conversation) {
        self.conversations
            .lock()
            .expect("conversations mutex poisoned")
            .push(conv);
    }

    fn add_participant(&self, conversation_id: Uuid, user_id: Uuid) {
        self.participants
            .lock()
            .expect("participants mutex poisoned")
            .push((conversation_id, user_id));
    }

    fn add_message(&self, msg: Message) {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(msg);
    }
}

#[async_trait]
impl MessageRepository for MockMessageRepo {
    async fn find_conversation(
        &self,
        id: Uuid,
    ) -> rust_backend::error::AppResult<Option<Conversation>> {
        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .find(|conv| conv.id == id)
            .cloned())
    }

    async fn find_user_conversations(
        &self,
        user_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Conversation>> {
        let participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        let conversation_ids: Vec<Uuid> = participants
            .iter()
            .filter(|(_, uid)| *uid == user_id)
            .map(|(cid, _)| *cid)
            .collect();
        drop(participants);

        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .filter(|conv| conversation_ids.contains(&conv.id))
            .cloned()
            .collect())
    }

    async fn create_conversation(
        &self,
        participant_ids: Vec<Uuid>,
    ) -> rust_backend::error::AppResult<Conversation> {
        let conversation = Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        for participant_id in participant_ids {
            participants.push((conversation.id, participant_id));
        }

        let mut conversations = self
            .conversations
            .lock()
            .expect("conversations mutex poisoned");
        conversations.push(conversation.clone());

        Ok(conversation)
    }

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Message>> {
        let mut messages: Vec<Message> = self
            .messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .filter(|msg| msg.conversation_id == conversation_id)
            .cloned()
            .collect();

        messages.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at));
        let offset = offset.max(0) as usize;
        let limit = limit.max(0) as usize;

        Ok(messages.into_iter().skip(offset).take(limit).collect())
    }

    async fn create_message(&self, message: &Message) -> rust_backend::error::AppResult<Message> {
        let mut messages = self.messages.lock().expect("messages mutex poisoned");
        messages.push(message.clone());
        Ok(message.clone())
    }

    async fn find_participant_ids(
        &self,
        conversation_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Uuid>> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .filter(|(cid, _)| *cid == conversation_id)
            .map(|(_, uid)| *uid)
            .collect())
    }

    async fn is_participant(
        &self,
        conversation_id: Uuid,
        user_id: Uuid,
    ) -> rust_backend::error::AppResult<bool> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .any(|(cid, uid)| *cid == conversation_id && *uid == user_id))
    }

    async fn mark_as_read(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

#[derive(Default)]
struct MockCategoryRepo;

#[async_trait]
impl CategoryRepository for MockCategoryRepo {
    async fn find_all(&self) -> rust_backend::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }

    async fn find_by_id(&self, _id: Uuid) -> rust_backend::error::AppResult<Option<Category>> {
        Ok(None)
    }

    async fn find_children(
        &self,
        _parent_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }
}

fn haversine_km(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    let earth_radius_km = 6_371.0_f64;
    let dlat = (lat2 - lat1).to_radians();
    let dlng = (lng2 - lng1).to_radians();
    let lat1 = lat1.to_radians();
    let lat2 = lat2.to_radians();

    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    earth_radius_km * c
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "integration-test-secret".to_string(),
        jwt_kid: "v1".to_string(),
        previous_jwt_secrets: Vec::new(),
        previous_jwt_kids: Vec::new(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend-test".to_string(),
        audience: "rust-backend-client".to_string(),
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
    }
}

// Mock Auth0ApiClient for tests
#[derive(Clone)]
struct MockAuth0ApiClient;

#[async_trait]
impl Auth0ApiClient for MockAuth0ApiClient {
    async fn signup(
        &self,
        _email: &str,
        _password: &str,
        _username: Option<&str>,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0SignupResponse>
    {
        Err(rust_backend::error::AppError::ServiceUnavailable {
            service: "auth0".to_string(),
            message: "Auth0 not available in tests".to_string(),
        })
    }

    async fn password_grant(
        &self,
        _email: &str,
        _password: &str,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0TokenResponse>
    {
        Err(rust_backend::error::AppError::ServiceUnavailable {
            service: "auth0".to_string(),
            message: "Auth0 not available in tests".to_string(),
        })
    }
}

// Mock JitUserProvisioningService for tests
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
impl rust_backend::middleware::auth::UserProvisioningService for MockJitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &rust_backend::utils::auth0_claims::Auth0Claims,
    ) -> rust_backend::error::AppResult<rust_backend::utils::auth0_claims::Auth0UserContext> {
        let sub_user_id = claims
            .sub
            .split('|')
            .nth(1)
            .and_then(|raw| Uuid::parse_str(raw).ok());

        let existing_identity_user_id = {
            let identities = self.auth_repo.identities.lock().unwrap();
            identities
                .iter()
                .find(|identity| identity.provider_id.as_deref() == Some(claims.sub.as_str()))
                .map(|identity| identity.user_id)
        };

        let existing_user_id = {
            let users = self.user_repo.users.lock().unwrap();
            existing_identity_user_id
                .or_else(|| {
                    sub_user_id
                        .and_then(|user_id| users.iter().find(|u| u.id == user_id).map(|u| u.id))
                })
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
                "admin" => rust_backend::domain::Role::Admin,
                "owner" => rust_backend::domain::Role::Owner,
                _ => rust_backend::domain::Role::Renter,
            };
            // Create new user if not found
            let user = rust_backend::domain::User {
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

        {
            let mut identities = self.auth_repo.identities.lock().unwrap();
            let has_identity = identities
                .iter()
                .any(|identity| identity.provider_id.as_deref() == Some(claims.sub.as_str()));
            if !has_identity {
                identities.push(rust_backend::domain::AuthIdentity {
                    id: Uuid::new_v4(),
                    user_id,
                    provider: rust_backend::domain::AuthProvider::Auth0,
                    provider_id: Some(claims.sub.clone()),
                    password_hash: None,
                    verified: claims.email_verified.unwrap_or(false),
                    created_at: Utc::now(),
                });
            }
        }

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
    if let Some(role_value) = claims
        .custom_claims
        .get("https://test-tenant.auth0.com/role")
    {
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

// Mock JWKS Client for testing
struct MockJwksClient {
    // Stores the RSA public key in DER format for each key ID
    decoding_keys: Mutex<std::collections::HashMap<String, jsonwebtoken::DecodingKey>>,
}

impl MockJwksClient {
    fn new() -> Self {
        let mut keys = std::collections::HashMap::new();
        // Create a decoding key from the test RSA public key
        // This matches the private key used in create_auth0_token_with_role
        let public_key_pem = include_str!("test_public_key.pem");
        if let Ok(key) = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes()) {
            keys.insert("test-key-id".to_string(), key);
        }
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
            .expect("decoding_keys mutex poisoned")
            .get(kid)
            .cloned()
            .ok_or(rust_backend::error::AppError::Unauthorized)
    }
}

fn auth0_config() -> Auth0Config {
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

// Helper to create a valid Auth0 token with role (RSA signed)
fn create_auth0_token_with_role(
    sub: &str,
    email: Option<String>,
    role: &str,
    exp: i64,
    key_id: &str,
) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-tenant.auth0.com/role".to_string(),
        serde_json::json!(role),
    );
    custom_claims.insert("role".to_string(), serde_json::json!(role));

    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("rust-backend-test".to_string()),
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
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
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

/// Creates app state and all required Auth0 app_data for tests that need authenticated endpoints
fn app_with_auth0_data(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    app_with_auth0_data_and_message_repo(
        user_repo,
        equipment_repo,
        Arc::new(MockMessageRepo::default()),
    )
}

fn app_with_auth0_data_and_message_repo(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
    message_repo: Arc<MockMessageRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo);
    let auth0_api_client = Arc::new(MockAuth0ApiClient);

    let provisioning_service: Arc<dyn UserProvisioningService> = Arc::new(
        MockJitUserProvisioningService::new(user_repo.clone(), auth_repo.clone()),
    );

    let jwks_provider: Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider> =
        Arc::new(MockJwksClient::new());

    let state = AppState {
        auth_service: Arc::new(rust_backend::application::AuthService::new(
            user_repo.clone(),
            auth_repo,
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
            user_repo.clone(),
            message_repo,
        )),
        security: rust_backend::config::SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 5,
            login_lockout_seconds: 300,
            login_backoff_base_ms: 200,
        },
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &rust_backend::config::SecurityConfig {
                cors_allowed_origins: vec!["http://localhost:3000".to_string()],
                metrics_allow_private_only: true,
                metrics_admin_token: None,
                login_max_failures: 5,
                login_lockout_seconds: 300,
                login_backoff_base_ms: 200,
            },
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    };

    (
        web::Data::new(state),
        web::Data::new(auth0_config()),
        web::Data::new(jwks_provider),
        web::Data::new(provisioning_service),
    )
}

fn app_state(user_repo: Arc<MockUserRepo>, equipment_repo: Arc<MockEquipmentRepo>) -> AppState {
    app_state_with_message_repo(
        user_repo,
        equipment_repo,
        Arc::new(MockMessageRepo::default()),
    )
}

fn app_state_with_message_repo(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
    message_repo: Arc<MockMessageRepo>,
) -> AppState {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo);
    let auth0_api_client = Arc::new(MockAuth0ApiClient);
    let auth0_config = rust_backend::config::Auth0Config {
        auth0_domain: Some("test-tenant.auth0.com".to_string()),
        auth0_audience: Some("rust-backend-test".to_string()),
        auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: None,
        auth0_client_secret: None,
        auth0_connection: "Username-Password-Authentication".to_string(),
    };
    let _auth0_jwks_client = rust_backend::utils::auth0_jwks::Auth0JwksClient::new(&auth0_config)
        .expect("failed to create test JWKS client");

    AppState {
        auth_service: Arc::new(rust_backend::application::AuthService::new(
            user_repo.clone(),
            auth_repo,
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
            user_repo.clone(),
            message_repo,
        )),
        security: rust_backend::config::SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 5,
            login_lockout_seconds: 300,
            login_backoff_base_ms: 200,
        },
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &rust_backend::config::SecurityConfig {
                cors_allowed_origins: vec!["http://localhost:3000".to_string()],
                metrics_allow_private_only: true,
                metrics_admin_token: None,
                login_max_failures: 5,
                login_lockout_seconds: 300,
                login_backoff_base_ms: 200,
            },
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    }
}

fn test_db_pool() -> sqlx::PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:1/test_db".to_string());
    PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("test db pool should build lazily")
}

#[test]
async fn metrics_route_is_registered() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
async fn equipment_crud_flow_succeeds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let owner_id = Uuid::new_v4();
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

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let owner_token = create_auth0_token(owner_id, "owner");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/equipment")
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .set_json(serde_json::json!({
            "category_id": Uuid::new_v4(),
            "title": "Cinema Camera",
            "description": "Full frame cinema camera body and accessories",
            "daily_rate": Decimal::new(9900, 2),
            "condition": "excellent",
            "location": "New York",
            "coordinates": {
                "latitude": 40.7128,
                "longitude": -74.0060
            }
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let created: serde_json::Value = actix_test::read_body_json(create_response).await;
    let equipment_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .expect("equipment id should exist")
        .to_string();
    assert_eq!(
        created
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7128)
    );
    assert_eq!(
        created
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0060)
    );

    let get_request = actix_test::TestRequest::get()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .to_request();
    let get_response = actix_test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);
    let fetched: serde_json::Value = actix_test::read_body_json(get_response).await;
    assert_eq!(
        fetched
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7128)
    );
    assert_eq!(
        fetched
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0060)
    );

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .set_json(serde_json::json!({
            "title": "Cinema Camera Updated",
            "description": "Updated description for camera package",
            "coordinates": {
                "latitude": 40.7130,
                "longitude": -74.0070
            }
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
    let updated: serde_json::Value = actix_test::read_body_json(update_response).await;
    assert_eq!(
        updated
            .get("coordinates")
            .and_then(|value| value.get("latitude"))
            .and_then(serde_json::Value::as_f64),
        Some(40.7130)
    );
    assert_eq!(
        updated
            .get("coordinates")
            .and_then(|value| value.get("longitude"))
            .and_then(serde_json::Value::as_f64),
        Some(-74.0070)
    );

    let delete_request = actix_test::TestRequest::delete()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .to_request();
    let delete_response = actix_test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
}

#[test]
async fn users_me_equipment_route_wins_over_dynamic_id_route() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "owner-route@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner-route".to_string()),
        full_name: Some("Owner Route".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: Uuid::new_v4(),
            owner_id: user_id,
            category_id: Uuid::new_v4(),
            title: "Owner item".to_string(),
            description: Some("Owned by /me user".to_string()),
            daily_rate: Decimal::new(1500, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("New York".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: Uuid::new_v4(),
            owner_id: other_user_id,
            category_id: Uuid::new_v4(),
            title: "Other owner item".to_string(),
            description: Some("Owned by another user".to_string()),
            daily_rate: Decimal::new(2200, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("Boston".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "owner");
    let request = actix_test::TestRequest::get()
        .uri("/api/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let items: Vec<serde_json::Value> = actix_test::read_body_json(response).await;
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]
            .get("owner_id")
            .and_then(serde_json::Value::as_str)
            .expect("owner_id should be present"),
        user_id.to_string()
    );
}

#[test]
async fn get_users_id_returns_public_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo);

    let user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "public-user@example.com".to_string(),
        role: Role::Renter,
        username: Some("public-user".to_string()),
        full_name: Some("Public User".to_string()),
        avatar_url: Some("https://example.com/public-user.png".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/users/{user_id}"))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(
        body.get("id")
            .and_then(serde_json::Value::as_str)
            .expect("id should be present"),
        user_id.to_string()
    );
    assert_eq!(
        body.get("username")
            .and_then(serde_json::Value::as_str)
            .expect("username should be present"),
        "public-user"
    );
    assert_eq!(
        body.get("avatar_url")
            .and_then(serde_json::Value::as_str)
            .expect("avatar_url should be present"),
        "https://example.com/public-user.png"
    );
    assert!(
        body.get("email").is_none(),
        "public profile response should not expose email"
    );
}

#[test]
async fn equipment_list_filters_by_price_category_and_radius() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo.clone());

    let category_id = Uuid::new_v4();
    let other_category_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    let now = Utc::now();
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .extend([
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Nearby good price".to_string(),
                description: Some("match".to_string()),
                daily_rate: Decimal::new(3000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7128, -74.0060".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Too expensive".to_string(),
                description: Some("price fail".to_string()),
                daily_rate: Decimal::new(12000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7130, -74.0070".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id: other_category_id,
                title: "Wrong category".to_string(),
                description: Some("category fail".to_string()),
                daily_rate: Decimal::new(3000, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("NYC".to_string()),
                coordinates: Some("40.7127, -74.0058".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
            Equipment {
                id: Uuid::new_v4(),
                owner_id,
                category_id,
                title: "Too far".to_string(),
                description: Some("distance fail".to_string()),
                daily_rate: Decimal::new(2500, 2),
                condition: rust_backend::domain::Condition::Good,
                location: Some("Boston".to_string()),
                coordinates: Some("42.3601, -71.0589".to_string()),
                is_available: true,
                created_at: now,
                updated_at: now,
            },
        ]);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/equipment?category_id={category_id}&min_price=20&max_price=40&lat=40.7128&lng=-74.0060&radius_km=5"
        ))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let items = body
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("items should be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("title").and_then(serde_json::Value::as_str),
        Some("Nearby good price")
    );
}

#[test]
async fn metrics_route_requires_private_network_or_admin_auth() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn security_headers_are_present() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/health").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-content-type-options"));
    assert!(response.headers().contains_key("x-frame-options"));
    assert!(response.headers().contains_key("referrer-policy"));
}

#[test]
async fn cors_preflight_respects_allowlist() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let allowed_preflight = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/api/auth/auth0/login")
        .insert_header(("Origin", "http://localhost:3000"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();
    let allowed_response = actix_test::call_service(&app, allowed_preflight).await;
    assert_eq!(allowed_response.status(), StatusCode::OK);
    assert_eq!(
        allowed_response
            .headers()
            .get("access-control-allow-origin")
            .expect("allow origin header missing"),
        "http://localhost:3000"
    );

    let denied_preflight = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/api/auth/auth0/login")
        .insert_header(("Origin", "http://evil.example"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();
    let denied_response = actix_test::call_service(&app, denied_preflight).await;
    assert_eq!(denied_response.status(), StatusCode::BAD_REQUEST);
}

#[test]
async fn auth_me_rejects_when_authorization_header_missing() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/auth/me")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn metrics_allows_admin_token_from_non_private_request() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let mut state = app_state(user_repo, equipment_repo);
    state.security.metrics_allow_private_only = true;
    state.security.metrics_admin_token = Some("ops-secret".to_string());

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/metrics")
        .insert_header(("x-admin-token", "ops-secret"))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
async fn renter_cannot_create_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let renter_id = Uuid::new_v4();
    user_repo.push(User {
        id: renter_id,
        email: "renter-create@example.com".to_string(),
        role: Role::Renter,
        username: Some("renter-create".to_string()),
        full_name: Some("Renter Create".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(renter_id, "renter");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/equipment")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "category_id": Uuid::new_v4(),
            "title": "Should Not Work",
            "description": "Renter cannot create equipment listing",
            "daily_rate": Decimal::new(4900, 2),
            "condition": "good",
            "location": "Austin"
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn non_owner_cannot_update_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let equipment_id = Uuid::new_v4();

    user_repo.push(User {
        id: owner_id,
        email: "owner-update@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner-update".to_string()),
        full_name: Some("Owner Update".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: other_user_id,
        email: "other-update@example.com".to_string(),
        role: Role::Owner,
        username: Some("other-update".to_string()),
        full_name: Some("Other Update".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: equipment_id,
            owner_id,
            category_id: Uuid::new_v4(),
            title: "Owner Only Item".to_string(),
            description: Some("Cannot be updated by another owner".to_string()),
            daily_rate: Decimal::new(5000, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("Denver".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_user_id, "owner");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "title": "Illegally Updated"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn admin_can_update_other_users_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let admin_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
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
    user_repo.push(User {
        id: target_id,
        email: "target@example.com".to_string(),
        role: Role::Renter,
        username: Some("target".to_string()),
        full_name: Some("Target".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/users/{target_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "full_name": "Updated By Admin"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
}

#[test]
async fn admin_can_update_foreign_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo.clone());

    let admin_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    user_repo.push(User {
        id: admin_id,
        email: "admin2@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin2".to_string()),
        full_name: Some("Admin 2".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: owner_id,
        email: "owner2@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner2".to_string()),
        full_name: Some("Owner 2".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let equipment_id = Uuid::new_v4();
    equipment_repo
        .equipment
        .lock()
        .expect("equipment mutex poisoned")
        .push(Equipment {
            id: equipment_id,
            owner_id,
            category_id: Uuid::new_v4(),
            title: "Owned Item".to_string(),
            description: Some("Owned".to_string()),
            daily_rate: Decimal::new(1000, 2),
            condition: rust_backend::domain::Condition::Good,
            location: Some("NY".to_string()),
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "title": "Admin Updated"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);
}

#[test]
async fn non_admin_cannot_update_other_users_profile() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data(user_repo.clone(), equipment_repo);

    let actor_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    user_repo.push(User {
        id: actor_id,
        email: "actor@example.com".to_string(),
        role: Role::Renter,
        username: Some("actor".to_string()),
        full_name: Some("Actor".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    user_repo.push(User {
        id: target_id,
        email: "target2@example.com".to_string(),
        role: Role::Renter,
        username: Some("target2".to_string()),
        full_name: Some("Target2".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(actor_id, "renter");

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/users/{target_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "full_name": "Should Fail"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn ws_upgrade_requires_authorization() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/ws")
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn ws_upgrade_requires_wss_in_production() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let mut state = app_state(user_repo, equipment_repo);
    state.app_environment = "production".to_string();

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/ws")
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
async fn ready_endpoint_checks_dependencies() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/ready").to_request();
    let response = actix_test::call_service(&app, request).await;
    let has_test_db_url =
        std::env::var("TEST_DATABASE_URL").is_ok() || std::env::var("DATABASE_URL").is_ok();
    if has_test_db_url {
        assert_eq!(response.status(), StatusCode::OK);
    } else {
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

// Message routes tests

#[test]
async fn create_conversation_succeeds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "creator@example.com".to_string(),
        role: Role::Renter,
        username: Some("creator".to_string()),
        full_name: Some("Creator".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "participant_ids": [other_id]
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let body: serde_json::Value = actix_test::read_body_json(create_response).await;
    assert!(body.get("id").is_some());
}

#[test]
async fn create_conversation_validates_min_participants() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "validator@example.com".to_string(),
        role: Role::Renter,
        username: Some("validator".to_string()),
        full_name: Some("Validator".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let token = create_auth0_token(user_id, "renter");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "participant_ids": []
        }))
        .to_request();
    let create_response = actix_test::call_service(&app, create_request).await;
    assert_eq!(create_response.status(), StatusCode::BAD_REQUEST);
}

#[test]
async fn list_conversations_returns_empty_for_new_user() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "listuser@example.com".to_string(),
        role: Role::Renter,
        username: Some("listuser".to_string()),
        full_name: Some("List User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let conversations = body.as_array().expect("conversations should be an array");
    assert_eq!(conversations.len(), 0);
}

#[test]
async fn get_conversation_fails_for_non_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "nonparticipant@example.com".to_string(),
        role: Role::Renter,
        username: Some("nonparticipant".to_string()),
        full_name: Some("Non Participant".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn get_conversation_succeeds_for_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "participant@example.com".to_string(),
        role: Role::Renter,
        username: Some("participant".to_string()),
        full_name: Some("Participant".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
async fn send_message_fails_for_non_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "nonparticipant-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("nonparticipant-msg".to_string()),
        full_name: Some("Non Participant Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn send_message_succeeds_for_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "participant-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("participant-msg".to_string()),
        full_name: Some("Participant Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    eprintln!(
        "DEBUG: user_id={}, conversation_id={}",
        user_id, conversation_id
    );
    let is_participant = message_repo.is_participant(conversation_id, user_id).await;
    eprintln!("DEBUG: is_participant={:?}", is_participant);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    eprintln!("DEBUG: response status={:?}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[test]
async fn send_message_validates_content_length() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "validator-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("validator-msg".to_string()),
        full_name: Some("Validator Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let short_request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": ""
        }))
        .to_request();
    let short_response = actix_test::call_service(&app, short_request).await;
    assert_eq!(short_response.status(), StatusCode::BAD_REQUEST);

    let long_content = "x".repeat(5001);
    let long_request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": long_content
        }))
        .to_request();
    let long_response = actix_test::call_service(&app, long_request).await;
    assert_eq!(long_response.status(), StatusCode::BAD_REQUEST);
}

#[test]
async fn list_messages_respects_pagination() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "paginator@example.com".to_string(),
        role: Role::Renter,
        username: Some("paginator".to_string()),
        full_name: Some("Paginator".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let now = Utc::now();
    for i in 0..10 {
        message_repo.add_message(Message {
            id: Uuid::new_v4(),
            conversation_id,
            sender_id: user_id,
            content: format!("Message {}", i),
            created_at: now + Duration::seconds(i),
        });
    }

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/conversations/{conversation_id}/messages?limit=5&offset=0"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let messages = body.as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 5);
}

#[test]
async fn list_messages_fails_for_non_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "nonparticipant-list@example.com".to_string(),
        role: Role::Renter,
        username: Some("nonparticipant-list".to_string()),
        full_name: Some("Non Participant List".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
async fn conversation_requires_authentication() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let state = app_state_with_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let conversation_id = Uuid::new_v4();

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}"))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn list_conversations_requires_authentication() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let state = app_state_with_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/conversations")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn create_conversation_requires_authentication() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let state = app_state_with_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/conversations")
        .set_json(serde_json::json!({
            "participant_ids": [Uuid::new_v4()]
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn send_message_requires_authentication() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let state = app_state_with_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let conversation_id = Uuid::new_v4();

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn admin_can_access_foreign_conversation() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

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

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
async fn admin_can_send_message_to_foreign_conversation() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: admin_id,
        email: "admin-msg@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin-msg".to_string()),
        full_name: Some("Admin Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Admin message"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[test]
async fn admin_can_list_foreign_conversation_messages() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: admin_id,
        email: "admin-list@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin-list".to_string()),
        full_name: Some("Admin List".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(admin_id, "admin");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}
