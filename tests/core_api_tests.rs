use std::sync::{Arc, Mutex};

use actix_rt::test;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::Utc;
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::AuthConfig;
use rust_backend::domain::{
    AuthIdentity, AuthProvider, Category, Conversation, Equipment, EquipmentPhoto, Message, Role,
    User, UserSession,
};
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, MessageRepository, UserRepository,
};
use rust_backend::security::LoginThrottle;
use rust_backend::security::{cors_middleware, security_headers};
use rust_decimal::Decimal;
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
                    && identity.provider == AuthProvider::Email
                    && provider == "email"
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

    async fn verify_email(&self, user_id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut identities = self.identities.lock().expect("identities mutex poisoned");
        for identity in identities.iter_mut() {
            if identity.user_id == user_id {
                identity.verified = true;
            }
        }
        Ok(())
    }

    async fn create_session(
        &self,
        session: &UserSession,
    ) -> rust_backend::error::AppResult<UserSession> {
        Ok(session.clone())
    }

    async fn find_session_by_token_hash(
        &self,
        _token_hash: &str,
    ) -> rust_backend::error::AppResult<Option<UserSession>> {
        Ok(None)
    }

    async fn revoke_session(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_all_sessions(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_session_with_replacement(
        &self,
        _id: Uuid,
        _replaced_by: Option<Uuid>,
        _reason: Option<&str>,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_family(
        &self,
        _family_id: Uuid,
        _reason: &str,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn touch_session(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
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
struct MockMessageRepo;

#[async_trait]
impl MessageRepository for MockMessageRepo {
    async fn find_conversation(
        &self,
        _id: Uuid,
    ) -> rust_backend::error::AppResult<Option<Conversation>> {
        Ok(None)
    }

    async fn find_user_conversations(
        &self,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Conversation>> {
        Ok(Vec::new())
    }

    async fn create_conversation(
        &self,
        _participant_ids: Vec<Uuid>,
    ) -> rust_backend::error::AppResult<Conversation> {
        Ok(Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    async fn find_messages(
        &self,
        _conversation_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Message>> {
        Ok(Vec::new())
    }

    async fn create_message(&self, message: &Message) -> rust_backend::error::AppResult<Message> {
        Ok(message.clone())
    }

    async fn is_participant(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<bool> {
        Ok(true)
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

fn app_state(user_repo: Arc<MockUserRepo>, equipment_repo: Arc<MockEquipmentRepo>) -> AppState {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo);
    let message_repo = Arc::new(MockMessageRepo);

    AppState {
        auth_service: Arc::new(AuthService::new(
            user_repo.clone(),
            auth_repo,
            auth_config(),
        )),
        user_service: Arc::new(UserService::new(user_repo, equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(equipment_repo)),
        message_service: Arc::new(MessageService::new(message_repo)),
        security: security_config(),
        login_throttle: Arc::new(LoginThrottle::new(&security_config())),
    }
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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
async fn auth_register_login_and_me_flow_succeeds() {
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

    let register_request = actix_test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(serde_json::json!({
            "email": "integration@example.com",
            "password": "super-secure-password",
            "username": "integration-user",
            "full_name": "Integration User"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);
    let register_body: serde_json::Value = actix_test::read_body_json(register_response).await;
    let user_id = register_body
        .get("user")
        .and_then(|user| user.get("id"))
        .and_then(serde_json::Value::as_str)
        .expect("user id should exist")
        .to_string();

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "integration@example.com",
            "password": "super-secure-password"
        }))
        .to_request();
    let login_response = actix_test::call_service(&app, login_request).await;
    assert_eq!(login_response.status(), StatusCode::OK);

    let me_request = actix_test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("x-user-id", user_id))
        .to_request();
    let me_response = actix_test::call_service(&app, me_request).await;
    assert_eq!(me_response.status(), StatusCode::OK);
}

#[test]
async fn equipment_crud_flow_succeeds() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo);

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let create_request = actix_test::TestRequest::post()
        .uri("/api/equipment")
        .insert_header(("x-user-id", owner_id.to_string()))
        .set_json(serde_json::json!({
            "category_id": Uuid::new_v4(),
            "title": "Cinema Camera",
            "description": "Full frame cinema camera body and accessories",
            "daily_rate": Decimal::new(9900, 2),
            "condition": "excellent",
            "location": "New York"
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

    let get_request = actix_test::TestRequest::get()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .to_request();
    let get_response = actix_test::call_service(&app, get_request).await;
    assert_eq!(get_response.status(), StatusCode::OK);

    let update_request = actix_test::TestRequest::put()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("x-user-id", owner_id.to_string()))
        .set_json(serde_json::json!({
            "title": "Cinema Camera Updated",
            "description": "Updated description for camera package"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);

    let delete_request = actix_test::TestRequest::delete()
        .uri(&format!("/api/equipment/{equipment_id}"))
        .insert_header(("x-user-id", owner_id.to_string()))
        .to_request();
    let delete_response = actix_test::call_service(&app, delete_request).await;
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);
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
        .uri("/api/auth/login")
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
        .uri("/api/auth/login")
        .insert_header(("Origin", "http://evil.example"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();
    let denied_response = actix_test::call_service(&app, denied_preflight).await;
    assert_eq!(denied_response.status(), StatusCode::BAD_REQUEST);
}

#[test]
async fn login_sets_secure_refresh_and_csrf_cookies() {
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

    let register_request = actix_test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(serde_json::json!({
            "email": "cookie-user@example.com",
            "password": "super-secure-password",
            "username": "cookie-user",
            "full_name": "Cookie User"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "cookie-user@example.com",
            "password": "super-secure-password"
        }))
        .to_request();
    let login_response = actix_test::call_service(&app, login_request).await;
    assert_eq!(login_response.status(), StatusCode::OK);

    let set_cookie_values: Vec<String> = login_response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().expect("set-cookie should be valid utf8"))
        .map(ToString::to_string)
        .collect();

    assert!(set_cookie_values
        .iter()
        .any(|cookie| cookie.contains("refresh_token=")
            && cookie.contains("HttpOnly")
            && cookie.contains("Secure")
            && cookie.contains("SameSite=Lax")));
    assert!(set_cookie_values
        .iter()
        .any(|cookie| cookie.contains("csrf_token=")
            && cookie.contains("Secure")
            && cookie.contains("SameSite=Lax")));
}

#[test]
async fn refresh_requires_csrf_token_for_cookie_auth() {
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

    let register_request = actix_test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(serde_json::json!({
            "email": "csrf-user@example.com",
            "password": "super-secure-password",
            "username": "csrf-user",
            "full_name": "Csrf User"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "csrf-user@example.com",
            "password": "super-secure-password"
        }))
        .to_request();
    let login_response = actix_test::call_service(&app, login_request).await;
    assert_eq!(login_response.status(), StatusCode::OK);

    let set_cookie_values: Vec<String> = login_response
        .headers()
        .get_all("set-cookie")
        .map(|value| value.to_str().expect("set-cookie should be valid utf8"))
        .map(ToString::to_string)
        .collect();

    let refresh_cookie = set_cookie_values
        .iter()
        .find(|cookie| cookie.starts_with("refresh_token="))
        .and_then(|cookie| cookie.split(';').next())
        .expect("refresh cookie should be set")
        .to_string();

    let csrf_cookie = set_cookie_values
        .iter()
        .find(|cookie| cookie.starts_with("csrf_token="))
        .and_then(|cookie| cookie.split(';').next())
        .expect("csrf cookie should be set")
        .to_string();

    let missing_csrf_header = actix_test::TestRequest::post()
        .uri("/api/auth/refresh")
        .insert_header(("Cookie", format!("{refresh_cookie}; {csrf_cookie}")))
        .set_json(serde_json::json!({}))
        .to_request();
    let missing_csrf_response = actix_test::call_service(&app, missing_csrf_header).await;
    assert_eq!(missing_csrf_response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn login_backoff_and_lockout_returns_too_many_requests() {
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

    let register_request = actix_test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(serde_json::json!({
            "email": "lockout-user@example.com",
            "password": "super-secure-password",
            "username": "lockout-user",
            "full_name": "Lockout User"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let mut seen_rate_limited = false;
    for _ in 0..6 {
        let login_request = actix_test::TestRequest::post()
            .uri("/api/auth/login")
            .set_json(serde_json::json!({
                "email": "lockout-user@example.com",
                "password": "wrong-password"
            }))
            .to_request();
        let login_response = actix_test::call_service(&app, login_request).await;
        if login_response.status() == StatusCode::TOO_MANY_REQUESTS {
            seen_rate_limited = true;
            break;
        }
    }

    assert!(seen_rate_limited);
}
