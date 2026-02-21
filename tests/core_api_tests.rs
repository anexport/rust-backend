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
    AuthRepository, CategoryRepository, EquipmentRepository, EquipmentSearchParams,
    MessageRepository, UserRepository,
};
use rust_backend::observability::AppMetrics;
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
    sessions: Mutex<Vec<UserSession>>,
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
        self.sessions
            .lock()
            .expect("sessions mutex poisoned")
            .push(session.clone());
        Ok(session.clone())
    }

    async fn find_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> rust_backend::error::AppResult<Option<UserSession>> {
        Ok(self
            .sessions
            .lock()
            .expect("sessions mutex poisoned")
            .iter()
            .find(|session| session.refresh_token_hash == token_hash)
            .cloned())
    }

    async fn revoke_session(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(session) = sessions.iter_mut().find(|session| session.id == _id) {
            session.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn revoke_all_sessions(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        for session in sessions
            .iter_mut()
            .filter(|session| session.user_id == _user_id)
        {
            session.revoked_at = Some(Utc::now());
        }
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
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(session) = sessions.iter_mut().find(|session| session.id == _id) {
            session.last_seen_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn has_active_session(&self, user_id: Uuid) -> rust_backend::error::AppResult<bool> {
        Ok(self
            .sessions
            .lock()
            .expect("sessions mutex poisoned")
            .iter()
            .any(|session| {
                session.user_id == user_id
                    && session.revoked_at.is_none()
                    && session.expires_at > Utc::now()
            }))
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
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security_config(),
        login_throttle: Arc::new(LoginThrottle::new(&security_config())),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: None,
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
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
async fn auth_register_login_and_me_flow_succeeds() {
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
    let _register_body: serde_json::Value = actix_test::read_body_json(register_response).await;

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "integration@example.com",
            "password": "super-secure-password"
        }))
        .to_request();
    let login_response = actix_test::call_service(&app, login_request).await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let login_body: serde_json::Value = actix_test::read_body_json(login_response).await;
    let access_token = login_body
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .expect("access token should exist")
        .to_string();

    let me_request = actix_test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .to_request();
    let me_response = actix_test::call_service(&app, me_request).await;
    assert_eq!(me_response.status(), StatusCode::OK);
}

#[test]
async fn auth_register_validation_error_has_specific_field_feedback() {
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

    let request = actix_test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(serde_json::json!({
            "email": "validation@example.com",
            "password": "short",
            "username": "valid-user"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    assert_eq!(body["code"], "VALIDATION_ERROR");
    assert_eq!(body["message"], "Password must be at least 12 characters");
    assert_eq!(body["details"][0]["field"], "password");
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
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let owner_token =
        rust_backend::utils::jwt::create_access_token(owner_id, "owner", &auth_config())
            .expect("owner token should be created");

    let create_request = actix_test::TestRequest::post()
        .uri("/api/equipment")
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
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
        .insert_header(("Authorization", format!("Bearer {owner_token}")))
        .set_json(serde_json::json!({
            "title": "Cinema Camera Updated",
            "description": "Updated description for camera package"
        }))
        .to_request();
    let update_response = actix_test::call_service(&app, update_request).await;
    assert_eq!(update_response.status(), StatusCode::OK);

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
    let state = app_state(user_repo.clone(), equipment_repo.clone());

    let user_id = Uuid::new_v4();
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

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let token = rust_backend::utils::jwt::create_access_token(user_id, "owner", &auth_config())
        .expect("owner token should be created");
    let request = actix_test::TestRequest::get()
        .uri("/api/users/me/equipment")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
async fn auth_scope_has_ip_rate_limit() {
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

    let mut saw_rate_limit = false;
    for _ in 0..40 {
        let request = actix_test::TestRequest::post()
            .uri("/api/auth/oauth/google")
            .set_json(serde_json::json!({
                "code": "fake-code",
                "state": "test-state"
            }))
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            saw_rate_limit = true;
            break;
        }
    }

    assert!(saw_rate_limit, "expected governor to return 429 eventually");
}

#[test]
async fn oauth_callback_requires_state() {
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

    let request = actix_test::TestRequest::post()
        .uri("/api/auth/oauth/google")
        .set_json(serde_json::json!({
            "code": "fake-code"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

#[test]
async fn refresh_rejects_when_csrf_header_does_not_match_cookie() {
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
            "email": "csrf-mismatch@example.com",
            "password": "super-secure-password",
            "username": "csrf-mismatch",
            "full_name": "Csrf Mismatch"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "csrf-mismatch@example.com",
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

    let refresh_request = actix_test::TestRequest::post()
        .uri("/api/auth/refresh")
        .insert_header(("Cookie", format!("{refresh_cookie}; {csrf_cookie}")))
        .insert_header(("x-csrf-token", "definitely-not-matching"))
        .set_json(serde_json::json!({}))
        .to_request();
    let refresh_response = actix_test::call_service(&app, refresh_request).await;
    assert_eq!(refresh_response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
async fn refresh_succeeds_with_matching_csrf_cookie_and_header() {
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
            "email": "csrf-valid@example.com",
            "password": "super-secure-password",
            "username": "csrf-valid",
            "full_name": "Csrf Valid"
        }))
        .to_request();
    let register_response = actix_test::call_service(&app, register_request).await;
    assert_eq!(register_response.status(), StatusCode::CREATED);

    let login_request = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "csrf-valid@example.com",
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

    let csrf_cookie_name_value = set_cookie_values
        .iter()
        .find(|cookie| cookie.starts_with("csrf_token="))
        .and_then(|cookie| cookie.split(';').next())
        .expect("csrf cookie should be set")
        .to_string();
    let csrf_value = csrf_cookie_name_value
        .split_once('=')
        .map(|(_, value)| value.to_string())
        .expect("csrf cookie should contain value");

    let refresh_request = actix_test::TestRequest::post()
        .uri("/api/auth/refresh")
        .insert_header((
            "Cookie",
            format!("{refresh_cookie}; {csrf_cookie_name_value}"),
        ))
        .insert_header(("x-csrf-token", csrf_value))
        .set_json(serde_json::json!({}))
        .to_request();
    let refresh_response = actix_test::call_service(&app, refresh_request).await;
    assert_eq!(refresh_response.status(), StatusCode::OK);
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
    let state = app_state(user_repo.clone(), equipment_repo);

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;
    let token = rust_backend::utils::jwt::create_access_token(renter_id, "renter", &auth_config())
        .expect("token should be created");

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
    let state = app_state(user_repo.clone(), equipment_repo.clone());

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;
    let token =
        rust_backend::utils::jwt::create_access_token(other_user_id, "owner", &auth_config())
            .expect("token should be created");

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
    let state = app_state(user_repo.clone(), equipment_repo);

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let token = rust_backend::utils::jwt::create_access_token(admin_id, "admin", &auth_config())
        .expect("admin token should be created");

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
    let state = app_state(user_repo.clone(), equipment_repo.clone());

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let token = rust_backend::utils::jwt::create_access_token(admin_id, "admin", &auth_config())
        .expect("admin token should be created");

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
    let state = app_state(user_repo.clone(), equipment_repo);

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
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let token = rust_backend::utils::jwt::create_access_token(actor_id, "renter", &auth_config())
        .expect("actor token should be created");

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
async fn ws_upgrade_rejects_when_user_has_no_active_session() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo.clone(), equipment_repo);

    let user_id = Uuid::new_v4();
    user_repo.push(User {
        id: user_id,
        email: "ws-user@example.com".to_string(),
        role: Role::Renter,
        username: Some("ws-user".to_string()),
        full_name: Some("Ws User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let token = rust_backend::utils::jwt::create_access_token(user_id, "renter", &auth_config())
        .expect("token should be created");

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
        .insert_header(("Authorization", format!("Bearer {token}")))
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
async fn metrics_endpoint_exposes_auth_failure_counter() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let mut state = app_state(user_repo, equipment_repo);
    state.security.metrics_allow_private_only = false;

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let failed_login = actix_test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(serde_json::json!({
            "email": "missing@example.com",
            "password": "wrong"
        }))
        .to_request();
    let failed_login_response = actix_test::call_service(&app, failed_login).await;
    assert_eq!(failed_login_response.status(), StatusCode::UNAUTHORIZED);

    let metrics_request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let metrics_response = actix_test::call_service(&app, metrics_request).await;
    assert_eq!(metrics_response.status(), StatusCode::OK);
    let metrics_body = actix_test::read_body(metrics_response).await;
    let text = String::from_utf8(metrics_body.to_vec()).expect("metrics should be utf8");
    assert!(text.contains("auth_failures_total"));
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
    assert_eq!(response.status(), StatusCode::OK);
}
