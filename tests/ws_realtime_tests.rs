use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, App, HttpServer};
use async_trait::async_trait;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use rust_backend::api::routes::{ws, AppState};
use rust_backend::application::{
    AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::{AuthConfig, SecurityConfig};
use rust_backend::domain::{
    AuthIdentity, Category, Conversation, Equipment, EquipmentPhoto, Message, User, UserSession,
};
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, MessageRepository, UserRepository,
};
use rust_backend::observability::AppMetrics;
use rust_backend::security::LoginThrottle;
use rust_backend::utils::jwt::create_access_token;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsClientMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

struct NoopUserRepo;

#[async_trait]
impl UserRepository for NoopUserRepo {
    async fn find_by_id(&self, _id: Uuid) -> rust_backend::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn find_by_email(&self, _email: &str) -> rust_backend::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn find_by_username(
        &self,
        _username: &str,
    ) -> rust_backend::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn create(&self, user: &User) -> rust_backend::error::AppResult<User> {
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> rust_backend::error::AppResult<User> {
        Ok(user.clone())
    }

    async fn delete(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

struct StubAuthRepo {
    has_active_session: bool,
}

#[async_trait]
impl AuthRepository for StubAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        _user_id: Uuid,
        _provider: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn find_identity_by_provider_id(
        &self,
        _provider: &str,
        _provider_id: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn verify_email(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
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

    async fn revoke_session_with_replacement(
        &self,
        _id: Uuid,
        _replaced_by: Option<Uuid>,
        _reason: Option<&str>,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_all_sessions(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
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

    async fn has_active_session(&self, _user_id: Uuid) -> rust_backend::error::AppResult<bool> {
        Ok(self.has_active_session)
    }
}

struct NoopCategoryRepo;

#[async_trait]
impl CategoryRepository for NoopCategoryRepo {
    async fn find_all(&self) -> rust_backend::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }

    async fn find_by_id(&self, _id: Uuid) -> rust_backend::error::AppResult<Option<Category>> {
        Ok(None)
    }

    async fn find_children(&self, _parent_id: Uuid) -> rust_backend::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }
}

struct NoopEquipmentRepo;

#[async_trait]
impl EquipmentRepository for NoopEquipmentRepo {
    async fn find_by_id(&self, _id: Uuid) -> rust_backend::error::AppResult<Option<Equipment>> {
        Ok(None)
    }

    async fn find_all(
        &self,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Equipment>> {
        Ok(Vec::new())
    }

    async fn find_by_owner(
        &self,
        _owner_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Equipment>> {
        Ok(Vec::new())
    }

    async fn create(&self, equipment: &Equipment) -> rust_backend::error::AppResult<Equipment> {
        Ok(equipment.clone())
    }

    async fn update(&self, equipment: &Equipment) -> rust_backend::error::AppResult<Equipment> {
        Ok(equipment.clone())
    }

    async fn delete(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
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

struct NoopMessageRepo;

#[async_trait]
impl MessageRepository for NoopMessageRepo {
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
        Ok(false)
    }

    async fn mark_as_read(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "ws-test-secret".to_string(),
        jwt_kid: "ws-v1".to_string(),
        previous_jwt_secrets: Vec::new(),
        previous_jwt_kids: Vec::new(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend-test".to_string(),
        audience: "rust-backend-client".to_string(),
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
    }
}

fn build_state(has_active_session: bool) -> AppState {
    let user_repo: Arc<dyn UserRepository> = Arc::new(NoopUserRepo);
    let auth_repo: Arc<dyn AuthRepository> = Arc::new(StubAuthRepo { has_active_session });
    let category_repo: Arc<dyn CategoryRepository> = Arc::new(NoopCategoryRepo);
    let equipment_repo: Arc<dyn EquipmentRepository> = Arc::new(NoopEquipmentRepo);
    let message_repo: Arc<dyn MessageRepository> = Arc::new(NoopMessageRepo);
    let security = security_config();

    AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo, auth_config())),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo, message_repo)),
        security: security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&security)),
        app_environment: "development".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: None,
    }
}

async fn spawn_ws_server(has_active_session: bool) -> (String, actix_web::dev::ServerHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr");
    let state = build_state(has_active_session);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .configure(ws::configure)
    })
    .listen(listener)
    .expect("listen test server")
    .run();

    let handle = server.handle();
    actix_web::rt::spawn(server);

    (format!("ws://{addr}/ws"), handle)
}

async fn recv_next_text(
    socket: &mut WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
) -> String {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("message should arrive")
            .expect("stream item should exist")
            .expect("socket message should be ok");

        match message {
            WsClientMessage::Text(text) => return text.to_string(),
            WsClientMessage::Ping(payload) => {
                socket
                    .send(WsClientMessage::Pong(payload))
                    .await
                    .expect("pong should send");
            }
            WsClientMessage::Pong(_) => {}
            WsClientMessage::Close(frame) => {
                panic!("unexpected close frame: {frame:?}");
            }
            _ => {}
        }
    }
}

#[actix_rt::test]
async fn websocket_ping_message_round_trip() {
    let (url, handle) = spawn_ws_server(true).await;
    let token = create_access_token(Uuid::new_v4(), "owner", &auth_config())
        .expect("token should be created");

    let mut request = url
        .into_client_request()
        .expect("request should be built from url");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header should be valid"),
    );

    let (mut socket, _) = connect_async(request)
        .await
        .expect("websocket connection should succeed");

    socket
        .send(WsClientMessage::Text(r#"{"type":"ping"}"#.into()))
        .await
        .expect("ping message should send");

    let text = recv_next_text(&mut socket).await;
    assert!(text.contains("\"type\":\"pong\""));

    let _ = socket.close(None).await;
    handle.stop(true).await;
}

#[actix_rt::test]
async fn malformed_ws_message_returns_error_and_connection_stays_open() {
    let (url, handle) = spawn_ws_server(true).await;
    let token = create_access_token(Uuid::new_v4(), "owner", &auth_config())
        .expect("token should be created");

    let mut request = url
        .into_client_request()
        .expect("request should be built from url");
    request.headers_mut().insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header should be valid"),
    );

    let (mut socket, _) = connect_async(request)
        .await
        .expect("websocket connection should succeed");

    socket
        .send(WsClientMessage::Text("{not-json".into()))
        .await
        .expect("malformed message should send");

    let first_text = recv_next_text(&mut socket).await;
    assert!(first_text.contains("\"type\":\"error\""));
    assert!(first_text.contains("BAD_MESSAGE"));

    socket
        .send(WsClientMessage::Text(r#"{"type":"ping"}"#.into()))
        .await
        .expect("second ping should send");

    let second_text = recv_next_text(&mut socket).await;
    assert!(second_text.contains("\"type\":\"pong\""));

    let _ = socket.close(None).await;
    handle.stop(true).await;
}
