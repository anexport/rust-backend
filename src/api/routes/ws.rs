use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use chrono::Utc;
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::api::dtos::SendMessageRequest;
use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/ws", web::get().to(ws_upgrade));
}

#[derive(Clone, Default)]
pub struct WsConnectionHub {
    sessions: Arc<RwLock<HashMap<Uuid, Vec<mpsc::UnboundedSender<String>>>>>,
}

impl WsConnectionHub {
    pub fn register(&self, user_id: Uuid) -> mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        if let Ok(mut sessions) = self.sessions.write() {
            sessions.entry(user_id).or_default().push(tx);
        }
        rx
    }

    pub fn prune_user(&self, user_id: Uuid) {
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(user_sessions) = sessions.get_mut(&user_id) {
                user_sessions.retain(|sender| !sender.is_closed());
                if user_sessions.is_empty() {
                    sessions.remove(&user_id);
                }
            }
        }
    }

    pub fn broadcast_to_users(&self, user_ids: &[Uuid], payload: &str) {
        if let Ok(mut sessions) = self.sessions.write() {
            for user_id in user_ids {
                if let Some(user_sessions) = sessions.get_mut(user_id) {
                    user_sessions.retain(|sender| sender.send(payload.to_string()).is_ok());
                }
            }
            sessions.retain(|_, user_sessions| !user_sessions.is_empty());
        }
    }
}

async fn ws_upgrade(
    request: HttpRequest,
    payload: web::Payload,
    state: web::Data<AppState>,
) -> AppResult<HttpResponse> {
    if state.app_environment == "production" && !is_secure_ws_request(&request) {
        return Err(AppError::BadRequest(
            "wss is required in production".to_string(),
        ));
    }

    let token = extract_ws_token(&request).ok_or(AppError::Unauthorized)?;
    let claims = state.auth_service.validate_access_token(&token)?;
    state
        .auth_service
        .ensure_active_session_for_user(claims.sub)
        .await?;

    let (response, session, stream) = actix_ws::handle(&request, payload)
        .map_err(|_| AppError::BadRequest("invalid websocket upgrade".to_string()))?;

    let message_service = state.message_service.clone();
    let hub = state.ws_hub.clone();
    let outbound_rx = hub.register(claims.sub);
    let metrics = state.metrics.clone();
    metrics.ws_connected();
    actix_web::rt::spawn(async move {
        let _ = ws_loop(
            session,
            stream,
            outbound_rx,
            message_service,
            hub.clone(),
            claims.sub,
        )
        .await;
        hub.prune_user(claims.sub);
        metrics.ws_disconnected();
    });

    Ok(response)
}

fn extract_ws_token(request: &HttpRequest) -> Option<String> {
    if let Some(header) = request
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
    {
        if let Some(token) = header.strip_prefix("Bearer ") {
            return Some(token.to_string());
        }
    }

    let protocol = request
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|value| value.to_str().ok())?;
    let mut parts = protocol.split(',');
    let first = parts.next()?.trim().to_ascii_lowercase();
    let second = parts.next()?.trim();
    if first == "bearer" && !second.is_empty() {
        return Some(second.to_string());
    }
    None
}

fn is_secure_ws_request(request: &HttpRequest) -> bool {
    if request.connection_info().scheme() == "https" {
        return true;
    }

    request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|proto| proto.eq_ignore_ascii_case("https"))
}

async fn ws_loop(
    mut session: actix_ws::Session,
    mut stream: actix_ws::MessageStream,
    mut outbound_rx: mpsc::UnboundedReceiver<String>,
    message_service: std::sync::Arc<crate::application::MessageService>,
    hub: WsConnectionHub,
    user_id: Uuid,
) -> AppResult<()> {
    let heartbeat_interval = Duration::from_secs(30);
    let heartbeat_timeout = Duration::from_secs(90);
    let mut heartbeat = tokio::time::interval(heartbeat_interval);
    let mut last_seen = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if last_seen.elapsed() > heartbeat_timeout {
                    let _ = session.close(None).await;
                    break;
                }
                if session.ping(b"ping").await.is_err() {
                    break;
                }
            }
            maybe_message = stream.next() => {
                let Some(Ok(message)) = maybe_message else {
                    break;
                };

                match message {
                    actix_ws::Message::Ping(bytes) => {
                        last_seen = tokio::time::Instant::now();
                        if session.pong(&bytes).await.is_err() {
                            break;
                        }
                    }
                    actix_ws::Message::Pong(_) => {
                        last_seen = tokio::time::Instant::now();
                    }
                    actix_ws::Message::Text(text) => {
                        last_seen = tokio::time::Instant::now();
                        if let Err(error) =
                            handle_text_message(
                                &mut session,
                                &message_service,
                                &hub,
                                user_id,
                                text.to_string(),
                            )
                                .await
                        {
                            match error {
                                AppError::BadRequest(_) => {
                                    let payload =
                                        json!({ "type": "error", "payload": { "code": "BAD_MESSAGE" } });
                                    if session.text(payload.to_string()).await.is_err() {
                                        break;
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                    actix_ws::Message::Close(reason) => {
                        let _ = session.close(reason).await;
                        break;
                    }
                    actix_ws::Message::Binary(_) => {
                        let payload = json!({ "type": "error", "payload": { "code": "UNSUPPORTED_BINARY" } });
                        if session.text(payload.to_string()).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            maybe_outbound = outbound_rx.recv() => {
                let Some(payload) = maybe_outbound else {
                    break;
                };
                if session.text(payload).await.is_err() {
                    break;
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct WsClientEnvelope {
    #[serde(rename = "type")]
    message_type: String,
    payload: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct WsSendMessagePayload {
    conversation_id: Uuid,
    content: String,
}

#[derive(Debug, Deserialize)]
struct WsTypingPayload {
    conversation_id: Uuid,
    is_typing: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WsReadPayload {
    conversation_id: Uuid,
}

async fn handle_text_message(
    session: &mut actix_ws::Session,
    message_service: &std::sync::Arc<crate::application::MessageService>,
    hub: &WsConnectionHub,
    user_id: Uuid,
    text: String,
) -> AppResult<()> {
    let envelope = parse_ws_envelope(&text)?;

    match envelope.message_type.as_str() {
        "ping" => {
            let payload = json!({ "type": "pong" });
            session
                .text(payload.to_string())
                .await
                .map_err(|_| AppError::InternalError(anyhow::anyhow!("failed to send pong")))?;
        }
        "message" => {
            let parsed = parse_send_message_payload(envelope.payload)?;

            // Persist first, then deliver to the socket.
            let saved = message_service
                .send_message(
                    user_id,
                    parsed.conversation_id,
                    SendMessageRequest {
                        content: parsed.content,
                    },
                )
                .await?;

            let server_event = json!({ "type": "message", "payload": saved });
            let participants = message_service
                .participant_ids(user_id, parsed.conversation_id)
                .await?;
            hub.broadcast_to_users(&participants, &server_event.to_string());
        }
        "typing" => {
            let parsed = parse_typing_payload(envelope.payload)?;
            let participants = message_service
                .participant_ids(user_id, parsed.conversation_id)
                .await?;
            let event = json!({
                "type": "typing",
                "payload": {
                    "conversation_id": parsed.conversation_id,
                    "user_id": user_id,
                    "is_typing": parsed.is_typing.unwrap_or(true),
                }
            });
            hub.broadcast_to_users(&participants, &event.to_string());
        }
        "read" => {
            let parsed = parse_read_payload(envelope.payload)?;
            message_service
                .mark_as_read(user_id, parsed.conversation_id)
                .await?;
            let participants = message_service
                .participant_ids(user_id, parsed.conversation_id)
                .await?;
            let event = json!({
                "type": "read",
                "payload": {
                    "conversation_id": parsed.conversation_id,
                    "user_id": user_id,
                    "read_at": Utc::now(),
                }
            });
            hub.broadcast_to_users(&participants, &event.to_string());
        }
        _ => {
            let payload = json!({ "type": "error", "payload": { "code": "UNSUPPORTED_TYPE" } });
            session.text(payload.to_string()).await.map_err(|_| {
                AppError::InternalError(anyhow::anyhow!("failed to send error event"))
            })?;
        }
    }

    Ok(())
}

fn parse_ws_envelope(text: &str) -> AppResult<WsClientEnvelope> {
    serde_json::from_str(text)
        .map_err(|_| AppError::BadRequest("invalid websocket message".to_string()))
}

fn parse_send_message_payload(payload: Option<Value>) -> AppResult<WsSendMessagePayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing message payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid message payload".to_string()))
}

fn parse_typing_payload(payload: Option<Value>) -> AppResult<WsTypingPayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing typing payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid typing payload".to_string()))
}

fn parse_read_payload(payload: Option<Value>) -> AppResult<WsReadPayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing read payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid read payload".to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{http::StatusCode, test as awtest, web, App};
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;
    use uuid::Uuid;

    use crate::api::routes::AppState;
    use crate::application::{
        AuthService, CategoryService, EquipmentService, MessageService, UserService,
    };
    use crate::config::{AuthConfig, SecurityConfig};
    use crate::domain::{
        AuthIdentity, Category, Conversation, Equipment, EquipmentPhoto, Message, User, UserSession,
    };
    use crate::infrastructure::repositories::{
        AuthRepository, CategoryRepository, EquipmentRepository, MessageRepository, UserRepository,
    };
    use crate::observability::AppMetrics;
    use crate::security::LoginThrottle;
    use crate::utils::jwt::create_access_token;

    struct NoopUserRepo;

    #[async_trait]
    impl UserRepository for NoopUserRepo {
        async fn find_by_id(&self, _id: Uuid) -> crate::error::AppResult<Option<User>> {
            Ok(None)
        }

        async fn find_by_email(&self, _email: &str) -> crate::error::AppResult<Option<User>> {
            Ok(None)
        }

        async fn find_by_username(&self, _username: &str) -> crate::error::AppResult<Option<User>> {
            Ok(None)
        }

        async fn create(&self, user: &User) -> crate::error::AppResult<User> {
            Ok(user.clone())
        }

        async fn update(&self, user: &User) -> crate::error::AppResult<User> {
            Ok(user.clone())
        }

        async fn delete(&self, _id: Uuid) -> crate::error::AppResult<()> {
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
        ) -> crate::error::AppResult<AuthIdentity> {
            Ok(identity.clone())
        }

        async fn find_identity_by_user_id(
            &self,
            _user_id: Uuid,
            _provider: &str,
        ) -> crate::error::AppResult<Option<AuthIdentity>> {
            Ok(None)
        }

        async fn find_identity_by_provider_id(
            &self,
            _provider: &str,
            _provider_id: &str,
        ) -> crate::error::AppResult<Option<AuthIdentity>> {
            Ok(None)
        }

        async fn verify_email(&self, _user_id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn create_session(
            &self,
            session: &UserSession,
        ) -> crate::error::AppResult<UserSession> {
            Ok(session.clone())
        }

        async fn find_session_by_token_hash(
            &self,
            _token_hash: &str,
        ) -> crate::error::AppResult<Option<UserSession>> {
            Ok(None)
        }

        async fn revoke_session(&self, _id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn revoke_session_with_replacement(
            &self,
            _id: Uuid,
            _replaced_by: Option<Uuid>,
            _reason: Option<&str>,
        ) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn revoke_all_sessions(&self, _user_id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn revoke_family(
            &self,
            _family_id: Uuid,
            _reason: &str,
        ) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn touch_session(&self, _id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn has_active_session(&self, _user_id: Uuid) -> crate::error::AppResult<bool> {
            Ok(self.has_active_session)
        }
    }

    struct NoopCategoryRepo;

    #[async_trait]
    impl CategoryRepository for NoopCategoryRepo {
        async fn find_all(&self) -> crate::error::AppResult<Vec<Category>> {
            Ok(Vec::new())
        }

        async fn find_by_id(&self, _id: Uuid) -> crate::error::AppResult<Option<Category>> {
            Ok(None)
        }

        async fn find_children(&self, _parent_id: Uuid) -> crate::error::AppResult<Vec<Category>> {
            Ok(Vec::new())
        }
    }

    struct NoopEquipmentRepo;

    #[async_trait]
    impl EquipmentRepository for NoopEquipmentRepo {
        async fn find_by_id(&self, _id: Uuid) -> crate::error::AppResult<Option<Equipment>> {
            Ok(None)
        }

        async fn find_all(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> crate::error::AppResult<Vec<Equipment>> {
            Ok(Vec::new())
        }

        async fn find_by_owner(&self, _owner_id: Uuid) -> crate::error::AppResult<Vec<Equipment>> {
            Ok(Vec::new())
        }

        async fn create(&self, equipment: &Equipment) -> crate::error::AppResult<Equipment> {
            Ok(equipment.clone())
        }

        async fn update(&self, equipment: &Equipment) -> crate::error::AppResult<Equipment> {
            Ok(equipment.clone())
        }

        async fn delete(&self, _id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }

        async fn add_photo(
            &self,
            photo: &EquipmentPhoto,
        ) -> crate::error::AppResult<EquipmentPhoto> {
            Ok(photo.clone())
        }

        async fn find_photos(
            &self,
            _equipment_id: Uuid,
        ) -> crate::error::AppResult<Vec<EquipmentPhoto>> {
            Ok(Vec::new())
        }

        async fn delete_photo(&self, _photo_id: Uuid) -> crate::error::AppResult<()> {
            Ok(())
        }
    }

    struct NoopMessageRepo;

    #[async_trait]
    impl MessageRepository for NoopMessageRepo {
        async fn find_conversation(
            &self,
            _id: Uuid,
        ) -> crate::error::AppResult<Option<Conversation>> {
            Ok(None)
        }

        async fn find_user_conversations(
            &self,
            _user_id: Uuid,
        ) -> crate::error::AppResult<Vec<Conversation>> {
            Ok(Vec::new())
        }

        async fn create_conversation(
            &self,
            _participant_ids: Vec<Uuid>,
        ) -> crate::error::AppResult<Conversation> {
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
        ) -> crate::error::AppResult<Vec<Message>> {
            Ok(Vec::new())
        }

        async fn create_message(&self, message: &Message) -> crate::error::AppResult<Message> {
            Ok(message.clone())
        }

        async fn is_participant(
            &self,
            _conversation_id: Uuid,
            _user_id: Uuid,
        ) -> crate::error::AppResult<bool> {
            Ok(false)
        }

        async fn mark_as_read(
            &self,
            _conversation_id: Uuid,
            _user_id: Uuid,
        ) -> crate::error::AppResult<()> {
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

    fn expired_access_token(user_id: Uuid) -> String {
        let config = auth_config();
        let now = Utc::now();
        let claims = crate::utils::jwt::Claims {
            sub: user_id,
            exp: (now - Duration::minutes(5)).timestamp() as usize,
            iat: (now - Duration::minutes(10)).timestamp() as usize,
            jti: Uuid::new_v4(),
            kid: config.jwt_kid.clone(),
            iss: config.issuer.clone(),
            aud: vec![config.audience.clone()],
            role: "owner".to_string(),
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(config.jwt_kid.clone());

        encode(
            &header,
            &claims,
            &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
        )
        .expect("expired token should encode")
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

    fn build_state(has_active_session: bool, app_environment: &str) -> AppState {
        let user_repo: Arc<dyn UserRepository> = Arc::new(NoopUserRepo);
        let auth_repo: Arc<dyn AuthRepository> = Arc::new(StubAuthRepo { has_active_session });
        let category_repo: Arc<dyn CategoryRepository> = Arc::new(NoopCategoryRepo);
        let equipment_repo: Arc<dyn EquipmentRepository> = Arc::new(NoopEquipmentRepo);
        let message_repo: Arc<dyn MessageRepository> = Arc::new(NoopMessageRepo);
        let security = security_config();

        AppState {
            auth_service: Arc::new(AuthService::new(
                user_repo.clone(),
                auth_repo,
                auth_config(),
            )),
            user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
            category_service: Arc::new(CategoryService::new(category_repo)),
            equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
            message_service: Arc::new(MessageService::new(user_repo, message_repo)),
            security: security.clone(),
            login_throttle: Arc::new(LoginThrottle::new(&security)),
            app_environment: app_environment.to_string(),
            metrics: Arc::new(AppMetrics::default()),
            db_pool: None,
            ws_hub: super::WsConnectionHub::default(),
        }
    }

    #[actix_rt::test]
    async fn ws_rejects_when_token_is_missing() {
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get().uri("/ws").to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn ws_rejects_invalid_bearer_token() {
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Authorization", "Bearer invalid-token"))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn ws_rejects_valid_token_when_session_is_revoked() {
        let token = create_access_token(Uuid::new_v4(), "renter", &auth_config())
            .expect("token should be created");

        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(false, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn ws_requires_wss_in_production() {
        let token = create_access_token(Uuid::new_v4(), "owner", &auth_config())
            .expect("token should be created");

        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "production")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn ws_accepts_valid_bearer_token_on_upgrade() {
        let token = create_access_token(Uuid::new_v4(), "owner", &auth_config())
            .expect("token should be created");

        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Connection", "Upgrade"))
            .insert_header(("Upgrade", "websocket"))
            .insert_header(("Sec-WebSocket-Version", "13"))
            .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[actix_rt::test]
    async fn ws_accepts_subprotocol_token_fallback_on_upgrade() {
        let token = create_access_token(Uuid::new_v4(), "owner", &auth_config())
            .expect("token should be created");

        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Connection", "Upgrade"))
            .insert_header(("Upgrade", "websocket"))
            .insert_header(("Sec-WebSocket-Version", "13"))
            .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
            .insert_header(("Sec-WebSocket-Protocol", format!("bearer, {token}")))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    }

    #[actix_rt::test]
    async fn ws_rejects_expired_token_on_upgrade() {
        let token = expired_access_token(Uuid::new_v4());

        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::new(build_state(true, "development")))
                .configure(super::configure),
        )
        .await;

        let request = awtest::TestRequest::get()
            .uri("/ws")
            .insert_header(("Connection", "Upgrade"))
            .insert_header(("Upgrade", "websocket"))
            .insert_header(("Sec-WebSocket-Version", "13"))
            .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let response = awtest::call_service(&app, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn extracts_token_from_authorization_header() {
        let request = awtest::TestRequest::default()
            .insert_header(("Authorization", "Bearer abc123"))
            .to_http_request();

        let token = super::extract_ws_token(&request);
        assert_eq!(token.as_deref(), Some("abc123"));
    }

    #[test]
    fn extracts_token_from_subprotocol_fallback() {
        let request = awtest::TestRequest::default()
            .insert_header(("Sec-WebSocket-Protocol", "bearer, fallback-token"))
            .to_http_request();

        let token = super::extract_ws_token(&request);
        assert_eq!(token.as_deref(), Some("fallback-token"));
    }

    #[test]
    fn ignores_invalid_subprotocol_format() {
        let request = awtest::TestRequest::default()
            .insert_header(("Sec-WebSocket-Protocol", "notbearer, token"))
            .to_http_request();

        let token = super::extract_ws_token(&request);
        assert!(token.is_none());
    }

    #[test]
    fn malformed_ws_text_message_returns_bad_request() {
        let result = super::parse_ws_envelope("{not-json");
        assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
    }

    #[test]
    fn missing_ws_message_payload_returns_bad_request() {
        let result = super::parse_send_message_payload(None);
        assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
    }

    #[test]
    fn invalid_ws_message_payload_shape_returns_bad_request() {
        let result =
            super::parse_send_message_payload(Some(json!({ "conversation_id": "not-a-uuid" })));
        assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
    }

    #[test]
    fn parse_typing_payload_accepts_valid_shape() {
        let conversation_id = Uuid::new_v4();
        let result = super::parse_typing_payload(Some(json!({
            "conversation_id": conversation_id,
            "is_typing": true
        })));
        assert!(result.is_ok());
    }

    #[test]
    fn parse_read_payload_accepts_valid_shape() {
        let conversation_id = Uuid::new_v4();
        let result = super::parse_read_payload(Some(json!({
            "conversation_id": conversation_id
        })));
        assert!(result.is_ok());
    }
}
