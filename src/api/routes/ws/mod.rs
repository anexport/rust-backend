use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::UserProvisioningService;
use crate::utils::auth0_jwks::{validate_auth0_token, JwksProvider};

mod handlers;
mod hub;
mod messages;
#[cfg(test)]
mod tests;

use self::handlers::handle_text_message;
#[cfg(test)]
use self::messages::{
    parse_read_payload, parse_send_message_payload, parse_typing_payload, parse_ws_envelope,
};

pub use self::hub::WsConnectionHub;
pub use self::messages::{WsClientEnvelope, WsReadPayload, WsSendMessagePayload, WsTypingPayload};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/ws", web::get().to(ws_upgrade));
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

    let user_id = authenticate_ws_user(&request, &state).await?;
    state
        .auth_service
        .ensure_active_session_for_user(user_id)
        .await?;

    let (response, session, stream) = actix_ws::handle(&request, payload)
        .map_err(|_| AppError::BadRequest("invalid websocket upgrade".to_string()))?;

    let message_service = state.message_service.clone();
    let hub = state.ws_hub.clone();
    let outbound_rx = hub.register(user_id);
    let metrics = state.metrics.clone();
    metrics.ws_connected();
    actix_web::rt::spawn(async move {
        let _ = ws_loop(
            session,
            stream,
            outbound_rx,
            message_service,
            hub.clone(),
            user_id,
        )
        .await;
        hub.prune_user(user_id);
        metrics.ws_disconnected();
    });

    Ok(response)
}

async fn authenticate_ws_user(
    request: &HttpRequest,
    _state: &web::Data<AppState>,
) -> AppResult<Uuid> {
    let token = extract_ws_token(request).ok_or(AppError::Unauthorized)?;

    let jwks_client = request
        .app_data::<web::Data<Arc<dyn JwksProvider>>>()
        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("missing JwksProvider app data")))?;
    let auth0_config = request
        .app_data::<web::Data<crate::config::Auth0Config>>()
        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("missing Auth0Config app data")))?;
    let provisioning_service = request
        .app_data::<web::Data<Arc<dyn UserProvisioningService>>>()
        .ok_or_else(|| {
            AppError::InternalError(anyhow::anyhow!("missing UserProvisioningService app data"))
        })?;

    let claims = validate_auth0_token(
        &token,
        jwks_client.as_ref().as_ref(),
        auth0_config.get_ref(),
    )
    .await?;
    let user_context = provisioning_service.provision_user(&claims).await?;
    Ok(user_context.user_id)
}

fn extract_ws_token(request: &HttpRequest) -> Option<String> {
    if let Some(query) = web::Query::<TokenQuery>::from_query(request.query_string()).ok() {
        if let Some(token) = &query.token {
            return Some(token.clone());
        }
    }

    if let Some(header) = request
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok())
    {
        // Case-insensitive "Bearer" prefix (accepts "Bearer", "bearer", "BEARER", etc.)
        let header_lower = header.trim_start();
        if let Some(token) = header_lower
            .to_ascii_lowercase()
            .strip_prefix("bearer ")
            .map(|_| header_lower.split_at(7).1)
        {
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
