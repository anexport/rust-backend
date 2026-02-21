use std::time::Duration;

use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::dtos::SendMessageRequest;
use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};

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

    let token = extract_ws_token(&request).ok_or(AppError::Unauthorized)?;
    let claims = state.auth_service.validate_access_token(&token)?;
    state
        .auth_service
        .ensure_active_session_for_user(claims.sub)
        .await?;

    let (response, session, stream) = actix_ws::handle(&request, payload)
        .map_err(|_| AppError::BadRequest("invalid websocket upgrade".to_string()))?;

    let message_service = state.message_service.clone();
    actix_web::rt::spawn(async move {
        let _ = ws_loop(session, stream, message_service, claims.sub).await;
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
    message_service: std::sync::Arc<crate::application::MessageService>,
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
                        if handle_text_message(&mut session, &message_service, user_id, text.to_string()).await.is_err() {
                            break;
                        }
                    }
                    actix_ws::Message::Close(reason) => {
                        let _ = session.close(reason).await;
                        break;
                    }
                    actix_ws::Message::Binary(_) => {}
                    _ => {}
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

async fn handle_text_message(
    session: &mut actix_ws::Session,
    message_service: &std::sync::Arc<crate::application::MessageService>,
    user_id: Uuid,
    text: String,
) -> AppResult<()> {
    let envelope: WsClientEnvelope = serde_json::from_str(&text)
        .map_err(|_| AppError::BadRequest("invalid websocket message".to_string()))?;

    match envelope.message_type.as_str() {
        "ping" => {
            let payload = json!({ "type": "pong" });
            session
                .text(payload.to_string())
                .await
                .map_err(|_| AppError::InternalError(anyhow::anyhow!("failed to send pong")))?;
        }
        "message" => {
            let payload = envelope
                .payload
                .ok_or_else(|| AppError::BadRequest("missing message payload".to_string()))?;
            let parsed: WsSendMessagePayload = serde_json::from_value(payload)
                .map_err(|_| AppError::BadRequest("invalid message payload".to_string()))?;

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
            session.text(server_event.to_string()).await.map_err(|_| {
                AppError::InternalError(anyhow::anyhow!("failed to send message event"))
            })?;
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
