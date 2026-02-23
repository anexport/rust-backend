use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

use crate::api::dtos::SendMessageRequest;
use crate::error::{AppError, AppResult};

use super::messages::{
    parse_read_payload, parse_send_message_payload, parse_typing_payload, parse_ws_envelope,
};
use super::WsConnectionHub;

pub(super) async fn handle_text_message(
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
