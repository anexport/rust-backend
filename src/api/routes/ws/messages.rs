use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, AppResult};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WsClientEnvelope {
    #[serde(rename = "type")]
    pub message_type: String,
    pub payload: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WsSendMessagePayload {
    pub conversation_id: Uuid,
    pub content: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WsTypingPayload {
    pub conversation_id: Uuid,
    pub is_typing: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct WsReadPayload {
    pub conversation_id: Uuid,
}

pub(super) fn parse_ws_envelope(text: &str) -> AppResult<WsClientEnvelope> {
    serde_json::from_str(text)
        .map_err(|_| AppError::BadRequest("invalid websocket message".to_string()))
}

pub(super) fn parse_send_message_payload(
    payload: Option<Value>,
) -> AppResult<WsSendMessagePayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing message payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid message payload".to_string()))
}

pub(super) fn parse_typing_payload(payload: Option<Value>) -> AppResult<WsTypingPayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing typing payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid typing payload".to_string()))
}

pub(super) fn parse_read_payload(payload: Option<Value>) -> AppResult<WsReadPayload> {
    let payload =
        payload.ok_or_else(|| AppError::BadRequest("missing read payload".to_string()))?;
    serde_json::from_value(payload)
        .map_err(|_| AppError::BadRequest("invalid read payload".to_string()))
}
