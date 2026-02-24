use actix_web::{web, HttpResponse};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::dtos::{CreateConversationRequest, SendMessageRequest};
use crate::api::routes::AppState;
use crate::error::AppResult;
use crate::middleware::auth::Auth0AuthenticatedUser;

#[derive(Debug, Deserialize)]
struct MessageQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/conversations")
            .route("", web::get().to(list_conversations))
            .route("", web::post().to(create_conversation))
            .route("/{id}", web::get().to(get_conversation))
            .route("/{id}/messages", web::get().to(list_messages))
            .route("/{id}/messages", web::post().to(send_message)),
    );
}

async fn list_conversations(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
) -> AppResult<HttpResponse> {
    let result = state
        .message_service
        .list_conversations(auth.0.user_id)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn create_conversation(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    payload: web::Json<CreateConversationRequest>,
) -> AppResult<HttpResponse> {
    let result = state
        .message_service
        .create_conversation(auth.0.user_id, payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(result))
}

async fn get_conversation(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let result = state
        .message_service
        .get_conversation(auth.0.user_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn list_messages(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    query: web::Query<MessageQuery>,
) -> AppResult<HttpResponse> {
    let q = query.into_inner();
    let result = state
        .message_service
        .list_messages(
            auth.0.user_id,
            path.into_inner(),
            q.limit.unwrap_or(50),
            q.offset.unwrap_or(0),
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn send_message(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<SendMessageRequest>,
) -> AppResult<HttpResponse> {
    let (result, participant_ids) = state
        .message_service
        .send_message_with_participants(auth.0.user_id, path.into_inner(), payload.into_inner())
        .await?;

    let ws_payload = serde_json::json!({
        "type": "new_message",
        "data": result
    })
    .to_string();
    state.ws_hub.broadcast_to_users(&participant_ids, &ws_payload);

    Ok(HttpResponse::Created().json(result))
}
