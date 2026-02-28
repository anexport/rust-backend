use actix_web::{web, HttpResponse};
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{PaginationParams, UpdateUserRequest};
use crate::api::routes::AppState;
use crate::error::AppResult;
use crate::middleware::auth::Auth0AuthenticatedUser;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/me/equipment", web::get().to(my_equipment))
            .route("/{id}", web::get().to(get_user_profile))
            .route("/{id}", web::put().to(update_user_profile)),
    );
}

async fn get_user_profile(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let result = state
        .user_service
        .get_public_profile(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn update_user_profile(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<UpdateUserRequest>,
) -> AppResult<HttpResponse> {
    payload.validate()?;
    let actor = auth.0.user_id;
    let target = path.into_inner();
    let result = state
        .user_service
        .update_profile(actor, target, payload.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn my_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    query: web::Query<PaginationParams>,
) -> AppResult<HttpResponse> {
    query.validate()?;
    let result = state
        .user_service
        .my_equipment(auth.0.user_id, query.page, query.limit)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}
