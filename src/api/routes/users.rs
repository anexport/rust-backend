use actix_web::{web, HttpResponse};
use uuid::Uuid;

use crate::api::dtos::UpdateUserRequest;
use crate::api::routes::AppState;
use crate::error::AppResult;
use crate::middleware::auth::AuthenticatedUser;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("/{id}", web::get().to(get_user_profile))
            .route("/{id}", web::put().to(update_user_profile))
            .route("/me/equipment", web::get().to(my_equipment)),
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
    auth: AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<UpdateUserRequest>,
) -> AppResult<HttpResponse> {
    let actor = auth.0.sub;
    let target = path.into_inner();
    let result = state
        .user_service
        .update_profile(actor, target, payload.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn my_equipment(
    state: web::Data<AppState>,
    auth: AuthenticatedUser,
) -> AppResult<HttpResponse> {
    let result = state.user_service.my_equipment(auth.0.sub).await?;
    Ok(HttpResponse::Ok().json(result))
}
