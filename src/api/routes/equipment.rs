use actix_web::{web, HttpResponse};
use uuid::Uuid;

use crate::api::dtos::{
    AddPhotoRequest, CreateEquipmentRequest, EquipmentQueryParams, UpdateEquipmentRequest,
};
use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::Auth0AuthenticatedUser;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/equipment")
            .route("", web::get().to(list_equipment))
            .route("", web::post().to(create_equipment))
            .route("/{id}", web::get().to(get_equipment))
            .route("/{id}", web::put().to(update_equipment))
            .route("/{id}", web::delete().to(delete_equipment))
            .route("/{id}/photos", web::post().to(add_photo))
            .route("/{id}/photos/{photo_id}", web::delete().to(delete_photo)),
    )
    .service(
        web::scope("/categories")
            .route("", web::get().to(list_categories))
            .route("/{id}", web::get().to(get_category)),
    );
}

async fn list_equipment(
    state: web::Data<AppState>,
    query: web::Query<EquipmentQueryParams>,
) -> AppResult<HttpResponse> {
    let result = state.equipment_service.list(query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn get_equipment(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let result = state.equipment_service.get_by_id(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn create_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    payload: web::Json<CreateEquipmentRequest>,
) -> AppResult<HttpResponse> {
    if auth.0.role != "owner" && auth.0.role != "admin" {
        return Err(AppError::Forbidden(
            "Only equipment owners can create listings. Please update your account to owner status.".to_string(),
        ));
    }
    let owner_id = auth.0.user_id;
    let result = state
        .equipment_service
        .create(owner_id, payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(result))
}

async fn update_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<UpdateEquipmentRequest>,
) -> AppResult<HttpResponse> {
    let actor_user_id = auth.0.user_id;
    let result = state
        .equipment_service
        .update(actor_user_id, path.into_inner(), payload.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn delete_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let actor_user_id = auth.0.user_id;
    state
        .equipment_service
        .delete(actor_user_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn add_photo(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<AddPhotoRequest>,
) -> AppResult<HttpResponse> {
    let actor_user_id = auth.0.user_id;
    let result = state
        .equipment_service
        .add_photo(actor_user_id, path.into_inner(), payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(result))
}

async fn delete_photo(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<(Uuid, Uuid)>,
) -> AppResult<HttpResponse> {
    let actor_user_id = auth.0.user_id;
    let (equipment_id, photo_id) = path.into_inner();
    state
        .equipment_service
        .delete_photo(actor_user_id, equipment_id, photo_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn list_categories(state: web::Data<AppState>) -> AppResult<HttpResponse> {
    let result = state.category_service.list().await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn get_category(
    state: web::Data<AppState>,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let result = state.category_service.get_by_id(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}
