use actix_web::{web, HttpResponse};
use uuid::Uuid;

use crate::api::dtos::{
    AdminCategoryRequest, AdminListQuery, AdminUpdateAvailabilityRequest, AdminUpdateRoleRequest,
};
use crate::api::routes::AppState;
use crate::error::{AppError, AppResult};
use crate::middleware::auth::Auth0AuthenticatedUser;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/stats", web::get().to(get_stats))
            .route("/users", web::get().to(list_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/users/{id}/role", web::put().to(update_user_role))
            .route("/users/{id}", web::delete().to(delete_user))
            .route("/equipment", web::get().to(list_equipment))
            .route("/equipment/{id}", web::delete().to(force_delete_equipment))
            .route(
                "/equipment/{id}/availability",
                web::put().to(toggle_equipment_availability),
            )
            .route("/categories", web::get().to(list_categories))
            .route("/categories", web::post().to(create_category))
            .route("/categories/{id}", web::put().to(update_category))
            .route("/categories/{id}", web::delete().to(delete_category)),
    );
}

async fn get_stats(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state.admin_service.get_stats().await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn list_users(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    query: web::Query<AdminListQuery>,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state
        .admin_service
        .list_users(
            query.page.unwrap_or(1),
            query.per_page.unwrap_or(20),
            query.search.clone(),
            query.role.clone(),
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn get_user(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state
        .admin_service
        .get_user_detail(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn update_user_role(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<AdminUpdateRoleRequest>,
) -> AppResult<HttpResponse> {
    let actor_id = require_admin(&auth)?;
    let result = state
        .admin_service
        .update_user_role(actor_id, path.into_inner(), payload.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn delete_user(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let actor_id = require_admin(&auth)?;
    state
        .admin_service
        .delete_user(actor_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn list_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    query: web::Query<AdminListQuery>,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state
        .admin_service
        .list_equipment(
            query.page.unwrap_or(1),
            query.per_page.unwrap_or(20),
            query.search.clone(),
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn force_delete_equipment(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let actor_id = require_admin(&auth)?;
    state
        .admin_service
        .force_delete_equipment(actor_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn toggle_equipment_availability(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<AdminUpdateAvailabilityRequest>,
) -> AppResult<HttpResponse> {
    let actor_id = require_admin(&auth)?;
    let is_available = state
        .admin_service
        .toggle_equipment_availability(actor_id, path.into_inner(), payload.is_available)
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "is_available": is_available })))
}

async fn list_categories(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state.admin_service.list_categories().await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn create_category(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    payload: web::Json<AdminCategoryRequest>,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state
        .admin_service
        .create_category(payload.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(result))
}

async fn update_category(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
    payload: web::Json<AdminCategoryRequest>,
) -> AppResult<HttpResponse> {
    let _ = require_admin(&auth)?;
    let result = state
        .admin_service
        .update_category(path.into_inner(), payload.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

async fn delete_category(
    state: web::Data<AppState>,
    auth: Auth0AuthenticatedUser,
    path: web::Path<Uuid>,
) -> AppResult<HttpResponse> {
    let actor_id = require_admin(&auth)?;
    state
        .admin_service
        .delete_category(actor_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

fn require_admin(auth: &Auth0AuthenticatedUser) -> AppResult<Uuid> {
    if auth.0.role != "admin" {
        return Err(AppError::Forbidden(
            "Admin role is required to access this endpoint".to_string(),
        ));
    }
    Ok(auth.0.user_id)
}
