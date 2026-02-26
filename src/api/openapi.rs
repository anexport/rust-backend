use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// Re-export the auth DTOs for OpenAPI compatibility
pub use crate::api::routes::auth::Auth0LoginRequestDto;
pub use crate::api::routes::auth::Auth0LoginResponse;
pub use crate::api::routes::auth::Auth0SignupRequestDto;

#[derive(OpenApi)]
#[openapi(
    paths(
        // Auth endpoints
        crate::api::routes::auth::auth0_signup,
        crate::api::routes::auth::auth0_login,
        crate::api::routes::auth::me,
        // Equipment endpoints
        crate::api::routes::equipment::list_equipment,
        crate::api::routes::equipment::get_equipment,
        crate::api::routes::equipment::create_equipment,
        crate::api::routes::equipment::update_equipment,
        crate::api::routes::equipment::delete_equipment,
        // Health check
        crate::api::routes::health,
        // Category endpoints
        crate::api::routes::equipment::list_categories,
        crate::api::routes::equipment::get_category,
    ),
    components(
        schemas(
            Auth0SignupRequestDto,
            Auth0LoginRequestDto,
            Auth0LoginResponse,
            crate::api::dtos::user_dto::UserDto,
            crate::api::dtos::equipment_dto::CreateEquipmentRequest,
            crate::api::dtos::equipment_dto::UpdateEquipmentRequest,
            crate::api::dtos::equipment_dto::EquipmentDto,
            crate::api::dtos::equipment_dto::EquipmentQueryParams,
            crate::api::dtos::category_dto::CategoryDto,
            crate::api::dtos::admin_dto::ErrorResponse,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "equipment", description = "Equipment listing and management"),
        (name = "health", description = "Health check endpoints"),
    ),
    info(
        title = "Rust Backend API",
        version = "0.1.0",
        description = "Equipment rental platform backend API",
        license(name = "MIT")
    )
)]
pub struct ApiDoc;

pub fn configure_swagger_ui(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(
        SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi()),
    );
}
