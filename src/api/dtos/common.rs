use serde::Serialize;
use utoipa::ToSchema;

/// Standard error response structure for API errors
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    /// Error type (e.g., "BadRequest", "Unauthorized", "NotFound", etc.)
    pub error: String,
    /// Human-readable error message
    pub message: String,
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams, validator::Validate)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

const fn default_page() -> i64 {
    1
}

const fn default_limit() -> i64 {
    20
}
