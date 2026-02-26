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
