use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationIssue {
    pub field: String,
    pub message: String,
    pub code: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DatabaseError(sqlx::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Validation error: {message}")]
    ValidationError {
        message: String,
        issues: Vec<ValidationIssue>,
    },

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal server error")]
    InternalError(#[source] anyhow::Error),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Too many requests")]
    RateLimited,

    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String, message: String },
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let error_code = self.error_code();
        let error = self.error_label();
        let message = self.public_message();

        let mut payload = serde_json::json!({
            "error": error,
            "message": message,
            "code": error_code,
        });

        if let Some(issues) = self.validation_issues() {
            payload["details"] =
                serde_json::to_value(issues).expect("validation issues should serialize");
        }

        HttpResponse::build(self.status_code()).json(payload)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::ValidationError { .. } => StatusCode::BAD_REQUEST,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::TokenExpired => StatusCode::UNAUTHORIZED,
            AppError::InvalidToken => StatusCode::UNAUTHORIZED,
            AppError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            AppError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            AppError::DatabaseError(_) | AppError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl AppError {
    pub fn error_code(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) => "DATABASE_ERROR",
            AppError::NotFound(_) => "NOT_FOUND",
            AppError::Unauthorized => "UNAUTHORIZED",
            AppError::Forbidden(_) => "FORBIDDEN",
            AppError::ValidationError { .. } => "VALIDATION_ERROR",
            AppError::Conflict(_) => "CONFLICT",
            AppError::InternalError(_) => "INTERNAL_ERROR",
            AppError::BadRequest(_) => "BAD_REQUEST",
            AppError::TokenExpired => "TOKEN_EXPIRED",
            AppError::InvalidToken => "INVALID_TOKEN",
            AppError::RateLimited => "RATE_LIMITED",
            AppError::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
        }
    }

    pub fn validation_error(message: impl Into<String>) -> Self {
        Self::ValidationError {
            message: message.into(),
            issues: Vec::new(),
        }
    }

    fn error_label(&self) -> &'static str {
        match self {
            AppError::DatabaseError(_) | AppError::InternalError(_) => "Internal server error",
            AppError::NotFound(_) => "Not found",
            AppError::Unauthorized => "Unauthorized",
            AppError::Forbidden(_) => "Forbidden",
            AppError::ValidationError { .. } => "Validation error",
            AppError::Conflict(_) => "Conflict",
            AppError::BadRequest(_) => "Bad request",
            AppError::TokenExpired => "Token expired",
            AppError::InvalidToken => "Invalid token",
            AppError::RateLimited => "Too many requests",
            AppError::ServiceUnavailable { .. } => "Service unavailable",
        }
    }

    pub(crate) fn public_message(&self) -> String {
        match self {
            AppError::DatabaseError(_) | AppError::InternalError(_) => {
                "Internal server error".to_string()
            }
            AppError::NotFound(message)
            | AppError::Forbidden(message)
            | AppError::Conflict(message)
            | AppError::BadRequest(message) => message.clone(),
            AppError::ValidationError { message, .. } => message.clone(),
            AppError::Unauthorized => "Unauthorized".to_string(),
            AppError::TokenExpired => "Token expired".to_string(),
            AppError::InvalidToken => "Invalid token".to_string(),
            AppError::RateLimited => "Too many requests".to_string(),
            AppError::ServiceUnavailable { message, .. } => message.clone(),
        }
    }

    fn validation_issues(&self) -> Option<&[ValidationIssue]> {
        match self {
            AppError::ValidationError { issues, .. } if !issues.is_empty() => Some(issues),
            _ => None,
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;
