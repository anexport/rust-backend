use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use thiserror::Error;
use validator::{ValidationErrors, ValidationErrorsKind};

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

    fn public_message(&self) -> String {
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

impl From<crate::domain::DomainError> for AppError {
    fn from(err: crate::domain::DomainError) -> Self {
        match err {
            crate::domain::DomainError::NotFound(msg) => AppError::NotFound(msg),
            crate::domain::DomainError::ValidationError(msg) => AppError::validation_error(msg),
            crate::domain::DomainError::BusinessRuleViolation(msg) => AppError::BadRequest(msg),
            crate::domain::DomainError::Conflict(msg) => AppError::Conflict(msg),
        }
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::InternalError(err)
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::Io(_) => AppError::ServiceUnavailable {
                service: "database".to_string(),
                message: "Unable to connect to database. Please try again later.".to_string(),
            },
            sqlx::Error::PoolTimedOut => AppError::ServiceUnavailable {
                service: "database".to_string(),
                message: "Service temporarily unavailable. Please try again later.".to_string(),
            },
            sqlx::Error::PoolClosed => AppError::ServiceUnavailable {
                service: "database".to_string(),
                message: "Service temporarily unavailable. Please try again later.".to_string(),
            },
            sqlx::Error::Database(database_error) => {
                if let Some(mapped) = map_database_error(
                    database_error.code().as_deref(),
                    database_error.constraint(),
                    database_error.message(),
                ) {
                    mapped
                } else {
                    AppError::DatabaseError(sqlx::Error::Database(database_error))
                }
            }
            other => AppError::DatabaseError(other),
        }
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        let mut issues = Vec::new();
        collect_validation_issues(None, &err, &mut issues);
        issues.sort_by(|left, right| {
            left.field
                .cmp(&right.field)
                .then(left.code.cmp(&right.code))
        });

        let message = match issues.as_slice() {
            [issue] => issue.message.clone(),
            _ => "Request validation failed".to_string(),
        };

        AppError::ValidationError { message, issues }
    }
}

fn collect_validation_issues(
    prefix: Option<String>,
    errors: &ValidationErrors,
    out: &mut Vec<ValidationIssue>,
) {
    for (field, kind) in errors.errors() {
        let path = match &prefix {
            Some(prefix) => format!("{prefix}.{field}"),
            None => field.to_string(),
        };

        match kind {
            ValidationErrorsKind::Field(field_errors) => {
                for error in field_errors {
                    let message = error
                        .message
                        .as_ref()
                        .map(std::borrow::Cow::to_string)
                        .unwrap_or_else(|| format!("{path} is invalid"));
                    out.push(ValidationIssue {
                        field: path.clone(),
                        message,
                        code: error.code.to_string(),
                    });
                }
            }
            ValidationErrorsKind::Struct(nested) => {
                collect_validation_issues(Some(path), nested, out);
            }
            ValidationErrorsKind::List(nested_items) => {
                for (index, nested) in nested_items {
                    collect_validation_issues(Some(format!("{path}[{index}]")), nested, out);
                }
            }
        }
    }
}

fn map_database_error(
    code: Option<&str>,
    constraint: Option<&str>,
    message: &str,
) -> Option<AppError> {
    match code {
        Some("23505") => Some(AppError::Conflict(
            conflict_message_from_constraint(constraint).to_string(),
        )),
        Some("23502") => Some(AppError::validation_error(
            required_field_message_from_db(message)
                .unwrap_or_else(|| "required field is missing".to_string()),
        )),
        Some("23503") => Some(AppError::BadRequest(
            "referenced resource does not exist".to_string(),
        )),
        Some("23514") => Some(AppError::validation_error(
            "request violates validation rules",
        )),
        Some("22P02") => Some(AppError::validation_error("invalid input format")),
        Some("08001") | Some("08006") => Some(AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: "Unable to connect to database. Please try again later.".to_string(),
        }),
        Some("53300") => Some(AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: "Service temporarily unavailable. Please try again later.".to_string(),
        }),
        Some("55P03") => Some(AppError::Conflict(
            "Resource is currently locked. Please try again.".to_string(),
        )),
        Some("P0001") => {
            let error_msg =
                extract_raise_exception_message(message).unwrap_or("Database validation error");
            Some(AppError::validation_error(error_msg))
        }
        _ => None,
    }
}

fn conflict_message_from_constraint(constraint: Option<&str>) -> &'static str {
    match constraint {
        Some("profiles_email_key") => "email already registered",
        Some("profiles_username_key") => "username already taken",
        Some("uq_auth_identities_provider_id") => "identity already linked",
        Some("auth_identities_user_id_provider_key") => "auth identity already exists",
        Some("conversation_participants_conversation_id_profile_id_key") => {
            "user is already a participant in this conversation"
        }
        Some("user_favorites_user_id_equipment_id_key") => "equipment already favorited",
        Some("availability_calendar_equipment_id_date_key") => "date is already booked",
        Some("unique_booking_inspection_type") => "inspection already exists for this booking",
        Some("unique_booking_request") => "booking already exists",
        Some("payments_stripe_payment_intent_id_key") => "payment already processed",
        Some("notification_preferences_user_unique") => "notification preferences already exist",
        Some("renter_profiles_profile_id_unique") => "renter profile already exists",
        Some("owner_profiles_profile_id_unique") => "owner profile already exists",
        Some("content_translations_content_type_content_id_field_name_tar_key") => {
            "translation already exists for this content"
        }
        Some("users_phone_key") => "phone number already registered",
        Some("identities_provider_id_provider_unique") => {
            "identity already linked to another account"
        }
        _ => "resource already exists",
    }
}

fn required_field_message_from_db(message: &str) -> Option<String> {
    let marker = "column \"";
    let start = message.find(marker)?;
    let rest = &message[start + marker.len()..];
    let end = rest.find('"')?;
    let field = &rest[..end];
    Some(format!("{field} is required"))
}

fn extract_raise_exception_message(message: &str) -> Option<&str> {
    if message.contains("RAISE EXCEPTION") || message.starts_with("ERROR:") {
        if let Some(colon_pos) = message.find(':') {
            let msg = message[colon_pos + 1..].trim();
            if !msg.is_empty() {
                return Some(msg);
            }
        }
    }
    let msg = message.trim();
    if msg.is_empty() {
        None
    } else {
        Some(msg)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
            _ => AppError::InvalidToken,
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes;
    use serde_json::Value;
    use validator::Validate;

    #[derive(Debug, Validate)]
    struct RegisterValidation {
        #[validate(length(min = 12, message = "Password must be at least 12 characters"))]
        password: String,
    }

    #[actix_web::test]
    async fn validation_error_response_includes_field_details() {
        let error: AppError = RegisterValidation {
            password: "short".to_string(),
        }
        .validate()
        .expect_err("validation should fail")
        .into();

        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(response.into_body())
            .await
            .map_err(|_| "body read failed")
            .expect("response body should be readable");
        let json: Value =
            serde_json::from_slice(&body).expect("response body should be valid json");

        assert_eq!(json["error"], "Validation error");
        assert_eq!(json["code"], "VALIDATION_ERROR");
        assert_eq!(json["message"], "Password must be at least 12 characters");
        assert_eq!(json["details"][0]["field"], "password");
        assert_eq!(
            json["details"][0]["message"],
            "Password must be at least 12 characters"
        );
        assert_eq!(json["details"][0]["code"], "length");
    }

    #[actix_web::test]
    async fn conflict_response_exposes_specific_message() {
        let response = AppError::Conflict("email already registered".to_string()).error_response();

        let body = to_bytes(response.into_body())
            .await
            .map_err(|_| "body read failed")
            .expect("response body should be readable");
        let json: Value =
            serde_json::from_slice(&body).expect("response body should be valid json");

        assert_eq!(json["error"], "Conflict");
        assert_eq!(json["code"], "CONFLICT");
        assert_eq!(json["message"], "email already registered");
    }

    #[test]
    fn maps_unique_constraint_violation_to_conflict_message() {
        let mapped = map_database_error(Some("23505"), Some("profiles_email_key"), "duplicate");
        assert!(matches!(
            mapped,
            Some(AppError::Conflict(message)) if message == "email already registered"
        ));
    }

    #[test]
    fn maps_not_null_violation_to_validation_message() {
        let mapped = map_database_error(
            Some("23502"),
            None,
            "null value in column \"password_hash\" violates not-null constraint",
        );
        assert!(matches!(
            mapped,
            Some(AppError::ValidationError { message, .. }) if message == "password_hash is required"
        ));
    }

    #[test]
    fn maps_connection_error_to_service_unavailable() {
        let mapped = map_database_error(Some("08001"), None, "connection failed");
        assert!(matches!(
            mapped,
            Some(AppError::ServiceUnavailable { service, message, .. })
                if service == "database" && message == "Unable to connect to database. Please try again later."
        ));

        let mapped = map_database_error(Some("08006"), None, "connection failed");
        assert!(matches!(
            mapped,
            Some(AppError::ServiceUnavailable { service, message, .. })
                if service == "database" && message == "Unable to connect to database. Please try again later."
        ));
    }

    #[test]
    fn maps_too_many_connections_to_service_unavailable() {
        let mapped = map_database_error(Some("53300"), None, "too many connections");
        assert!(matches!(
            mapped,
            Some(AppError::ServiceUnavailable { service, message, .. })
                if service == "database" && message == "Service temporarily unavailable. Please try again later."
        ));
    }

    #[test]
    fn maps_lock_not_available_to_conflict() {
        let mapped = map_database_error(Some("55P03"), None, "lock not available");
        assert!(matches!(
            mapped,
            Some(AppError::Conflict(message)) if message == "Resource is currently locked. Please try again."
        ));
    }

    #[test]
    fn maps_raise_exception_to_validation_error() {
        let mapped = map_database_error(
            Some("P0001"),
            None,
            "Booking date range exceeds maximum allowed period of 30 days",
        );
        assert!(matches!(
            mapped,
            Some(AppError::ValidationError { message, .. })
                if message == "Booking date range exceeds maximum allowed period of 30 days"
        ));
    }

    #[test]
    fn maps_conversation_participant_constraint() {
        let mapped = map_database_error(
            Some("23505"),
            Some("conversation_participants_conversation_id_profile_id_key"),
            "duplicate",
        );
        assert!(matches!(
            mapped,
            Some(AppError::Conflict(message))
                if message == "user is already a participant in this conversation"
        ));
    }

    #[test]
    fn maps_user_favorites_constraint() {
        let mapped = map_database_error(
            Some("23505"),
            Some("user_favorites_user_id_equipment_id_key"),
            "duplicate",
        );
        assert!(matches!(
            mapped,
            Some(AppError::Conflict(message)) if message == "equipment already favorited"
        ));
    }

    #[test]
    fn service_unavailable_returns_503_status() {
        let error = AppError::ServiceUnavailable {
            service: "database".to_string(),
            message: "Unable to connect to database.".to_string(),
        };
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error.error_code(), "SERVICE_UNAVAILABLE");
    }
}
