use actix_web::body::to_bytes;
use actix_web::http::StatusCode;
use actix_web::ResponseError;
use serde_json::Value;
use validator::Validate;

use super::db_mapping::{
    conflict_message_from_constraint, extract_raise_exception_message, map_database_error,
    required_field_message_from_db,
};
use super::AppError;

#[derive(Debug, Validate)]
struct RegisterValidation {
    #[validate(length(min = 12, message = "Password must be at least 12 characters"))]
    password: String,
}

#[actix_rt::test]
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
    let json: Value = serde_json::from_slice(&body).expect("response body should be valid json");

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

#[actix_rt::test]
async fn conflict_response_exposes_specific_message() {
    let response = AppError::Conflict("email already registered".to_string()).error_response();

    let body = to_bytes(response.into_body())
        .await
        .map_err(|_| "body read failed")
        .expect("response body should be readable");
    let json: Value = serde_json::from_slice(&body).expect("response body should be valid json");

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

#[test]
fn error_code_and_status_code_cover_remaining_variants() {
    let validation_error = AppError::ValidationError {
        message: "invalid input".to_string(),
        issues: Vec::new(),
    };
    let cases = vec![
        (
            AppError::DatabaseError(sqlx::Error::RowNotFound),
            StatusCode::INTERNAL_SERVER_ERROR,
            "DATABASE_ERROR",
        ),
        (
            AppError::NotFound("missing".to_string()),
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
        ),
        (
            AppError::Unauthorized,
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
        ),
        (
            AppError::Forbidden("forbidden".to_string()),
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
        ),
        (
            validation_error,
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
        ),
        (
            AppError::Conflict("duplicate".to_string()),
            StatusCode::CONFLICT,
            "CONFLICT",
        ),
        (
            AppError::InternalError(anyhow::anyhow!("boom")),
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
        ),
        (
            AppError::BadRequest("bad".to_string()),
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
        ),
        (
            AppError::TokenExpired,
            StatusCode::UNAUTHORIZED,
            "TOKEN_EXPIRED",
        ),
        (
            AppError::InvalidToken,
            StatusCode::UNAUTHORIZED,
            "INVALID_TOKEN",
        ),
        (
            AppError::RateLimited,
            StatusCode::TOO_MANY_REQUESTS,
            "RATE_LIMITED",
        ),
        (
            AppError::ServiceUnavailable {
                service: "db".to_string(),
                message: "down".to_string(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
        ),
    ];

    for (error, status, code) in cases {
        assert_eq!(error.status_code(), status);
        assert_eq!(error.error_code(), code);
    }
}

#[test]
fn public_message_hides_internal_errors_and_exposes_public_variants() {
    let internal_db = AppError::DatabaseError(sqlx::Error::RowNotFound);
    assert_eq!(internal_db.public_message(), "Internal server error");

    let internal_anyhow = AppError::InternalError(anyhow::anyhow!("sensitive details"));
    assert_eq!(internal_anyhow.public_message(), "Internal server error");

    let exposed = AppError::ServiceUnavailable {
        service: "database".to_string(),
        message: "Try again later".to_string(),
    };
    assert_eq!(exposed.public_message(), "Try again later");
}

#[test]
fn from_domain_error_maps_all_variants() {
    let not_found: AppError = crate::domain::DomainError::NotFound("missing".to_string()).into();
    assert!(matches!(not_found, AppError::NotFound(message) if message == "missing"));

    let validation: AppError =
        crate::domain::DomainError::ValidationError("invalid".to_string()).into();
    assert!(matches!(
        validation,
        AppError::ValidationError { message, .. } if message == "invalid"
    ));

    let business: AppError =
        crate::domain::DomainError::BusinessRuleViolation("rule broken".to_string()).into();
    assert!(matches!(business, AppError::BadRequest(message) if message == "rule broken"));

    let conflict: AppError = crate::domain::DomainError::Conflict("duplicate".to_string()).into();
    assert!(matches!(conflict, AppError::Conflict(message) if message == "duplicate"));
}

#[test]
fn from_jsonwebtoken_error_maps_expired_and_non_expired() {
    let expired =
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
    let app_error: AppError = expired.into();
    assert!(matches!(app_error, AppError::TokenExpired));

    let invalid =
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidSignature);
    let app_error: AppError = invalid.into();
    assert!(matches!(app_error, AppError::InvalidToken));
}

#[test]
fn maps_remaining_sqlstate_codes_and_unknown() {
    let foreign_key = map_database_error(Some("23503"), None, "fk violation");
    assert!(matches!(
        foreign_key,
        Some(AppError::BadRequest(message)) if message == "referenced resource does not exist"
    ));

    let check_violation = map_database_error(Some("23514"), None, "check violation");
    assert!(matches!(
        check_violation,
        Some(AppError::ValidationError { message, .. })
            if message == "request violates validation rules"
    ));

    let invalid_text = map_database_error(Some("22P02"), None, "invalid input syntax");
    assert!(matches!(
        invalid_text,
        Some(AppError::ValidationError { message, .. }) if message == "invalid input format"
    ));

    let unknown = map_database_error(Some("99999"), None, "unknown");
    assert!(unknown.is_none());
}

#[test]
fn required_field_message_from_db_parses_and_handles_no_match() {
    let parsed = required_field_message_from_db("null value in column \"email\" violates not-null");
    assert_eq!(parsed, Some("email is required".to_string()));

    let no_match = required_field_message_from_db("not a postgres not-null message");
    assert_eq!(no_match, None);
}

#[test]
fn extract_raise_exception_message_handles_variants() {
    let raised = extract_raise_exception_message("ERROR: booking overlaps existing record");
    assert_eq!(raised, Some("booking overlaps existing record"));

    let passthrough = extract_raise_exception_message("custom validation message");
    assert_eq!(passthrough, Some("custom validation message"));

    let empty = extract_raise_exception_message("   ");
    assert_eq!(empty, None);
}

#[test]
fn conflict_message_from_constraint_covers_additional_branches() {
    assert_eq!(
        conflict_message_from_constraint(Some("profiles_username_key")),
        "username already taken"
    );
    assert_eq!(
        conflict_message_from_constraint(Some("users_phone_key")),
        "phone number already registered"
    );
    assert_eq!(
        conflict_message_from_constraint(Some("identities_provider_id_provider_unique")),
        "identity already linked to another account"
    );
    assert_eq!(
        conflict_message_from_constraint(Some("unknown_constraint")),
        "resource already exists"
    );
    assert_eq!(
        conflict_message_from_constraint(None),
        "resource already exists"
    );
}
