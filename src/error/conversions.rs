use crate::error::app_error::AppError;
use crate::error::db_mapping::map_database_error;
use crate::error::validation_mapping::collect_validation_issues;

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

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
            _ => AppError::InvalidToken,
        }
    }
}
