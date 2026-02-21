use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum DomainError {
    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Business rule violation: {0}")]
    BusinessRuleViolation(String),

    #[error("Conflict: {0}")]
    Conflict(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    mod display {
        use super::*;

        #[test]
        fn not_found_displays_with_message() {
            let error = DomainError::NotFound("User 123".to_string());
            assert_eq!(error.to_string(), "Resource not found: User 123");
        }

        #[test]
        fn validation_error_displays_with_message() {
            let error = DomainError::ValidationError("Email is required".to_string());
            assert_eq!(error.to_string(), "Validation error: Email is required");
        }

        #[test]
        fn business_rule_violation_displays_with_message() {
            let error =
                DomainError::BusinessRuleViolation("Cannot delete active rental".to_string());
            assert_eq!(
                error.to_string(),
                "Business rule violation: Cannot delete active rental"
            );
        }

        #[test]
        fn conflict_displays_with_message() {
            let error = DomainError::Conflict("Email already exists".to_string());
            assert_eq!(error.to_string(), "Conflict: Email already exists");
        }
    }

    mod equality {
        use super::*;

        #[test]
        fn same_not_found_errors_are_equal() {
            let error1 = DomainError::NotFound("User 123".to_string());
            let error2 = DomainError::NotFound("User 123".to_string());
            assert_eq!(error1, error2);
        }

        #[test]
        fn different_message_not_found_errors_are_not_equal() {
            let error1 = DomainError::NotFound("User 123".to_string());
            let error2 = DomainError::NotFound("User 456".to_string());
            assert_ne!(error1, error2);
        }

        #[test]
        fn different_variants_are_not_equal() {
            let error1 = DomainError::NotFound("User 123".to_string());
            let error2 = DomainError::ValidationError("User 123".to_string());
            assert_ne!(error1, error2);
        }
    }

    mod clone {
        use super::*;

        #[test]
        fn clone_produces_equal_error() {
            let error = DomainError::NotFound("User 123".to_string());
            let cloned = error.clone();
            assert_eq!(error, cloned);
        }

        #[test]
        fn clone_validation_error() {
            let error = DomainError::ValidationError("Invalid input".to_string());
            let cloned = error.clone();
            assert_eq!(error, cloned);
        }
    }

    mod error_derive {
        use super::*;

        #[test]
        fn error_trait_is_implemented() {
            let error: &dyn std::error::Error = &DomainError::NotFound("test".to_string());
            assert!(!error.to_string().is_empty());
        }

        #[test]
        fn error_source_is_none() {
            let error = DomainError::NotFound("test".to_string());
            use std::error::Error;
            assert!(error.source().is_none());
        }
    }
}
