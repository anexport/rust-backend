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

impl DomainError {
    pub fn not_found(resource: impl Into<String>) -> Self {
        DomainError::NotFound(resource.into())
    }

    pub fn validation(message: impl Into<String>) -> Self {
        DomainError::ValidationError(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        DomainError::Conflict(message.into())
    }

    pub fn cannot_delete_active_rental() -> Self {
        DomainError::BusinessRuleViolation("Cannot delete rental while it is active".to_string())
    }

    pub fn equipment_not_available() -> Self {
        DomainError::BusinessRuleViolation(
            "Equipment is not available for the requested period".to_string(),
        )
    }

    pub fn cannot_modify_completed_rental() -> Self {
        DomainError::BusinessRuleViolation("Cannot modify a completed rental".to_string())
    }

    pub fn insufficient_inventory(item: impl Into<String>) -> Self {
        DomainError::BusinessRuleViolation(format!("Insufficient inventory for {}", item.into()))
    }

    pub fn user_already_has_active_rental() -> Self {
        DomainError::BusinessRuleViolation("User already has an active rental".to_string())
    }

    pub fn rental_cannot_be_cancelled() -> Self {
        DomainError::BusinessRuleViolation("Rental cannot be cancelled at this stage".to_string())
    }

    pub fn payment_required_for_action() -> Self {
        DomainError::BusinessRuleViolation(
            "Payment is required before this action can be performed".to_string(),
        )
    }
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

    mod constructors {
        use super::*;

        #[test]
        fn not_found_constructor_maps_to_not_found_variant() {
            let error = DomainError::not_found("Equipment 42");
            assert_eq!(error, DomainError::NotFound("Equipment 42".to_string()));
        }

        #[test]
        fn validation_constructor_maps_to_validation_variant() {
            let error = DomainError::validation("Missing name");
            assert_eq!(
                error,
                DomainError::ValidationError("Missing name".to_string())
            );
        }

        #[test]
        fn conflict_constructor_maps_to_conflict_variant() {
            let error = DomainError::conflict("Username already exists");
            assert_eq!(
                error,
                DomainError::Conflict("Username already exists".to_string())
            );
        }

        #[test]
        fn cannot_delete_active_rental_has_expected_message() {
            let error = DomainError::cannot_delete_active_rental();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation(
                    "Cannot delete rental while it is active".to_string()
                )
            );
        }

        #[test]
        fn equipment_not_available_has_expected_message() {
            let error = DomainError::equipment_not_available();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation(
                    "Equipment is not available for the requested period".to_string()
                )
            );
        }

        #[test]
        fn cannot_modify_completed_rental_has_expected_message() {
            let error = DomainError::cannot_modify_completed_rental();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation("Cannot modify a completed rental".to_string())
            );
        }

        #[test]
        fn insufficient_inventory_includes_item_name() {
            let error = DomainError::insufficient_inventory("Camera");
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation("Insufficient inventory for Camera".to_string())
            );
        }

        #[test]
        fn user_already_has_active_rental_has_expected_message() {
            let error = DomainError::user_already_has_active_rental();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation("User already has an active rental".to_string())
            );
        }

        #[test]
        fn rental_cannot_be_cancelled_has_expected_message() {
            let error = DomainError::rental_cannot_be_cancelled();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation(
                    "Rental cannot be cancelled at this stage".to_string()
                )
            );
        }

        #[test]
        fn payment_required_for_action_has_expected_message() {
            let error = DomainError::payment_required_for_action();
            assert_eq!(
                error,
                DomainError::BusinessRuleViolation(
                    "Payment is required before this action can be performed".to_string()
                )
            );
        }
    }
}
