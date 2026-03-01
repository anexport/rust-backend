// Property-based tests for domain entities
// These tests verify invariants across the entire input space using proptest

use proptest::prelude::*;
use rust_backend::domain::category::Category;
use rust_backend::domain::equipment::{Condition, Equipment};
use rust_backend::domain::message::Message;
use rust_backend::domain::user::{AuthProvider, Role};
use uuid::Uuid;

// ============================================================================
// Equipment Property Tests
// ============================================================================

proptest! {
    /// For all latitude values outside [-90, 90], set_coordinates fails
    #[test]
    fn latitude_out_of_range_rejected(lat in -1000.0f64..1000.0) {
        prop_assume!(!(-90.0..=90.0).contains(&lat));
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(lat, 0.0);
        prop_assert!(result.is_err());
    }

    /// For all latitude values within [-90, 90], set_coordinates succeeds
    #[test]
    fn latitude_in_range_accepted(lat in -90.0f64..=90.0) {
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(lat, 0.0);
        prop_assert!(result.is_ok());
    }

    /// For all longitude values outside [-180, 180], set_coordinates fails
    #[test]
    fn longitude_out_of_range_rejected(lng in -360.0f64..360.0) {
        prop_assume!(!(-180.0..=180.0).contains(&lng));
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(0.0, lng);
        prop_assert!(result.is_err());
    }

    /// For all longitude values within [-180, 180], set_coordinates succeeds
    #[test]
    fn longitude_in_range_accepted(lng in -180.0f64..=180.0) {
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(0.0, lng);
        prop_assert!(result.is_ok());
    }

    /// For all valid coordinate pairs, set_coordinates stores them correctly
    #[test]
    fn coordinates_roundtrip_preserves_values(lat in -90.0f64..=90.0, lng in -180.0f64..=180.0) {
        let mut equipment = Equipment::default();
        equipment.set_coordinates(lat, lng).unwrap();
        let (stored_lat, stored_lng) = equipment.coordinates_tuple().unwrap();
        prop_assert!((stored_lat - lat).abs() < f64::EPSILON);
        prop_assert!((stored_lng - lng).abs() < f64::EPSILON);
    }

    /// For all boundary latitudes, set_coordinates succeeds
    #[test]
    fn latitude_boundary_values(lat in prop::sample::select(vec![-90.0, 90.0, -45.0, 45.0, 0.0])) {
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(lat, 0.0);
        prop_assert!(result.is_ok());
    }

    /// For all boundary longitudes, set_coordinates succeeds
    #[test]
    fn longitude_boundary_values(lng in prop::sample::select(vec![-180.0, 180.0, -90.0, 90.0, 0.0])) {
        let mut equipment = Equipment::default();
        let result = equipment.set_coordinates(0.0, lng);
        prop_assert!(result.is_ok());
    }

    /// For all Condition variants, serialize/deserialize roundtrip preserves the value
    #[test]
    fn condition_serialization_roundtrip(condition in prop::sample::select(vec![
        Condition::New,
        Condition::Excellent,
        Condition::Good,
        Condition::Fair,
    ])) {
        let serialized = serde_json::to_string(&condition).unwrap();
        let deserialized: Condition = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(condition, deserialized);
    }

    /// For all Condition variants, the serialized string is lowercase
    #[test]
    fn condition_serializes_to_lowercase(condition in prop::sample::select(vec![
        Condition::New,
        Condition::Excellent,
        Condition::Good,
        Condition::Fair,
    ])) {
        let serialized = serde_json::to_string(&condition).unwrap();
        prop_assert!(serialized.to_lowercase() == serialized);
    }
}

// ============================================================================
// User Property Tests
// ============================================================================

proptest! {
    /// For all Role variants, serialize/deserialize roundtrip preserves the value
    #[test]
    fn role_serialization_roundtrip(role in prop::sample::select(vec![
        Role::Renter,
        Role::Owner,
        Role::Admin,
    ])) {
        let serialized = serde_json::to_string(&role).unwrap();
        let deserialized: Role = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(role, deserialized);
    }

    /// For all Role variants, Display produces the same string as serialization
    #[test]
    fn role_display_matches_serialization(role in prop::sample::select(vec![
        Role::Renter,
        Role::Owner,
        Role::Admin,
    ])) {
        let display_str = role.to_string();
        let serialized = serde_json::to_string(&role).unwrap();
        // Remove quotes from JSON serialization
        let serialized_without_quotes = serialized.trim_matches('"');
        prop_assert_eq!(display_str, serialized_without_quotes);
    }

    /// For all AuthProvider variants, serialize/deserialize roundtrip preserves the value
    #[test]
    fn auth_provider_serialization_roundtrip(auth_provider in prop::sample::select(vec![
        AuthProvider::Email,
        AuthProvider::Google,
        AuthProvider::Github,
        AuthProvider::Auth0,
    ])) {
        let serialized = serde_json::to_string(&auth_provider).unwrap();
        let deserialized: AuthProvider = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(auth_provider, deserialized);
    }

    /// For all AuthProvider variants, Display produces the same string as serialization
    #[test]
    fn auth_provider_display_matches_serialization(auth_provider in prop::sample::select(vec![
        AuthProvider::Email,
        AuthProvider::Google,
        AuthProvider::Github,
        AuthProvider::Auth0,
    ])) {
        let display_str = auth_provider.to_string();
        let serialized = serde_json::to_string(&auth_provider).unwrap();
        // Remove quotes from JSON serialization
        let serialized_without_quotes = serialized.trim_matches('"');
        prop_assert_eq!(display_str, serialized_without_quotes);
    }

    /// For all strings not in valid Role values, deserialization fails
    #[test]
    fn invalid_role_rejection(s in ".*") {
        let valid_roles = ["renter", "owner", "admin"];
        prop_assume!(!valid_roles.contains(&s.as_str()));
        let json = format!("\"{}\"", s);
        let result: Result<Role, _> = serde_json::from_str(&json);
        prop_assert!(result.is_err());
    }

    /// For all valid Role strings, deserialization succeeds
    #[test]
    fn valid_role_accepted(role_str in prop::sample::select(vec!["renter", "owner", "admin"])) {
        let json = format!("\"{}\"", role_str);
        let result: Result<Role, _> = serde_json::from_str(&json);
        prop_assert!(result.is_ok());
    }

    /// For all strings not in valid AuthProvider values, deserialization fails
    #[test]
    fn invalid_auth_provider_rejection(s in ".*") {
        let valid_providers = ["email", "google", "github", "auth0"];
        prop_assume!(!valid_providers.contains(&s.as_str()));
        let json = format!("\"{}\"", s);
        let result: Result<AuthProvider, _> = serde_json::from_str(&json);
        prop_assert!(result.is_err());
    }

    /// For all valid AuthProvider strings, deserialization succeeds
    #[test]
    fn valid_auth_provider_accepted(provider_str in prop::sample::select(vec![
        "email",
        "google",
        "github",
        "auth0",
    ])) {
        let json = format!("\"{}\"", provider_str);
        let result: Result<AuthProvider, _> = serde_json::from_str(&json);
        prop_assert!(result.is_ok());
    }
}

// ============================================================================
// Category Property Tests
// ============================================================================

proptest! {
    /// For all Categories, serialize/deserialize roundtrip preserves the value
    #[test]
    fn category_serialization_roundtrip(
        name in "[a-zA-Z0-9 ]{1,100}",
        has_parent in proptest::bool::ANY,
    ) {
        let category = Category {
            id: Uuid::new_v4(),
            name,
            parent_id: if has_parent { Some(Uuid::new_v4()) } else { None },
            created_at: chrono::Utc::now(),
        };
        let serialized = serde_json::to_string(&category).unwrap();
        let deserialized: Category = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(category.id, deserialized.id);
        prop_assert_eq!(category.name, deserialized.name);
        prop_assert_eq!(category.parent_id, deserialized.parent_id);
    }
}

// ============================================================================
// Message Property Tests
// ============================================================================

proptest! {
    /// For all Messages, serialize/deserialize roundtrip preserves the value
    #[test]
    fn message_serialization_roundtrip(
        content in "\\PC*[A-Za-z0-9 ]", // Arbitrary string with at least one visible char
    ) {
        // Truncate to 5000 chars max (API limit)
        let content = if content.len() > 5000 {
            content.chars().take(5000).collect()
        } else {
            content
        };

        let message = Message {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            content,
            created_at: chrono::Utc::now(),
        };
        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(message.id, deserialized.id);
        prop_assert_eq!(message.conversation_id, deserialized.conversation_id);
        prop_assert_eq!(message.sender_id, deserialized.sender_id);
        prop_assert_eq!(message.content, deserialized.content);
    }

    /// For valid content strings up to 5000 chars, Message can be created and serialized
    #[test]
    fn message_content_serializes(content in "[a-zA-Z0-9 ]{1,5000}") {
        let message = Message {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            content,
            created_at: chrono::Utc::now(),
        };
        // Should serialize successfully
        let _ = serde_json::to_string(&message).unwrap();
    }
}
