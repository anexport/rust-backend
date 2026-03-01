use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_category(name: &str) -> Category {
        Category {
            id: Uuid::new_v4(),
            name: name.to_string(),
            parent_id: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn category_serialization_roundtrip_without_parent() {
        let original = create_test_category("Test Category");
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Category = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.name, original.name);
        assert_eq!(deserialized.parent_id, original.parent_id);
    }

    #[test]
    fn category_serialization_roundtrip_with_parent() {
        let parent_id = Uuid::new_v4();
        let original = Category {
            id: Uuid::new_v4(),
            name: "Subcategory".to_string(),
            parent_id: Some(parent_id),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Category = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.name, original.name);
        assert_eq!(deserialized.parent_id, original.parent_id);
        assert_eq!(deserialized.parent_id, Some(parent_id));
    }

    #[test]
    fn category_with_nil_parent_serializes_correctly() {
        let original = Category {
            id: Uuid::new_v4(),
            name: "Root Category".to_string(),
            parent_id: Some(Uuid::nil()),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Category = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.parent_id, Some(Uuid::nil()));
    }

    #[test]
    fn category_name_preserved_through_serialization() {
        let test_names = vec![
            "Sports",
            "Power Tools",
            "Camera Equipment",
            "Outdoor Adventure",
            "Special & Characters",
        ];

        for name in test_names {
            let original = create_test_category(name);
            let serialized = serde_json::to_string(&original).unwrap();
            let deserialized: Category = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized.name, name);
        }
    }

    #[test]
    fn category_hierarchical_consistency_with_parent() {
        let parent_id = Uuid::new_v4();
        let child = Category {
            id: Uuid::new_v4(),
            name: "Child Category".to_string(),
            parent_id: Some(parent_id),
            created_at: Utc::now(),
        };

        // Parent should not equal child
        assert_ne!(child.id, parent_id);

        // Parent ID should be a valid UUID when set
        assert!(child.parent_id.is_some());
        assert!(child.parent_id.unwrap() != Uuid::nil());
    }

    #[test]
    fn category_hierarchical_consistency_without_parent() {
        let root_category = create_test_category("Root Category");

        // Root category should have no parent
        assert!(root_category.parent_id.is_none());
    }

    #[test]
    fn category_deserialization_from_json() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Test Category",
            "parent_id": null,
            "created_at": "2024-01-01T00:00:00Z"
        }"#;

        let category: Category = serde_json::from_str(json).unwrap();
        assert_eq!(category.name, "Test Category");
        assert!(category.parent_id.is_none());
    }

    #[test]
    fn category_deserialization_with_parent_from_json() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "Child Category",
            "parent_id": "550e8400-e29b-41d4-a716-446655440001",
            "created_at": "2024-01-01T00:00:00Z"
        }"#;

        let category: Category = serde_json::from_str(json).unwrap();
        assert_eq!(category.name, "Child Category");
        assert!(category.parent_id.is_some());
        assert_eq!(
            category.parent_id.unwrap(),
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()
        );
    }
}
