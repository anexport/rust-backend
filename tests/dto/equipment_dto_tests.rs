// Tests for equipment DTOs in src/api/dtos/equipment_dto.rs
// Tests CreateEquipmentRequest, UpdateEquipmentRequest, Coordinates validation

use rust_backend::api::dtos::equipment_dto::{
    AddPhotoRequest, Coordinates, CreateEquipmentRequest, UpdateEquipmentRequest,
};
use rust_decimal::Decimal;
use serde_json;
use uuid::Uuid;
use validator::Validate;

#[test]
fn test_create_equipment_request_valid_all_fields() {
    // Test valid request with all fields including coordinates
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Equipment Title".to_string(),
        description: "This is a valid description with at least 10 characters".to_string(),
        daily_rate: Decimal::from(50),
        condition: "new".to_string(),
        location: "San Francisco, CA".to_string(),
        coordinates: Some(Coordinates {
            latitude: 37.7749,
            longitude: -122.4194,
        }),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_valid_without_coordinates() {
    // Test valid request without coordinates
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Another Valid Title".to_string(),
        description: "Description meets minimum length requirement".to_string(),
        daily_rate: Decimal::from(75),
        condition: "excellent".to_string(),
        location: "New York, NY".to_string(),
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_title_min_length() {
    // Test title with minimum valid length (3 characters)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "ABC".to_string(),
        description: "Valid description text".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_title_max_length() {
    // Test title with maximum valid length (200 characters)
    let category_id = Uuid::new_v4();
    let title = "A".repeat(200);
    let request = CreateEquipmentRequest {
        category_id,
        title,
        description: "Valid description text".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_title_too_short() {
    // Test title too short (2 characters, min is 3)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "AB".to_string(),
        description: "Valid description text".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
}

#[test]
fn test_create_equipment_request_title_too_long() {
    // Test title too long (201 characters, max is 200)
    let category_id = Uuid::new_v4();
    let title = "A".repeat(201);
    let request = CreateEquipmentRequest {
        category_id,
        title,
        description: "Valid description text".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
}

#[test]
fn test_create_equipment_request_title_empty() {
    // Test empty title
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "".to_string(),
        description: "Valid description text".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
}

#[test]
fn test_create_equipment_request_description_min_length() {
    // Test description with minimum valid length (10 characters)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "1234567890".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_description_too_short() {
    // Test description too short (9 characters, min is 10)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "123456789".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("description"));
}

#[test]
fn test_create_equipment_request_description_empty() {
    // Test empty description
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("description"));
}

#[test]
fn test_create_equipment_request_location_min_length() {
    // Test location with minimum valid length (2 characters)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "Valid description".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "NY".to_string(),
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_location_max_length() {
    // Test location with maximum valid length (255 characters)
    let category_id = Uuid::new_v4();
    let location = "A".repeat(255);
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "Valid description".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location,
        coordinates: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_location_too_short() {
    // Test location too short (1 character, min is 2)
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "Valid description".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "A".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("location"));
}

#[test]
fn test_create_equipment_request_location_too_long() {
    // Test location too long (256 characters, max is 255)
    let category_id = Uuid::new_v4();
    let location = "A".repeat(256);
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "Valid description".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location,
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("location"));
}

#[test]
fn test_coordinates_latitude_min() {
    // Test latitude at minimum valid value (-90)
    let coords = Coordinates {
        latitude: -90.0,
        longitude: 0.0,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_coordinates_latitude_max() {
    // Test latitude at maximum valid value (90)
    let coords = Coordinates {
        latitude: 90.0,
        longitude: 0.0,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_coordinates_latitude_below_min() {
    // Test latitude below minimum (-90.1)
    let coords = Coordinates {
        latitude: -90.1,
        longitude: 0.0,
    };
    let result = coords.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("latitude"));
}

#[test]
fn test_coordinates_latitude_above_max() {
    // Test latitude above maximum (90.1)
    let coords = Coordinates {
        latitude: 90.1,
        longitude: 0.0,
    };
    let result = coords.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("latitude"));
}

#[test]
fn test_coordinates_longitude_min() {
    // Test longitude at minimum valid value (-180)
    let coords = Coordinates {
        latitude: 0.0,
        longitude: -180.0,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_coordinates_longitude_max() {
    // Test longitude at maximum valid value (180)
    let coords = Coordinates {
        latitude: 0.0,
        longitude: 180.0,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_coordinates_longitude_below_min() {
    // Test longitude below minimum (-180.1)
    let coords = Coordinates {
        latitude: 0.0,
        longitude: -180.1,
    };
    let result = coords.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("longitude"));
}

#[test]
fn test_coordinates_longitude_above_max() {
    // Test longitude above maximum (180.1)
    let coords = Coordinates {
        latitude: 0.0,
        longitude: 180.1,
    };
    let result = coords.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("longitude"));
}

#[test]
fn test_coordinates_valid_values() {
    // Test typical valid coordinate values
    let coords = Coordinates {
        latitude: 37.7749,
        longitude: -122.4194,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_coordinates_equator_prime_meridian() {
    // Test coordinates at equator and prime meridian (0, 0)
    let coords = Coordinates {
        latitude: 0.0,
        longitude: 0.0,
    };
    assert!(coords.validate().is_ok());
}

#[test]
fn test_create_equipment_request_with_invalid_coordinates() {
    // Test request with invalid coordinates - should fail validation
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "Valid Title".to_string(),
        description: "Valid description".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "Location".to_string(),
        coordinates: Some(Coordinates {
            latitude: 100.0, // Invalid latitude (>90)
            longitude: 0.0,
        }),
    };
    assert!(request.validate().is_err());
}

#[test]
fn test_update_equipment_request_all_none_valid() {
    // Test update request with all None values (valid - all fields optional)
    let request = UpdateEquipmentRequest::default();
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_equipment_request_partial_update_valid() {
    // Test partial update with some fields set
    let request = UpdateEquipmentRequest {
        title: Some("New Title".to_string()),
        description: None,
        daily_rate: None,
        condition: None,
        location: None,
        coordinates: None,
        is_available: Some(false),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_update_equipment_request_title_too_short() {
    // Test update request with title too short
    let request = UpdateEquipmentRequest {
        title: Some("AB".to_string()),
        description: None,
        daily_rate: None,
        condition: None,
        location: None,
        coordinates: None,
        is_available: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
}

#[test]
fn test_update_equipment_request_title_too_long() {
    // Test update request with title too long
    let request = UpdateEquipmentRequest {
        title: Some("A".repeat(201)),
        description: None,
        daily_rate: None,
        condition: None,
        location: None,
        coordinates: None,
        is_available: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
}

#[test]
fn test_update_equipment_request_description_too_short() {
    // Test update request with description too short
    let request = UpdateEquipmentRequest {
        title: None,
        description: Some("Short".to_string()),
        daily_rate: None,
        condition: None,
        location: None,
        coordinates: None,
        is_available: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("description"));
}

#[test]
fn test_update_equipment_request_location_too_short() {
    // Test update request with location too short
    let request = UpdateEquipmentRequest {
        title: None,
        description: None,
        daily_rate: None,
        condition: None,
        location: Some("A".to_string()),
        coordinates: None,
        is_available: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("location"));
}

#[test]
fn test_update_equipment_request_location_too_long() {
    // Test update request with location too long
    let request = UpdateEquipmentRequest {
        title: None,
        description: None,
        daily_rate: None,
        condition: None,
        location: Some("A".repeat(256)),
        coordinates: None,
        is_available: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("location"));
}

#[test]
fn test_update_equipment_request_invalid_coordinates() {
    // Test update request with invalid coordinates - should fail validation
    let request = UpdateEquipmentRequest {
        title: None,
        description: None,
        daily_rate: None,
        condition: None,
        location: None,
        coordinates: Some(Coordinates {
            latitude: 100.0,  // Invalid latitude (>90)
            longitude: 200.0, // Invalid longitude (>180)
        }),
        is_available: None,
    };
    assert!(request.validate().is_err());
}

#[test]
fn test_create_equipment_request_deserialization() {
    // Test deserialization from JSON
    let category_id = Uuid::new_v4();
    let json = format!(
        r#"{{
        "category_id": "{}",
        "title": "Test Equipment",
        "description": "Test description with enough characters",
        "daily_rate": "100.00",
        "condition": "good",
        "location": "Test Location",
        "coordinates": {{"latitude": 37.7749, "longitude": -122.4194}}
    }}"#,
        category_id
    );
    let request: CreateEquipmentRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.title, "Test Equipment");
    assert_eq!(
        request.description,
        "Test description with enough characters"
    );
    assert!(request.validate().is_ok());
}

#[test]
fn test_coordinates_roundtrip() {
    // Test coordinates serialization/deserialization roundtrip
    let original = Coordinates {
        latitude: 37.7749,
        longitude: -122.4194,
    };
    let json = serde_json::to_string(&original).unwrap();
    let deserialized: Coordinates = serde_json::from_str(&json).unwrap();
    assert_eq!(original.latitude, deserialized.latitude);
    assert_eq!(original.longitude, deserialized.longitude);
}

#[test]
fn test_add_photo_request_valid_url() {
    // Test valid photo URL
    let request = AddPhotoRequest {
        photo_url: "https://example.com/photo.jpg".to_string(),
        is_primary: None,
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_add_photo_request_invalid_url() {
    // Test invalid photo URL
    let request = AddPhotoRequest {
        photo_url: "not-a-url".to_string(),
        is_primary: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("photo_url"));
}

#[test]
fn test_add_photo_request_empty_url() {
    // Test empty photo URL
    let request = AddPhotoRequest {
        photo_url: "".to_string(),
        is_primary: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("photo_url"));
}

#[test]
fn test_add_photo_request_with_primary_flag() {
    // Test photo request with is_primary flag
    let request = AddPhotoRequest {
        photo_url: "https://example.com/photo.jpg".to_string(),
        is_primary: Some(true),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_equipment_request_multiple_invalid_fields() {
    // Test request with multiple invalid fields
    let category_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id,
        title: "".to_string(),
        description: "".to_string(),
        daily_rate: Decimal::from(10),
        condition: "good".to_string(),
        location: "".to_string(),
        coordinates: None,
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("title"));
    assert!(errors.contains_key("description"));
    assert!(errors.contains_key("location"));
}

#[test]
fn test_update_equipment_request_all_fields_valid() {
    // Test update request with all fields set and valid
    let request = UpdateEquipmentRequest {
        title: Some("Updated Title".to_string()),
        description: Some("Updated description with enough characters".to_string()),
        daily_rate: Some(Decimal::from(150)),
        condition: Some("excellent".to_string()),
        location: Some("Updated Location".to_string()),
        coordinates: Some(Coordinates {
            latitude: 40.7128,
            longitude: -74.0060,
        }),
        is_available: Some(true),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_coordinates_edge_cases() {
    // Test various edge cases for coordinates
    let test_cases = vec![
        (-90.0, -180.0), // Minimum latitude and longitude
        (90.0, 180.0),   // Maximum latitude and longitude
        (-90.0, 180.0),  // Min lat, max long
        (90.0, -180.0),  // Max lat, min long
        (0.0, 0.0),      // Equator and prime meridian
    ];

    for (lat, lng) in test_cases {
        let coords = Coordinates {
            latitude: lat,
            longitude: lng,
        };
        assert!(
            coords.validate().is_ok(),
            "Coordinates ({}, {}) should be valid",
            lat,
            lng
        );
    }
}
