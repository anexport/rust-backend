use chrono::Utc;
use rust_backend::api::dtos::EquipmentResponse;
use rust_backend::application::{
    map_coordinates, map_equipment_to_response, map_equipment_with_photos_to_response,
    parse_condition,
};
use rust_backend::domain::{Condition, Equipment, EquipmentPhoto};
use rust_backend::error::AppError;
use rust_decimal::Decimal;
use uuid::Uuid;

fn test_equipment(id: Uuid) -> Equipment {
    Equipment {
        id,
        owner_id: Uuid::new_v4(),
        category_id: Uuid::new_v4(),
        title: "Test Equipment".to_string(),
        description: Some("Test Description".to_string()),
        daily_rate: Decimal::new(1000, 2),
        condition: Condition::Good,
        location: Some("Test Location".to_string()),
        coordinates: None,
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// parse_condition tests

#[test]
fn parse_condition_accepts_new() {
    let result = parse_condition("new").unwrap();
    assert_eq!(result, Condition::New);
}

#[test]
fn parse_condition_accepts_excellent() {
    let result = parse_condition("excellent").unwrap();
    assert_eq!(result, Condition::Excellent);
}

#[test]
fn parse_condition_accepts_good() {
    let result = parse_condition("good").unwrap();
    assert_eq!(result, Condition::Good);
}

#[test]
fn parse_condition_accepts_fair() {
    let result = parse_condition("fair").unwrap();
    assert_eq!(result, Condition::Fair);
}

#[test]
fn parse_condition_handles_uppercase() {
    let result = parse_condition("NEW").unwrap();
    assert_eq!(result, Condition::New);
}

#[test]
fn parse_condition_handles_mixed_case() {
    let result = parse_condition("ExcelLeNt").unwrap();
    assert_eq!(result, Condition::Excellent);
}

#[test]
fn parse_condition_trims_whitespace() {
    let result = parse_condition("  good  ").unwrap();
    assert_eq!(result, Condition::Good);
}

#[test]
fn parse_condition_rejects_invalid() {
    let result = parse_condition("broken");
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
    if let Err(AppError::ValidationError { message, .. }) = result {
        assert!(message.contains("Condition must be one of"));
        assert!(message.contains("new"));
        assert!(message.contains("excellent"));
        assert!(message.contains("good"));
        assert!(message.contains("fair"));
    }
}

#[test]
fn parse_condition_rejects_empty_string() {
    let result = parse_condition("");
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
}

#[test]
fn parse_condition_rejects_whitespace_only() {
    let result = parse_condition("   ");
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
}

// map_coordinates tests

#[test]
fn map_coordinates_returns_none_when_no_coordinates() {
    let equipment = test_equipment(Uuid::new_v4());
    assert_eq!(equipment.coordinates, None);

    let result = map_coordinates(&equipment);
    assert!(result.is_none());
}

#[test]
fn map_coordinates_maps_valid_coordinates() {
    let mut equipment = test_equipment(Uuid::new_v4());
    equipment.set_coordinates(40.7128, -74.0060).unwrap();

    let result = map_coordinates(&equipment);

    assert!(result.is_some());
    let coords = result.unwrap();
    assert!((coords.latitude - 40.7128).abs() < 0.0001);
    assert!((coords.longitude - (-74.0060)).abs() < 0.0001);
}

#[test]
fn map_coordinates_handles_negative_coordinates() {
    let mut equipment = test_equipment(Uuid::new_v4());
    equipment.set_coordinates(-33.8688, 151.2093).unwrap(); // Sydney

    let result = map_coordinates(&equipment);

    assert!(result.is_some());
    let coords = result.unwrap();
    assert!((coords.latitude - (-33.8688)).abs() < 0.0001);
    assert!((coords.longitude - 151.2093).abs() < 0.0001);
}

#[test]
fn map_coordinates_handles_zero_coordinates() {
    let mut equipment = test_equipment(Uuid::new_v4());
    equipment.set_coordinates(0.0, 0.0).unwrap(); // Null Island

    let result = map_coordinates(&equipment);

    assert!(result.is_some());
    let coords = result.unwrap();
    assert_eq!(coords.latitude, 0.0);
    assert_eq!(coords.longitude, 0.0);
}

#[test]
fn map_coordinates_handles_equator_and_prime_meridian() {
    let mut equipment = test_equipment(Uuid::new_v4());
    equipment.set_coordinates(0.0, 0.0).unwrap();

    let result = map_coordinates(&equipment);

    assert!(result.is_some());
    let coords = result.unwrap();
    assert_eq!(coords.latitude, 0.0);
    assert_eq!(coords.longitude, 0.0);
}

#[test]
fn map_coordinates_handles_boundary_values() {
    let mut equipment = test_equipment(Uuid::new_v4());

    // Max latitude (North Pole)
    equipment.set_coordinates(90.0, 0.0).unwrap();
    let result = map_coordinates(&equipment);
    assert_eq!(result.unwrap().latitude, 90.0);

    // Min latitude (South Pole)
    equipment.set_coordinates(-90.0, 0.0).unwrap();
    let result = map_coordinates(&equipment);
    assert_eq!(result.unwrap().latitude, -90.0);

    // Max longitude (International Date Line)
    equipment.set_coordinates(0.0, 180.0).unwrap();
    let result = map_coordinates(&equipment);
    assert_eq!(result.unwrap().longitude, 180.0);

    // Min longitude
    equipment.set_coordinates(0.0, -180.0).unwrap();
    let result = map_coordinates(&equipment);
    assert_eq!(result.unwrap().longitude, -180.0);
}

// map_equipment_to_response tests

#[test]
fn map_equipment_to_response_maps_all_fields() {
    let id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();
    let created_at = Utc::now();

    let mut equipment = Equipment {
        id,
        owner_id,
        category_id,
        title: "Camera Equipment".to_string(),
        description: Some("Professional camera".to_string()),
        daily_rate: Decimal::new(5000, 2),
        condition: Condition::Excellent,
        location: Some("New York".to_string()),
        coordinates: None,
        is_available: true,
        created_at,
        updated_at: created_at,
    };
    equipment.set_coordinates(40.7128, -74.0060).unwrap();

    let response: EquipmentResponse = map_equipment_to_response(equipment);

    assert_eq!(response.id, id);
    assert_eq!(response.owner_id, owner_id);
    assert_eq!(response.category_id, category_id);
    assert_eq!(response.title, "Camera Equipment");
    assert_eq!(response.description, "Professional camera");
    assert_eq!(response.daily_rate, Decimal::new(5000, 2));
    assert_eq!(response.condition, "excellent");
    assert_eq!(response.location, "New York");
    assert!(response.coordinates.is_some());
    assert!(response.is_available);
    assert_eq!(response.photos.len(), 0);
    assert_eq!(response.created_at, created_at);
}

#[test]
fn map_equipment_to_response_handles_none_description() {
    let id = Uuid::new_v4();
    let equipment = {
        let mut e = test_equipment(id);
        e.description = None;
        e
    };

    let response: EquipmentResponse = map_equipment_to_response(equipment);

    assert_eq!(response.description, "");
}

#[test]
fn map_equipment_to_response_handles_none_location() {
    let id = Uuid::new_v4();
    let equipment = {
        let mut e = test_equipment(id);
        e.location = None;
        e
    };

    let response: EquipmentResponse = map_equipment_to_response(equipment);

    assert_eq!(response.location, "");
}

#[test]
fn map_equipment_to_response_handles_none_coordinates() {
    let id = Uuid::new_v4();
    let equipment = test_equipment(id);

    let response: EquipmentResponse = map_equipment_to_response(equipment);

    assert!(response.coordinates.is_none());
}

#[test]
fn map_equipment_to_response_condition_string_conversion() {
    let test_cases = vec![
        (Condition::New, "new"),
        (Condition::Excellent, "excellent"),
        (Condition::Good, "good"),
        (Condition::Fair, "fair"),
    ];

    for (condition, expected_string) in test_cases {
        let equipment = {
            let mut e = test_equipment(Uuid::new_v4());
            e.condition = condition;
            e
        };
        let response: EquipmentResponse = map_equipment_to_response(equipment);
        assert_eq!(response.condition, expected_string);
    }
}

#[test]
fn map_equipment_to_response_sets_empty_photos() {
    let equipment = test_equipment(Uuid::new_v4());

    let response: EquipmentResponse = map_equipment_to_response(equipment);

    assert_eq!(response.photos.len(), 0);
}

// map_equipment_with_photos_to_response tests

#[test]
fn map_equipment_with_photos_to_response_maps_photos() {
    let equipment_id = Uuid::new_v4();
    let equipment = test_equipment(equipment_id);

    let photo1_id = Uuid::new_v4();
    let photo2_id = Uuid::new_v4();
    let created_at = Utc::now();

    let photos = vec![
        EquipmentPhoto {
            id: photo1_id,
            equipment_id,
            photo_url: "https://example.com/photo1.jpg".to_string(),
            is_primary: true,
            order_index: 0,
            created_at,
        },
        EquipmentPhoto {
            id: photo2_id,
            equipment_id,
            photo_url: "https://example.com/photo2.jpg".to_string(),
            is_primary: false,
            order_index: 1,
            created_at,
        },
    ];

    let response: EquipmentResponse = map_equipment_with_photos_to_response(equipment, photos);

    assert_eq!(response.photos.len(), 2);
    assert_eq!(response.photos[0].id, photo1_id);
    assert_eq!(
        response.photos[0].photo_url,
        "https://example.com/photo1.jpg"
    );
    assert!(response.photos[0].is_primary);
    assert_eq!(response.photos[0].order_index, 0);
    assert_eq!(response.photos[1].id, photo2_id);
    assert_eq!(
        response.photos[1].photo_url,
        "https://example.com/photo2.jpg"
    );
    assert!(!response.photos[1].is_primary);
    assert_eq!(response.photos[1].order_index, 1);
}

#[test]
fn map_equipment_with_photos_to_response_handles_empty_photos() {
    let equipment = test_equipment(Uuid::new_v4());
    let photos: Vec<EquipmentPhoto> = vec![];

    let response: EquipmentResponse = map_equipment_with_photos_to_response(equipment, photos);

    assert!(response.photos.is_empty());
}

#[test]
fn map_equipment_with_photos_to_response_maps_equipment_fields() {
    let equipment_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let category_id = Uuid::new_v4();

    let equipment = Equipment {
        id: equipment_id,
        owner_id,
        category_id,
        title: "Test Item".to_string(),
        description: Some("Description".to_string()),
        daily_rate: Decimal::new(2000, 2),
        condition: Condition::Good,
        location: Some("Location".to_string()),
        coordinates: None,
        is_available: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let response: EquipmentResponse = map_equipment_with_photos_to_response(equipment, vec![]);

    assert_eq!(response.id, equipment_id);
    assert_eq!(response.owner_id, owner_id);
    assert_eq!(response.category_id, category_id);
    assert_eq!(response.title, "Test Item");
    assert_eq!(response.description, "Description");
    assert_eq!(response.daily_rate, Decimal::new(2000, 2));
    assert_eq!(response.condition, "good");
    assert_eq!(response.location, "Location");
    assert!(!response.is_available);
}

#[test]
fn map_equipment_with_photos_to_response_preserves_coordinates() {
    let equipment_id = Uuid::new_v4();
    let equipment = test_equipment(equipment_id);

    let response: EquipmentResponse = map_equipment_with_photos_to_response(equipment, vec![]);

    // Equipment created by test_equipment has no coordinates
    assert!(response.coordinates.is_none());
}

#[test]
fn map_equipment_with_photos_to_response_primary_flag_preserved() {
    let equipment_id = Uuid::new_v4();
    let equipment = test_equipment(equipment_id);

    let photos = vec![
        EquipmentPhoto {
            id: Uuid::new_v4(),
            equipment_id,
            photo_url: "https://example.com/1.jpg".to_string(),
            is_primary: false,
            order_index: 0,
            created_at: Utc::now(),
        },
        EquipmentPhoto {
            id: Uuid::new_v4(),
            equipment_id,
            photo_url: "https://example.com/2.jpg".to_string(),
            is_primary: true,
            order_index: 1,
            created_at: Utc::now(),
        },
    ];

    let response: EquipmentResponse = map_equipment_with_photos_to_response(equipment, photos);

    assert!(!response.photos[0].is_primary);
    assert!(response.photos[1].is_primary);
}
