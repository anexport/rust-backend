use crate::api::dtos::{Coordinates, EquipmentPhotoResponse, EquipmentResponse};
use crate::domain::{Condition, Equipment};
use crate::error::{AppError, AppResult};

pub fn parse_condition(raw: &str) -> AppResult<Condition> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "new" => Ok(Condition::New),
        "excellent" => Ok(Condition::Excellent),
        "good" => Ok(Condition::Good),
        "fair" => Ok(Condition::Fair),
        _ => Err(AppError::validation_error(
            "Condition must be one of: new, excellent, good, fair",
        )),
    }
}

pub fn map_coordinates(equipment: &Equipment) -> Option<Coordinates> {
    equipment
        .coordinates_tuple()
        .map(|(latitude, longitude)| Coordinates {
            latitude,
            longitude,
        })
}

pub fn map_equipment_to_response(equipment: Equipment) -> EquipmentResponse {
    let coordinates = map_coordinates(&equipment);
    EquipmentResponse {
        id: equipment.id,
        owner_id: equipment.owner_id,
        category_id: equipment.category_id,
        title: equipment.title,
        description: equipment.description.unwrap_or_default(),
        daily_rate: equipment.daily_rate,
        condition: equipment.condition.to_string(),
        location: equipment.location.unwrap_or_default(),
        coordinates,
        is_available: equipment.is_available,
        photos: Vec::new(),
        created_at: equipment.created_at,
    }
}

pub fn map_equipment_with_photos_to_response(
    equipment: Equipment,
    photos: Vec<crate::domain::EquipmentPhoto>,
) -> EquipmentResponse {
    let mut response = map_equipment_to_response(equipment);
    response.photos = photos
        .into_iter()
        .map(|photo| EquipmentPhotoResponse {
            id: photo.id,
            photo_url: photo.photo_url,
            is_primary: photo.is_primary,
            order_index: photo.order_index,
        })
        .collect();
    response
}
