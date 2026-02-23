use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateEquipmentRequest {
    pub category_id: Uuid,

    #[validate(length(
        min = 3,
        max = 200,
        message = "Title must be between 3 and 200 characters"
    ))]
    pub title: String,

    #[validate(length(min = 10, message = "Description must be at least 10 characters"))]
    pub description: String,

    pub daily_rate: Decimal,

    pub condition: String,

    #[validate(length(
        min = 2,
        max = 255,
        message = "Location must be between 2 and 255 characters"
    ))]
    pub location: String,

    #[validate(nested)]
    pub coordinates: Option<Coordinates>,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct Coordinates {
    #[validate(range(min = -90.0, max = 90.0, message = "Latitude must be between -90 and 90"))]
    pub latitude: f64,
    #[validate(range(min = -180.0, max = 180.0, message = "Longitude must be between -180 and 180"))]
    pub longitude: f64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateEquipmentRequest {
    #[validate(length(
        min = 3,
        max = 200,
        message = "Title must be between 3 and 200 characters"
    ))]
    pub title: Option<String>,

    #[validate(length(min = 10, message = "Description must be at least 10 characters"))]
    pub description: Option<String>,

    pub daily_rate: Option<Decimal>,

    pub condition: Option<String>,

    #[validate(length(
        min = 2,
        max = 255,
        message = "Location must be between 2 and 255 characters"
    ))]
    pub location: Option<String>,

    #[validate(nested)]
    pub coordinates: Option<Coordinates>,

    pub is_available: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct EquipmentQueryParams {
    pub category_id: Option<Uuid>,
    pub min_price: Option<Decimal>,
    pub max_price: Option<Decimal>,
    #[serde(alias = "latitude")]
    pub lat: Option<f64>,
    #[serde(alias = "longitude")]
    pub lng: Option<f64>,
    pub radius_km: Option<f64>,
    pub is_available: Option<bool>,
    pub page: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct EquipmentResponse {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub category_id: Uuid,
    pub title: String,
    pub description: String,
    pub daily_rate: Decimal,
    pub condition: String,
    pub location: String,
    pub coordinates: Option<Coordinates>,
    pub is_available: bool,
    pub photos: Vec<EquipmentPhotoResponse>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EquipmentPhotoResponse {
    pub id: Uuid,
    pub photo_url: String,
    pub is_primary: bool,
    pub order_index: i32,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AddPhotoRequest {
    #[validate(url)]
    pub photo_url: String,
    pub is_primary: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
    pub total_pages: i64,
}
