use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateEquipmentRequest {
    pub category_id: Uuid,

    #[validate(length(min = 3, max = 200))]
    pub title: String,

    #[validate(length(min = 10))]
    pub description: String,

    pub daily_rate: Decimal,

    #[validate(length(min = 3, max = 32))]
    pub condition: String,

    #[validate(length(min = 2, max = 255))]
    pub location: String,
    pub coordinates: Option<Coordinates>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateEquipmentRequest {
    #[validate(length(min = 3, max = 200))]
    pub title: Option<String>,
    #[validate(length(min = 10))]
    pub description: Option<String>,
    pub daily_rate: Option<Decimal>,
    #[validate(length(min = 3, max = 32))]
    pub condition: Option<String>,
    #[validate(length(min = 2, max = 255))]
    pub location: Option<String>,
    pub coordinates: Option<Coordinates>,
    pub is_available: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct EquipmentQueryParams {
    pub category_id: Option<Uuid>,
    pub min_price: Option<Decimal>,
    pub max_price: Option<Decimal>,
    pub location: Option<String>,
    pub radius_km: Option<f64>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
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
