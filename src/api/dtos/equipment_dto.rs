use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate, ToSchema)]
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

#[derive(Debug, Deserialize, Serialize, Validate, ToSchema)]
pub struct Coordinates {
    #[validate(range(min = -90.0, max = 90.0, message = "Latitude must be between -90 and 90"))]
    pub latitude: f64,
    #[validate(range(min = -180.0, max = 180.0, message = "Longitude must be between -180 and 180"))]
    pub longitude: f64,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
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

#[derive(Debug, Deserialize, Validate, ToSchema, IntoParams)]
pub struct EquipmentQueryParams {
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub category_id: Option<Uuid>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub min_price: Option<Decimal>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub max_price: Option<Decimal>,
    #[serde(
        default,
        alias = "latitude",
        deserialize_with = "deserialize_optional_query_value"
    )]
    pub lat: Option<f64>,
    #[serde(
        default,
        alias = "longitude",
        deserialize_with = "deserialize_optional_query_value"
    )]
    pub lng: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub radius_km: Option<f64>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub is_available: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub page: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_optional_query_value")]
    pub limit: Option<i64>,
}

fn deserialize_optional_query_value<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = Option::<String>::deserialize(deserializer)?;
    let Some(value) = raw else {
        return Ok(None);
    };

    let normalized = value.trim();
    if normalized.is_empty()
        || normalized.eq_ignore_ascii_case("undefined")
        || normalized.eq_ignore_ascii_case("null")
    {
        return Ok(None);
    }

    normalized
        .parse::<T>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Serialize, ToSchema)]
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

#[derive(Debug, Serialize, ToSchema)]
pub struct EquipmentPhotoResponse {
    pub id: Uuid,
    pub photo_url: String,
    pub is_primary: bool,
    pub order_index: i32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
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

// Alias for OpenAPI compatibility
pub type EquipmentDto = EquipmentResponse;
