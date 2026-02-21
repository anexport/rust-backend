use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "condition", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    New,
    Excellent,
    Good,
    Fair,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Equipment {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub category_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub daily_rate: Decimal,
    pub condition: Condition,
    pub location: Option<String>,
    pub coordinates: Option<String>,
    pub is_available: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Equipment {
    pub fn coordinates_tuple(&self) -> Option<(f64, f64)> {
        self.coordinates.as_ref().and_then(|c| {
            let parts: Vec<&str> = c.split(',').collect();
            if parts.len() == 2 {
                let lat = parts[0].trim().parse::<f64>().ok()?;
                let lng = parts[1].trim().parse::<f64>().ok()?;
                Some((lat, lng))
            } else {
                None
            }
        })
    }

    pub fn set_coordinates(&mut self, lat: f64, lng: f64) {
        self.coordinates = Some(format!("{}, {}", lat, lng));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EquipmentPhoto {
    pub id: Uuid,
    pub equipment_id: Uuid,
    pub photo_url: String,
    pub is_primary: bool,
    pub order_index: i32,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_equipment() -> Equipment {
        Equipment {
            id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            category_id: Uuid::new_v4(),
            title: "Test Equipment".to_string(),
            description: None,
            daily_rate: Decimal::new(1000, 2),
            condition: Condition::Good,
            location: None,
            coordinates: None,
            is_available: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn condition_serializes_to_lowercase() {
        assert_eq!(serde_json::to_string(&Condition::New).unwrap(), "\"new\"");
        assert_eq!(
            serde_json::to_string(&Condition::Excellent).unwrap(),
            "\"excellent\""
        );
        assert_eq!(serde_json::to_string(&Condition::Good).unwrap(), "\"good\"");
        assert_eq!(serde_json::to_string(&Condition::Fair).unwrap(), "\"fair\"");
    }

    #[test]
    fn condition_deserializes_from_lowercase() {
        assert_eq!(
            serde_json::from_str::<Condition>("\"new\"").unwrap(),
            Condition::New
        );
        assert_eq!(
            serde_json::from_str::<Condition>("\"excellent\"").unwrap(),
            Condition::Excellent
        );
        assert_eq!(
            serde_json::from_str::<Condition>("\"good\"").unwrap(),
            Condition::Good
        );
        assert_eq!(
            serde_json::from_str::<Condition>("\"fair\"").unwrap(),
            Condition::Fair
        );
    }

    #[test]
    fn coordinates_tuple_returns_none_when_coordinates_is_none() {
        let equipment = create_test_equipment();
        assert!(equipment.coordinates_tuple().is_none());
    }

    #[test]
    fn coordinates_tuple_parses_valid_string() {
        let mut equipment = create_test_equipment();
        equipment.coordinates = Some("40.7128, -74.0060".to_string());
        let result = equipment.coordinates_tuple();
        assert!(result.is_some());
        let (lat, lng) = result.unwrap();
        assert!((lat - 40.7128).abs() < 0.0001);
        assert!((lng - (-74.0060)).abs() < 0.0001);
    }

    #[test]
    fn coordinates_tuple_parses_without_extra_spaces() {
        let mut equipment = create_test_equipment();
        equipment.coordinates = Some("40.7128,-74.0060".to_string());
        let result = equipment.coordinates_tuple();
        assert!(result.is_some());
        let (lat, lng) = result.unwrap();
        assert!((lat - 40.7128).abs() < 0.0001);
        assert!((lng - (-74.0060)).abs() < 0.0001);
    }

    #[test]
    fn coordinates_tuple_returns_none_for_invalid_format() {
        let mut equipment = create_test_equipment();
        equipment.coordinates = Some("invalid".to_string());
        assert!(equipment.coordinates_tuple().is_none());

        equipment.coordinates = Some("40.7128".to_string());
        assert!(equipment.coordinates_tuple().is_none());

        equipment.coordinates = Some("40.7128, -74.0060, 100".to_string());
        assert!(equipment.coordinates_tuple().is_none());

        equipment.coordinates = Some("abc, def".to_string());
        assert!(equipment.coordinates_tuple().is_none());
    }

    #[test]
    fn set_coordinates_sets_string_correctly() {
        let mut equipment = create_test_equipment();
        equipment.set_coordinates(40.7128, -74.0060);
        assert!(equipment.coordinates.is_some());
        let result = equipment.coordinates_tuple();
        assert!(result.is_some());
        let (lat, lng) = result.unwrap();
        assert!((lat - 40.7128).abs() < 0.0001);
        assert!((lng - (-74.0060)).abs() < 0.0001);
    }

    #[test]
    fn set_coordinates_overwrites_existing() {
        let mut equipment = create_test_equipment();
        equipment.coordinates = Some("1.0, 2.0".to_string());
        equipment.set_coordinates(40.7128, -74.0060);
        let (lat, lng) = equipment.coordinates_tuple().unwrap();
        assert!((lat - 40.7128).abs() < 0.0001);
        assert!((lng - (-74.0060)).abs() < 0.0001);
    }
}
