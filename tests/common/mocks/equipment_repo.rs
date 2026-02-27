use super::utils::haversine_km;
use async_trait::async_trait;
use rust_backend::domain::{Equipment, EquipmentPhoto};
use rust_backend::error::AppResult;
use rust_backend::infrastructure::repositories::{EquipmentRepository, EquipmentSearchParams};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct MockEquipmentRepo {
    pub equipment: Mutex<Vec<Equipment>>,
    pub photos: Mutex<Vec<EquipmentPhoto>>,
}

impl MockEquipmentRepo {
    pub fn push(&self, equipment: Equipment) {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .push(equipment);
    }

    pub fn push_photo(&self, photo: EquipmentPhoto) {
        self.photos
            .lock()
            .expect("photos mutex poisoned")
            .push(photo);
    }
}

#[async_trait]
impl EquipmentRepository for MockEquipmentRepo {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .find(|equipment| equipment.id == id)
            .cloned())
    }

    async fn find_all(&self, limit: i64, offset: i64) -> AppResult<Vec<Equipment>> {
        let rows = self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone();

        let start = offset.max(0) as usize;
        let limit = limit.max(0) as usize;
        Ok(rows.into_iter().skip(start).take(limit).collect())
    }

    async fn search(
        &self,
        params: &EquipmentSearchParams,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        let mut rows: Vec<Equipment> = self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone()
            .into_iter()
            .filter(|item| {
                params
                    .category_id
                    .is_none_or(|category_id| item.category_id == category_id)
            })
            .filter(|item| params.min_price.is_none_or(|min| item.daily_rate >= min))
            .filter(|item| params.max_price.is_none_or(|max| item.daily_rate <= max))
            .filter(|item| {
                params
                    .is_available
                    .is_none_or(|available| item.is_available == available)
            })
            .collect();

        if let Some(((lat, lng), radius_km)) =
            params.latitude.zip(params.longitude).zip(params.radius_km)
        {
            rows.retain(|item| {
                item.coordinates_tuple()
                    .is_some_and(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng) <= radius_km)
            });
            rows.sort_by(|left, right| {
                let left_distance = left
                    .coordinates_tuple()
                    .map(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng))
                    .unwrap_or(f64::MAX);
                let right_distance = right
                    .coordinates_tuple()
                    .map(|(ilat, ilng)| haversine_km(lat, lng, ilat, ilng))
                    .unwrap_or(f64::MAX);
                left_distance.total_cmp(&right_distance)
            });
        }

        let start = offset.max(0) as usize;
        let limit = limit.max(0) as usize;
        Ok(rows.into_iter().skip(start).take(limit).collect())
    }

    async fn find_by_owner(
        &self,
        owner_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        let rows: Vec<Equipment> = self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .filter(|equipment| equipment.owner_id == owner_id)
            .cloned()
            .collect();

        let start = offset.max(0) as usize;
        let limit = limit.max(0) as usize;
        Ok(rows.into_iter().skip(start).take(limit).collect())
    }

    async fn count_by_owner(&self, owner_id: Uuid) -> AppResult<i64> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .filter(|equipment| equipment.owner_id == owner_id)
            .count() as i64)
    }

    async fn create(&self, equipment: &Equipment) -> AppResult<Equipment> {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .push(equipment.clone());
        Ok(equipment.clone())
    }

    async fn update(&self, equipment: &Equipment) -> AppResult<Equipment> {
        let mut rows = self.equipment.lock().expect("equipment mutex poisoned");
        if let Some(existing) = rows.iter_mut().find(|existing| existing.id == equipment.id) {
            *existing = equipment.clone();
            Ok(equipment.clone())
        } else {
            Err(rust_backend::error::AppError::NotFound(
                "equipment not found".to_string(),
            ))
        }
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .retain(|equipment| equipment.id != id);
        Ok(())
    }

    async fn add_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        self.photos
            .lock()
            .expect("photos mutex poisoned")
            .push(photo.clone());
        Ok(photo.clone())
    }

    async fn find_photos(&self, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        Ok(self
            .photos
            .lock()
            .expect("photos mutex poisoned")
            .iter()
            .filter(|photo| photo.equipment_id == equipment_id)
            .cloned()
            .collect())
    }

    async fn find_photo_by_id(&self, photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>> {
        Ok(self
            .photos
            .lock()
            .expect("photos mutex poisoned")
            .iter()
            .find(|photo| photo.id == photo_id)
            .cloned())
    }

    async fn update_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        let mut photos = self.photos.lock().expect("photos mutex poisoned");
        if let Some(existing) = photos.iter_mut().find(|p| p.id == photo.id) {
            *existing = photo.clone();
            Ok(photo.clone())
        } else {
            Err(rust_backend::error::AppError::NotFound(
                "photo not found".to_string(),
            ))
        }
    }

    async fn delete_photo(&self, photo_id: Uuid) -> AppResult<()> {
        self.photos
            .lock()
            .expect("photos mutex poisoned")
            .retain(|photo| photo.id != photo_id);
        Ok(())
    }
}
