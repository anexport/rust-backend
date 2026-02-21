use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    AddPhotoRequest, CreateEquipmentRequest, EquipmentPhotoResponse, EquipmentQueryParams,
    EquipmentResponse, PaginatedResponse, UpdateEquipmentRequest,
};
use crate::domain::{Condition, Equipment, EquipmentPhoto};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::EquipmentRepository;

#[derive(Clone)]
pub struct EquipmentService {
    equipment_repo: Arc<dyn EquipmentRepository>,
}

impl EquipmentService {
    pub fn new(equipment_repo: Arc<dyn EquipmentRepository>) -> Self {
        Self { equipment_repo }
    }

    pub async fn list(
        &self,
        params: EquipmentQueryParams,
    ) -> AppResult<PaginatedResponse<EquipmentResponse>> {
        let page = params.page.unwrap_or(1).max(1);
        let limit = params.limit.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * limit;

        let rows = self.equipment_repo.find_all(limit, offset).await?;
        let items = rows
            .into_iter()
            .map(|item| EquipmentResponse {
                id: item.id,
                owner_id: item.owner_id,
                category_id: item.category_id,
                title: item.title,
                description: item.description.unwrap_or_default(),
                daily_rate: item.daily_rate,
                condition: condition_as_str(item.condition),
                location: item.location.unwrap_or_default(),
                coordinates: None,
                is_available: item.is_available,
                photos: Vec::new(),
                created_at: item.created_at,
            })
            .collect::<Vec<_>>();

        Ok(PaginatedResponse {
            total: items.len() as i64,
            items,
            page,
            limit,
            total_pages: 1,
        })
    }

    pub async fn get_by_id(&self, id: Uuid) -> AppResult<EquipmentResponse> {
        let equipment = self
            .equipment_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        let photos = self.equipment_repo.find_photos(id).await?;

        Ok(EquipmentResponse {
            id: equipment.id,
            owner_id: equipment.owner_id,
            category_id: equipment.category_id,
            title: equipment.title,
            description: equipment.description.unwrap_or_default(),
            daily_rate: equipment.daily_rate,
            condition: condition_as_str(equipment.condition),
            location: equipment.location.unwrap_or_default(),
            coordinates: None,
            is_available: equipment.is_available,
            photos: photos
                .into_iter()
                .map(|photo| EquipmentPhotoResponse {
                    id: photo.id,
                    photo_url: photo.photo_url,
                    is_primary: photo.is_primary,
                    order_index: photo.order_index,
                })
                .collect(),
            created_at: equipment.created_at,
        })
    }

    pub async fn create(
        &self,
        owner_id: Uuid,
        request: CreateEquipmentRequest,
    ) -> AppResult<EquipmentResponse> {
        request.validate()?;

        let condition = parse_condition(&request.condition)?;
        let now = Utc::now();
        let mut equipment = Equipment {
            id: Uuid::new_v4(),
            owner_id,
            category_id: request.category_id,
            title: request.title,
            description: Some(request.description),
            daily_rate: request.daily_rate,
            condition,
            location: Some(request.location),
            coordinates: None,
            is_available: true,
            created_at: now,
            updated_at: now,
        };

        if let Some(coords) = request.coordinates {
            equipment.set_coordinates(coords.latitude, coords.longitude);
        }

        let created = self.equipment_repo.create(&equipment).await?;

        Ok(EquipmentResponse {
            id: created.id,
            owner_id: created.owner_id,
            category_id: created.category_id,
            title: created.title,
            description: created.description.unwrap_or_default(),
            daily_rate: created.daily_rate,
            condition: condition_as_str(created.condition),
            location: created.location.unwrap_or_default(),
            coordinates: None,
            is_available: created.is_available,
            photos: Vec::new(),
            created_at: created.created_at,
        })
    }

    pub async fn update(
        &self,
        actor_user_id: Uuid,
        equipment_id: Uuid,
        request: UpdateEquipmentRequest,
    ) -> AppResult<EquipmentResponse> {
        request.validate()?;

        let mut existing = self
            .equipment_repo
            .find_by_id(equipment_id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        if existing.owner_id != actor_user_id {
            return Err(AppError::Forbidden("not equipment owner".to_string()));
        }

        if let Some(title) = request.title {
            existing.title = title;
        }
        if let Some(description) = request.description {
            existing.description = Some(description);
        }
        if let Some(daily_rate) = request.daily_rate {
            existing.daily_rate = daily_rate;
        }
        if let Some(condition) = request.condition {
            existing.condition = parse_condition(&condition)?;
        }
        if let Some(location) = request.location {
            existing.location = Some(location);
        }
        if let Some(is_available) = request.is_available {
            existing.is_available = is_available;
        }
        if let Some(coordinates) = request.coordinates {
            existing.set_coordinates(coordinates.latitude, coordinates.longitude);
        }

        let updated = self.equipment_repo.update(&existing).await?;
        Ok(EquipmentResponse {
            id: updated.id,
            owner_id: updated.owner_id,
            category_id: updated.category_id,
            title: updated.title,
            description: updated.description.unwrap_or_default(),
            daily_rate: updated.daily_rate,
            condition: condition_as_str(updated.condition),
            location: updated.location.unwrap_or_default(),
            coordinates: None,
            is_available: updated.is_available,
            photos: Vec::new(),
            created_at: updated.created_at,
        })
    }

    pub async fn delete(&self, actor_user_id: Uuid, equipment_id: Uuid) -> AppResult<()> {
        let existing = self
            .equipment_repo
            .find_by_id(equipment_id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        if existing.owner_id != actor_user_id {
            return Err(AppError::Forbidden("not equipment owner".to_string()));
        }

        self.equipment_repo.delete(equipment_id).await
    }

    pub async fn add_photo(
        &self,
        actor_user_id: Uuid,
        equipment_id: Uuid,
        request: AddPhotoRequest,
    ) -> AppResult<EquipmentPhotoResponse> {
        request.validate()?;

        let existing = self
            .equipment_repo
            .find_by_id(equipment_id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        if existing.owner_id != actor_user_id {
            return Err(AppError::Forbidden("not equipment owner".to_string()));
        }

        let photos = self.equipment_repo.find_photos(equipment_id).await?;
        let photo = EquipmentPhoto {
            id: Uuid::new_v4(),
            equipment_id,
            photo_url: request.photo_url,
            is_primary: request.is_primary.unwrap_or(false),
            order_index: photos.len() as i32,
            created_at: Utc::now(),
        };

        let created = self.equipment_repo.add_photo(&photo).await?;
        Ok(EquipmentPhotoResponse {
            id: created.id,
            photo_url: created.photo_url,
            is_primary: created.is_primary,
            order_index: created.order_index,
        })
    }

    pub async fn delete_photo(
        &self,
        actor_user_id: Uuid,
        equipment_id: Uuid,
        photo_id: Uuid,
    ) -> AppResult<()> {
        let existing = self
            .equipment_repo
            .find_by_id(equipment_id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        if existing.owner_id != actor_user_id {
            return Err(AppError::Forbidden("not equipment owner".to_string()));
        }

        self.equipment_repo.delete_photo(photo_id).await
    }
}

fn parse_condition(raw: &str) -> AppResult<Condition> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "new" => Ok(Condition::New),
        "excellent" => Ok(Condition::Excellent),
        "good" => Ok(Condition::Good),
        "fair" => Ok(Condition::Fair),
        _ => Err(AppError::ValidationError("invalid condition".to_string())),
    }
}

fn condition_as_str(condition: Condition) -> String {
    match condition {
        Condition::New => "new".to_string(),
        Condition::Excellent => "excellent".to_string(),
        Condition::Good => "good".to_string(),
        Condition::Fair => "fair".to_string(),
    }
}
