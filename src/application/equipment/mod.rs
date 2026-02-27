use std::sync::Arc;

use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    AddPhotoRequest, CreateEquipmentRequest, EquipmentPhotoResponse, EquipmentQueryParams,
    EquipmentResponse, PaginatedResponse, UpdateEquipmentRequest,
};
use crate::domain::{Equipment, EquipmentPhoto};
use crate::error::{AppResult, AppError};
use crate::infrastructure::repositories::{
    EquipmentRepository, EquipmentSearchParams, UserRepository,
};

pub mod auth;
pub mod mapper;

#[derive(Clone)]
pub struct EquipmentService {
    user_repo: Arc<dyn UserRepository>,
    equipment_repo: Arc<dyn EquipmentRepository>,
}

impl EquipmentService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        equipment_repo: Arc<dyn EquipmentRepository>,
    ) -> Self {
        Self {
            user_repo,
            equipment_repo,
        }
    }

    pub async fn list(
        &self,
        params: EquipmentQueryParams,
    ) -> AppResult<PaginatedResponse<EquipmentResponse>> {
        let page = params.page.unwrap_or(1).max(1);
        let limit = params.limit.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * limit;

        let search = EquipmentSearchParams {
            category_id: params.category_id,
            min_price: params.min_price,
            max_price: params.max_price,
            latitude: params.lat,
            longitude: params.lng,
            radius_km: params.radius_km,
            is_available: params.is_available,
        };

        let rows = self.equipment_repo.search(&search, limit, offset).await?;
        let total = self.equipment_repo.count_search(&search).await?;
        let total_pages = if total == 0 {
            0
        } else {
            (total + limit - 1) / limit
        };
        let items = rows
            .into_iter()
            .map(mapper::map_equipment_to_response)
            .collect::<Vec<_>>();

        Ok(PaginatedResponse {
            total,
            items,
            page,
            limit,
            total_pages,
        })
    }

    pub async fn get_by_id(&self, id: Uuid) -> AppResult<EquipmentResponse> {
        let equipment = self
            .equipment_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        let photos = self.equipment_repo.find_photos(id).await?;
        Ok(mapper::map_equipment_with_photos_to_response(equipment, photos))
    }

    pub async fn create(
        &self,
        owner_id: Uuid,
        request: CreateEquipmentRequest,
    ) -> AppResult<EquipmentResponse> {
        request.validate()?;

        if request.daily_rate <= Decimal::ZERO {
            return Err(AppError::validation_error(
                "Daily rate must be greater than zero",
            ));
        }

        let condition = mapper::parse_condition(&request.condition)?;
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
            equipment.set_coordinates(coords.latitude, coords.longitude)?;
        }

        let created = self.equipment_repo.create(&equipment).await?;
        Ok(mapper::map_equipment_to_response(created))
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

        auth::check_equipment_access(&*self.user_repo, actor_user_id, existing.owner_id).await?;

        if let Some(title) = request.title {
            existing.title = title;
        }
        if let Some(description) = request.description {
            existing.description = Some(description);
        }
        if let Some(daily_rate) = request.daily_rate {
            if daily_rate <= Decimal::ZERO {
                return Err(AppError::validation_error(
                    "Daily rate must be greater than zero",
                ));
            }
            existing.daily_rate = daily_rate;
        }
        if let Some(condition) = request.condition {
            existing.condition = mapper::parse_condition(&condition)?;
        }
        if let Some(location) = request.location {
            existing.location = Some(location);
        }
        if let Some(is_available) = request.is_available {
            existing.is_available = is_available;
        }
        if let Some(coordinates) = request.coordinates {
            existing.set_coordinates(coordinates.latitude, coordinates.longitude)?;
        }

        let updated = self.equipment_repo.update(&existing).await?;
        Ok(mapper::map_equipment_to_response(updated))
    }

    pub async fn delete(&self, actor_user_id: Uuid, equipment_id: Uuid) -> AppResult<()> {
        let existing = self
            .equipment_repo
            .find_by_id(equipment_id)
            .await?
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))?;

        auth::check_equipment_access(&*self.user_repo, actor_user_id, existing.owner_id).await?;

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

        auth::check_equipment_access(&*self.user_repo, actor_user_id, existing.owner_id).await?;

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

        auth::check_equipment_access(&*self.user_repo, actor_user_id, existing.owner_id).await?;

        self.equipment_repo.delete_photo(photo_id).await
    }
}
