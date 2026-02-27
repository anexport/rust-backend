use std::sync::Arc;

use tracing::info;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    EquipmentResponse, PaginatedResponse, PublicProfileResponse, UpdateUserRequest,
    UserProfileResponse,
};
use crate::domain::{Role, User};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{EquipmentRepository, UserRepository};

#[derive(Clone)]
pub struct UserService {
    user_repo: Arc<dyn UserRepository>,
    equipment_repo: Arc<dyn EquipmentRepository>,
}

impl UserService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        equipment_repo: Arc<dyn EquipmentRepository>,
    ) -> Self {
        Self {
            user_repo,
            equipment_repo,
        }
    }

    pub async fn get_public_profile(&self, id: Uuid) -> AppResult<PublicProfileResponse> {
        let user = self
            .user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        Ok(PublicProfileResponse {
            id: user.id,
            username: user.username,
            avatar_url: user.avatar_url,
        })
    }

    pub async fn get_profile(&self, id: Uuid) -> AppResult<UserProfileResponse> {
        let user = self
            .user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        Ok(map_profile(user))
    }

    pub async fn update_profile(
        &self,
        actor_user_id: Uuid,
        target_user_id: Uuid,
        request: UpdateUserRequest,
    ) -> AppResult<UserProfileResponse> {
        request.validate()?;

        let mut user = self
            .user_repo
            .find_by_id(target_user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        if actor_user_id != target_user_id {
            let actor = self
                .user_repo
                .find_by_id(actor_user_id)
                .await?
                .ok_or(AppError::Unauthorized)?;
            if actor.role != Role::Admin {
                return Err(AppError::Forbidden(
                    "You can only modify your own profile".to_string(),
                ));
            }
            info!(
                actor_user_id = %actor_user_id,
                target_user_id = %target_user_id,
                "admin updated another user profile"
            );
        }

        if let Some(username) = request.username {
            user.username = Some(username);
        }
        if let Some(full_name) = request.full_name {
            user.full_name = Some(full_name);
        }
        if let Some(avatar_url) = request.avatar_url {
            user.avatar_url = Some(avatar_url);
        }

        let updated = self.user_repo.update(&user).await?;
        Ok(map_profile(updated))
    }

    pub async fn my_equipment(
        &self,
        user_id: Uuid,
        page: i64,
        limit: i64,
    ) -> AppResult<PaginatedResponse<EquipmentResponse>> {
        let page = page.max(1);
        let limit = limit.clamp(1, 100);
        let offset = (page - 1) * limit;

        let total = self.equipment_repo.count_by_owner(user_id).await?;
        let total_pages = if total == 0 {
            0
        } else {
            (total + limit - 1) / limit
        };

        let equipment = self
            .equipment_repo
            .find_by_owner(user_id, limit, offset)
            .await?;

        let items = equipment
            .into_iter()
            .map(|e| {
                let coordinates = e.coordinates_tuple().map(|(latitude, longitude)| {
                    crate::api::dtos::Coordinates {
                        latitude,
                        longitude,
                    }
                });
                EquipmentResponse {
                    id: e.id,
                    owner_id: e.owner_id,
                    category_id: e.category_id,
                    title: e.title,
                    description: e.description.unwrap_or_default(),
                    daily_rate: e.daily_rate,
                    condition: e.condition.to_string(),
                    location: e.location.unwrap_or_default(),
                    coordinates,
                    is_available: e.is_available,
                    photos: Vec::new(),
                    created_at: e.created_at,
                }
            })
            .collect();

        Ok(PaginatedResponse {
            items,
            total,
            page,
            limit,
            total_pages,
        })
    }
}

fn map_profile(user: User) -> UserProfileResponse {
    UserProfileResponse {
        id: user.id,
        email: user.email,
        role: user.role.to_string(),
        username: user.username,
        full_name: user.full_name,
        avatar_url: user.avatar_url,
        created_at: user.created_at,
    }
}
