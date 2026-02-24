use std::sync::Arc;

use chrono::Utc;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    AdminCategoryRequest, AdminCategoryResponse, AdminEquipmentListResponse, AdminEquipmentRow,
    AdminStatsResponse, AdminUpdateRoleRequest, AdminUserDetailResponse, AdminUserListResponse,
    AdminUserRow,
};
use crate::domain::{Category, Role, User};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{
    CategoryRepository, EquipmentRepository, EquipmentSearchParams, UserRepository,
};

#[derive(Clone)]
pub struct AdminService {
    user_repo: Arc<dyn UserRepository>,
    equipment_repo: Arc<dyn EquipmentRepository>,
    category_repo: Arc<dyn CategoryRepository>,
}

impl AdminService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        equipment_repo: Arc<dyn EquipmentRepository>,
        category_repo: Arc<dyn CategoryRepository>,
    ) -> Self {
        Self {
            user_repo,
            equipment_repo,
            category_repo,
        }
    }

    pub async fn get_stats(&self) -> AppResult<AdminStatsResponse> {
        let total_users = self.user_repo.count_all(None, None).await?;
        let total_equipment = self.equipment_repo.count_all(None).await?;
        let available_equipment = self
            .equipment_repo
            .count_search(&EquipmentSearchParams {
                is_available: Some(true),
                ..EquipmentSearchParams::default()
            })
            .await?;
        let total_categories = self.category_repo.count_all().await?;

        Ok(AdminStatsResponse {
            total_users,
            total_equipment,
            available_equipment,
            total_categories,
        })
    }

    pub async fn list_users(
        &self,
        page: i64,
        per_page: i64,
        search: Option<String>,
        role: Option<String>,
    ) -> AppResult<AdminUserListResponse> {
        let (page, per_page, offset) = normalize_pagination(page, per_page);
        let role = parse_optional_role(role.as_deref())?;
        let users = self
            .user_repo
            .list_all(per_page, offset, search.as_deref(), role)
            .await?;
        let total = self.user_repo.count_all(search.as_deref(), role).await?;
        let owner_ids = users.iter().map(|user| user.id).collect::<Vec<_>>();
        let equipment_counts = self.equipment_repo.count_by_owners(&owner_ids).await?;

        let mut rows = Vec::with_capacity(users.len());
        for user in users {
            let equipment_count = equipment_counts.get(&user.id).copied().unwrap_or(0);
            rows.push(AdminUserRow {
                id: user.id,
                email: user.email,
                role: user.role.to_string(),
                username: user.username,
                full_name: user.full_name,
                created_at: user.created_at,
                equipment_count,
            });
        }

        Ok(AdminUserListResponse {
            users: rows,
            total,
            page,
            per_page,
        })
    }

    pub async fn get_user_detail(&self, id: Uuid) -> AppResult<AdminUserDetailResponse> {
        let user = self
            .user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;
        let equipment_count = self.equipment_repo.count_by_owner(user.id).await?;

        Ok(map_user_detail(user, equipment_count))
    }

    pub async fn update_user_role(
        &self,
        actor_id: Uuid,
        target_id: Uuid,
        payload: AdminUpdateRoleRequest,
    ) -> AppResult<AdminUserDetailResponse> {
        payload.validate()?;
        let new_role = parse_role(&payload.role)?;

        if actor_id == target_id && new_role != Role::Admin {
            return Err(AppError::Forbidden(
                "Admins cannot demote themselves".to_string(),
            ));
        }

        info!(
            actor = %actor_id,
            action = "admin.update_user_role",
            target = %target_id,
            role = %new_role.to_string()
        );
        let user = self.user_repo.update_role(target_id, new_role).await?;
        let equipment_count = self.equipment_repo.count_by_owner(user.id).await?;
        Ok(map_user_detail(user, equipment_count))
    }

    pub async fn delete_user(&self, actor_id: Uuid, target_id: Uuid) -> AppResult<()> {
        if actor_id == target_id {
            return Err(AppError::Forbidden(
                "Admins cannot delete themselves".to_string(),
            ));
        }

        info!(
            actor = %actor_id,
            action = "admin.delete_user",
            target = %target_id
        );
        self.user_repo.delete(target_id).await
    }

    pub async fn list_equipment(
        &self,
        page: i64,
        per_page: i64,
        search: Option<String>,
    ) -> AppResult<AdminEquipmentListResponse> {
        let (page, per_page, offset) = normalize_pagination(page, per_page);
        let rows = self
            .equipment_repo
            .list_all_with_owner(per_page, offset, search.as_deref())
            .await?;
        let total = self.equipment_repo.count_all(search.as_deref()).await?;

        Ok(AdminEquipmentListResponse {
            equipment: rows
                .into_iter()
                .map(|item| AdminEquipmentRow {
                    id: item.id,
                    title: item.title,
                    owner_email: item.owner_email,
                    category_name: item.category_name,
                    daily_rate: item.daily_rate,
                    is_available: item.is_available,
                    created_at: item.created_at,
                })
                .collect(),
            total,
            page,
            per_page,
        })
    }

    pub async fn force_delete_equipment(&self, actor_id: Uuid, id: Uuid) -> AppResult<()> {
        info!(
            actor = %actor_id,
            action = "admin.force_delete_equipment",
            target = %id
        );
        self.equipment_repo.delete(id).await
    }

    pub async fn toggle_equipment_availability(
        &self,
        actor_id: Uuid,
        id: Uuid,
        requested_state: bool,
    ) -> AppResult<bool> {
        info!(
            actor = %actor_id,
            action = "admin.set_equipment_availability",
            target = %id,
            is_available = requested_state
        );
        self.equipment_repo
            .set_availability_atomic(id, requested_state)
            .await
    }

    pub async fn list_categories(&self) -> AppResult<Vec<AdminCategoryResponse>> {
        let categories = self.category_repo.find_all().await?;
        Ok(categories.into_iter().map(map_category).collect())
    }

    pub async fn create_category(
        &self,
        payload: AdminCategoryRequest,
    ) -> AppResult<AdminCategoryResponse> {
        payload.validate()?;
        self.validate_category_parent(None, payload.parent_id)
            .await?;
        let category = Category {
            id: Uuid::new_v4(),
            name: payload.name,
            parent_id: payload.parent_id,
            created_at: Utc::now(),
        };
        let created = self.category_repo.create(&category).await?;
        Ok(map_category(created))
    }

    pub async fn update_category(
        &self,
        id: Uuid,
        payload: AdminCategoryRequest,
    ) -> AppResult<AdminCategoryResponse> {
        payload.validate()?;

        let existing = self
            .category_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("category not found".to_string()))?;
        self.validate_category_parent(Some(id), payload.parent_id)
            .await?;

        let updated = self
            .category_repo
            .update(&Category {
                id,
                name: payload.name,
                parent_id: payload.parent_id,
                created_at: existing.created_at,
            })
            .await?;

        Ok(map_category(updated))
    }

    pub async fn delete_category(&self, actor_id: Uuid, id: Uuid) -> AppResult<()> {
        info!(
            actor = %actor_id,
            action = "admin.delete_category",
            target = %id
        );
        self.category_repo.delete(id).await
    }

    async fn validate_category_parent(
        &self,
        category_id: Option<Uuid>,
        parent_id: Option<Uuid>,
    ) -> AppResult<()> {
        let Some(mut cursor) = parent_id else {
            return Ok(());
        };

        if Some(cursor) == category_id {
            return Err(AppError::BadRequest(
                "category cannot be its own parent".to_string(),
            ));
        }

        let mut visited = std::collections::HashSet::new();

        loop {
            if !visited.insert(cursor) {
                return Err(AppError::BadRequest(
                    "category hierarchy contains a cycle".to_string(),
                ));
            }

            let parent = self
                .category_repo
                .find_by_id(cursor)
                .await?
                .ok_or_else(|| AppError::BadRequest("parent category not found".to_string()))?;

            if Some(parent.id) == category_id {
                return Err(AppError::BadRequest(
                    "category parent relationship would create a cycle".to_string(),
                ));
            }

            let Some(next_cursor) = parent.parent_id else {
                return Ok(());
            };

            cursor = next_cursor;
        }
    }
}

fn normalize_pagination(page: i64, per_page: i64) -> (i64, i64, i64) {
    let page = page.max(1);
    let per_page = per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;
    (page, per_page, offset)
}

fn parse_role(input: &str) -> AppResult<Role> {
    match input.trim().to_ascii_lowercase().as_str() {
        "renter" => Ok(Role::Renter),
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        _ => Err(AppError::BadRequest(
            "Role must be one of: renter, owner, admin".to_string(),
        )),
    }
}

fn parse_optional_role(input: Option<&str>) -> AppResult<Option<Role>> {
    input.map(parse_role).transpose()
}

fn map_category(category: Category) -> AdminCategoryResponse {
    AdminCategoryResponse {
        id: category.id,
        name: category.name,
        parent_id: category.parent_id,
        created_at: category.created_at,
    }
}

fn map_user_detail(user: User, equipment_count: i64) -> AdminUserDetailResponse {
    AdminUserDetailResponse {
        id: user.id,
        email: user.email,
        role: user.role.to_string(),
        username: user.username,
        full_name: user.full_name,
        avatar_url: user.avatar_url,
        created_at: user.created_at,
        updated_at: user.updated_at,
        equipment_count,
    }
}
