#![cfg_attr(tarpaulin, skip)]
#![allow(unused_variables)]

use crate::domain::{
    AuthIdentity, Category, Conversation, Equipment, EquipmentPhoto, Message, Role, User,
};
use crate::error::{AppError, AppResult};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct EquipmentSearchParams {
    pub category_id: Option<Uuid>,
    pub min_price: Option<Decimal>,
    pub max_price: Option<Decimal>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub radius_km: Option<f64>,
    pub is_available: Option<bool>,
}

impl EquipmentSearchParams {
    pub const fn has_filters(&self) -> bool {
        self.category_id.is_some()
            || self.min_price.is_some()
            || self.max_price.is_some()
            || self.latitude.is_some()
            || self.longitude.is_some()
            || self.radius_km.is_some()
            || self.is_available.is_some()
    }
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>>;
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>>;
    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>>;
    async fn create(&self, user: &User) -> AppResult<User>;
    async fn update(&self, user: &User) -> AppResult<User>;
    async fn delete(&self, id: Uuid) -> AppResult<()>;
    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        role: Option<Role>,
    ) -> AppResult<Vec<User>> {
        let _ = (limit, offset, search, role);
        Err(AppError::InternalError(anyhow::anyhow!(
            "list_all is not supported by this repository implementation".to_string(),
        )))
    }
    async fn count_all(&self, search: Option<&str>, role: Option<Role>) -> AppResult<i64> {
        let _ = (search, role);
        Err(AppError::InternalError(anyhow::anyhow!(
            "count_all is not supported by this repository implementation".to_string(),
        )))
    }
    async fn update_role(&self, id: Uuid, role: Role) -> AppResult<User> {
        let _ = (id, role);
        Err(AppError::InternalError(anyhow::anyhow!(
            "update_role is not supported by this repository implementation".to_string(),
        )))
    }
}

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity>;
    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<Option<AuthIdentity>>;
    async fn find_identity_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> AppResult<Option<AuthIdentity>>;
    async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity>;
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EquipmentWithOwner {
    pub id: Uuid,
    pub owner_id: Uuid,
    pub category_id: Uuid,
    pub title: String,
    pub daily_rate: Decimal,
    pub is_available: bool,
    pub created_at: DateTime<Utc>,
    pub owner_email: String,
    pub category_name: String,
}

#[async_trait]
pub trait EquipmentRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Equipment>>;
    async fn find_all(&self, limit: i64, offset: i64) -> AppResult<Vec<Equipment>>;
    async fn search(
        &self,
        params: &EquipmentSearchParams,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        if !params.has_filters() {
            return self.find_all(limit, offset).await;
        }

        Err(AppError::BadRequest(
            "equipment search filters are not supported by this repository implementation"
                .to_string(),
        ))
    }
    async fn count_search(&self, params: &EquipmentSearchParams) -> AppResult<i64> {
        const PAGE_SIZE: i64 = 1_000;

        let mut total = 0_i64;
        let mut offset = 0_i64;
        loop {
            let items = self.search(params, PAGE_SIZE, offset).await?;
            let count = items.len() as i64;
            total = total.saturating_add(count);

            if count < PAGE_SIZE || offset > i64::MAX - PAGE_SIZE {
                break;
            }
            offset += PAGE_SIZE;
        }

        Ok(total)
    }
    async fn find_by_owner(&self, owner_id: Uuid) -> AppResult<Vec<Equipment>>;
    async fn count_by_owner(&self, owner_id: Uuid) -> AppResult<i64> {
        let _ = owner_id;
        Err(AppError::InternalError(anyhow::anyhow!(
            "count_by_owner is not supported by this repository implementation".to_string(),
        )))
    }
    async fn count_by_owners(&self, owner_ids: &[Uuid]) -> AppResult<HashMap<Uuid, i64>> {
        let mut counts = HashMap::with_capacity(owner_ids.len());
        for owner_id in owner_ids {
            counts.insert(*owner_id, self.count_by_owner(*owner_id).await?);
        }
        Ok(counts)
    }
    async fn create(&self, equipment: &Equipment) -> AppResult<Equipment>;
    async fn update(&self, equipment: &Equipment) -> AppResult<Equipment>;
    async fn set_availability_atomic(&self, id: Uuid, is_available: bool) -> AppResult<bool> {
        let _ = (id, is_available);
        Err(AppError::InternalError(anyhow::anyhow!(
            "set_availability_atomic is not supported by this repository implementation"
                .to_string(),
        )))
    }
    async fn delete(&self, id: Uuid) -> AppResult<()>;
    async fn count_all(&self, search: Option<&str>) -> AppResult<i64> {
        let _ = search;
        Err(AppError::InternalError(anyhow::anyhow!(
            "count_all is not supported by this repository implementation".to_string(),
        )))
    }
    async fn list_all_with_owner(
        &self,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> AppResult<Vec<EquipmentWithOwner>> {
        let _ = (limit, offset, search);
        Err(AppError::InternalError(anyhow::anyhow!(
            "list_all_with_owner is not supported by this repository implementation".to_string(),
        )))
    }

    async fn add_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto>;
    async fn find_photos(&self, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>>;
    async fn find_photo_by_id(&self, photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>>;
    async fn update_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto>;
    async fn delete_photo(&self, photo_id: Uuid) -> AppResult<()>;
}

#[async_trait]
pub trait MessageRepository: Send + Sync {
    async fn find_conversation(&self, id: Uuid) -> AppResult<Option<Conversation>>;
    async fn find_user_conversations(&self, user_id: Uuid) -> AppResult<Vec<Conversation>>;
    async fn create_conversation(&self, participant_ids: Vec<Uuid>) -> AppResult<Conversation>;

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Message>>;
    async fn create_message(&self, message: &Message) -> AppResult<Message>;
    async fn find_participant_ids(&self, _conversation_id: Uuid) -> AppResult<Vec<Uuid>> {
        Ok(Vec::new())
    }

    async fn is_participant(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<bool>;
    async fn mark_as_read(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<()>;
}

#[async_trait]
pub trait CategoryRepository: Send + Sync {
    async fn find_all(&self) -> AppResult<Vec<Category>>;
    async fn count_all(&self) -> AppResult<i64> {
        Err(AppError::InternalError(anyhow::anyhow!(
            "count_all is not supported by this repository implementation".to_string(),
        )))
    }
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Category>>;
    async fn find_children(&self, parent_id: Uuid) -> AppResult<Vec<Category>>;
    async fn create(&self, category: &Category) -> AppResult<Category> {
        let _ = category;
        Err(AppError::InternalError(anyhow::anyhow!(
            "create is not supported by this repository implementation".to_string(),
        )))
    }
    async fn update(&self, category: &Category) -> AppResult<Category> {
        let _ = category;
        Err(AppError::InternalError(anyhow::anyhow!(
            "update is not supported by this repository implementation".to_string(),
        )))
    }
    async fn delete(&self, id: Uuid) -> AppResult<()> {
        let _ = id;
        Err(AppError::InternalError(anyhow::anyhow!(
            "delete is not supported by this repository implementation".to_string(),
        )))
    }
}
