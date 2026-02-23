use crate::domain::{
    AuthIdentity, Category, Conversation, Equipment, EquipmentPhoto, Message, User, UserSession,
};
use crate::error::AppResult;
use async_trait::async_trait;
use rust_decimal::Decimal;
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

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>>;
    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>>;
    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>>;
    async fn create(&self, user: &User) -> AppResult<User>;
    async fn update(&self, user: &User) -> AppResult<User>;
    async fn delete(&self, id: Uuid) -> AppResult<()>;
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
    async fn verify_email(&self, user_id: Uuid) -> AppResult<()>;

    async fn create_session(&self, session: &UserSession) -> AppResult<UserSession>;
    async fn find_session_by_token_hash(&self, token_hash: &str) -> AppResult<Option<UserSession>>;
    async fn revoke_session(&self, id: Uuid) -> AppResult<()>;
    async fn revoke_session_with_replacement(
        &self,
        id: Uuid,
        replaced_by: Option<Uuid>,
        reason: Option<&str>,
    ) -> AppResult<()>;
    async fn revoke_all_sessions(&self, user_id: Uuid) -> AppResult<()>;
    async fn revoke_family(&self, family_id: Uuid, reason: &str) -> AppResult<()>;
    async fn touch_session(&self, id: Uuid) -> AppResult<()>;
    async fn has_active_session(&self, user_id: Uuid) -> AppResult<bool>;
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
        if params.category_id.is_none()
            && params.min_price.is_none()
            && params.max_price.is_none()
            && params.latitude.is_none()
            && params.longitude.is_none()
            && params.radius_km.is_none()
            && params.is_available.is_none()
        {
            return self.find_all(limit, offset).await;
        }

        self.find_all(limit, offset).await
    }
    async fn find_by_owner(&self, owner_id: Uuid) -> AppResult<Vec<Equipment>>;
    async fn create(&self, equipment: &Equipment) -> AppResult<Equipment>;
    async fn update(&self, equipment: &Equipment) -> AppResult<Equipment>;
    async fn delete(&self, id: Uuid) -> AppResult<()>;

    async fn add_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto>;
    async fn find_photos(&self, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>>;
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
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Category>>;
    async fn find_children(&self, parent_id: Uuid) -> AppResult<Vec<Category>>;
}
