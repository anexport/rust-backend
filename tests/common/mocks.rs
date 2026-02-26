use async_trait::async_trait;
use chrono::Utc;
use rust_backend::domain::{
    AuthIdentity, AuthProvider, Category, Conversation, Equipment, EquipmentPhoto, Message, User,
};
use rust_backend::error::AppResult;
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, EquipmentSearchParams,
    MessageRepository, UserRepository,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Default)]
pub struct MockUserRepo {
    pub users: Mutex<Vec<User>>,
}

impl MockUserRepo {
    pub fn push(&self, user: User) {
        self.users.lock().expect("users mutex poisoned").push(user);
    }
}

#[async_trait]
impl UserRepository for MockUserRepo {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.id == id)
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.email == email)
            .cloned())
    }

    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> AppResult<User> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> AppResult<User> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        if let Some(existing) = users.iter_mut().find(|existing| existing.id == user.id) {
            *existing = user.clone();
        }
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .retain(|user| user.id != id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MockAuthRepo {
    pub identities: Mutex<Vec<AuthIdentity>>,
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .expect("identities mutex poisoned")
            .iter()
            .find(|identity| identity.user_id == user_id && identity.provider.as_str() == provider)
            .cloned())
    }

    async fn find_identity_by_provider_id(
        &self,
        _provider: &str,
        _provider_id: &str,
    ) -> AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
        Ok(identity.clone())
    }
}

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

    async fn find_all(&self, _limit: i64, _offset: i64) -> AppResult<Vec<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone())
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

    async fn find_by_owner(&self, owner_id: Uuid) -> AppResult<Vec<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .iter()
            .filter(|equipment| equipment.owner_id == owner_id)
            .cloned()
            .collect())
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
        }
        Ok(equipment.clone())
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

    async fn delete_photo(&self, photo_id: Uuid) -> AppResult<()> {
        self.photos
            .lock()
            .expect("photos mutex poisoned")
            .retain(|photo| photo.id != photo_id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MockCategoryRepo {
    pub categories: Mutex<Vec<Category>>,
}

#[async_trait]
impl CategoryRepository for MockCategoryRepo {
    async fn find_all(&self) -> AppResult<Vec<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .clone())
    }

    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    async fn find_children(&self, parent_id: Uuid) -> AppResult<Vec<Category>> {
        Ok(self
            .categories
            .lock()
            .expect("categories mutex poisoned")
            .iter()
            .filter(|c| c.parent_id == Some(parent_id))
            .cloned()
            .collect())
    }

    async fn create(&self, category: &Category) -> AppResult<Category> {
        self.categories
            .lock()
            .expect("categories mutex poisoned")
            .push(category.clone());
        Ok(category.clone())
    }
}

#[derive(Default)]
pub struct MockMessageRepo {
    pub conversations: Mutex<Vec<Conversation>>,
    pub messages: Mutex<Vec<Message>>,
    pub participants: Mutex<Vec<(Uuid, Uuid)>>,
    pub participant_limit: Mutex<usize>,
}

impl MockMessageRepo {
    pub fn add_conversation(&self, conv: Conversation) {
        self.conversations
            .lock()
            .expect("conversations mutex poisoned")
            .push(conv);
    }

    pub fn add_participant(&self, conversation_id: Uuid, user_id: Uuid) {
        self.participants
            .lock()
            .expect("participants mutex poisoned")
            .push((conversation_id, user_id));
    }

    pub fn add_message(&self, msg: Message) {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(msg);
    }

    pub fn with_limit(&self, limit: usize) {
        *self.participant_limit.lock().expect("limit mutex poisoned") = limit;
    }

    pub fn is_participant_sync(&self, conversation_id: Uuid, user_id: Uuid) -> bool {
        self.participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .any(|(cid, uid)| *cid == conversation_id && *uid == user_id)
    }
}

#[async_trait]
impl MessageRepository for MockMessageRepo {
    async fn find_conversation(&self, id: Uuid) -> AppResult<Option<Conversation>> {
        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    async fn find_user_conversations(&self, user_id: Uuid) -> AppResult<Vec<Conversation>> {
        let participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        let conversation_ids: Vec<Uuid> = participants
            .iter()
            .filter(|(_, uid)| *uid == user_id)
            .map(|(cid, _)| *cid)
            .collect();
        drop(participants);

        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .filter(|c| conversation_ids.contains(&c.id))
            .cloned()
            .collect())
    }

    async fn create_conversation(&self, participant_ids: Vec<Uuid>) -> AppResult<Conversation> {
        let limit = *self.participant_limit.lock().expect("limit mutex poisoned");
        if limit > 0 && participant_ids.len() > limit {
            return Err(rust_backend::error::AppError::Conflict(format!(
                "Conversation cannot have more than {} participants",
                limit
            )));
        }

        let conversation = Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        for participant_id in participant_ids {
            participants.push((conversation.id, participant_id));
        }

        let mut conversations = self
            .conversations
            .lock()
            .expect("conversations mutex poisoned");
        conversations.push(conversation.clone());

        Ok(conversation)
    }

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Message>> {
        let mut messages: Vec<Message> = self
            .messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .cloned()
            .collect();

        messages.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at));
        let offset = offset.max(0) as usize;
        let limit = limit.max(0) as usize;

        Ok(messages.into_iter().skip(offset).take(limit).collect())
    }

    async fn create_message(&self, message: &Message) -> AppResult<Message> {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(message.clone());
        Ok(message.clone())
    }

    async fn find_participant_ids(&self, conversation_id: Uuid) -> AppResult<Vec<Uuid>> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .filter(|(cid, _)| *cid == conversation_id)
            .map(|(_, uid)| *uid)
            .collect())
    }

    async fn is_participant(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .any(|(cid, uid)| *cid == conversation_id && *uid == user_id))
    }

    async fn mark_as_read(&self, _conversation_id: Uuid, _user_id: Uuid) -> AppResult<()> {
        Ok(())
    }
}

pub fn haversine_km(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    let r = 6371.0;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lng = (lng2 - lng1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lng / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}
