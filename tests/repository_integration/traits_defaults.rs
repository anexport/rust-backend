use std::sync::Mutex;

use async_trait::async_trait;
use rust_backend::domain::{Conversation, Equipment, EquipmentPhoto, Message};
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::repositories::{
    EquipmentRepository, EquipmentSearchParams, MessageRepository,
};
use uuid::Uuid;

#[derive(Default)]
struct EquipmentRepositorySpy {
    calls: Mutex<Vec<(i64, i64)>>,
}

fn unreachable_call<T>() -> AppResult<T> {
    panic!("unexpected test call")
}

#[async_trait]
impl EquipmentRepository for EquipmentRepositorySpy {
    async fn find_by_id(&self, _id: Uuid) -> AppResult<Option<Equipment>> {
        unreachable_call()
    }

    async fn find_all(&self, limit: i64, offset: i64) -> AppResult<Vec<Equipment>> {
        self.calls
            .lock()
            .expect("calls mutex poisoned")
            .push((limit, offset));
        Ok(Vec::new())
    }

    async fn find_by_owner(&self, _owner_id: Uuid) -> AppResult<Vec<Equipment>> {
        unreachable_call()
    }

    async fn create(&self, _equipment: &Equipment) -> AppResult<Equipment> {
        unreachable_call()
    }

    async fn update(&self, _equipment: &Equipment) -> AppResult<Equipment> {
        unreachable_call()
    }

    async fn delete(&self, _id: Uuid) -> AppResult<()> {
        unreachable_call()
    }

    async fn add_photo(&self, _photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        unreachable_call()
    }

    async fn find_photos(&self, _equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        unreachable_call()
    }

    async fn find_photo_by_id(&self, _photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>> {
        unreachable_call()
    }

    async fn update_photo(&self, _photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        unreachable_call()
    }

    async fn delete_photo(&self, _photo_id: Uuid) -> AppResult<()> {
        unreachable_call()
    }
}

struct MessageRepositoryDefaultsOnly;

#[async_trait]
impl MessageRepository for MessageRepositoryDefaultsOnly {
    async fn find_conversation(&self, _id: Uuid) -> AppResult<Option<Conversation>> {
        unreachable_call()
    }

    async fn find_user_conversations(&self, _user_id: Uuid) -> AppResult<Vec<Conversation>> {
        unreachable_call()
    }

    async fn create_conversation(&self, _participant_ids: Vec<Uuid>) -> AppResult<Conversation> {
        unreachable_call()
    }

    async fn find_messages(
        &self,
        _conversation_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> AppResult<Vec<Message>> {
        unreachable_call()
    }

    async fn create_message(&self, _message: &Message) -> AppResult<Message> {
        unreachable_call()
    }

    async fn is_participant(&self, _conversation_id: Uuid, _user_id: Uuid) -> AppResult<bool> {
        unreachable_call()
    }

    async fn mark_as_read(&self, _conversation_id: Uuid, _user_id: Uuid) -> AppResult<()> {
        unreachable_call()
    }
}

#[derive(Default)]
struct EquipmentRepositoryCountSearchLimitGuard {
    search_calls: Mutex<Vec<(i64, i64)>>,
}

#[async_trait]
impl EquipmentRepository for EquipmentRepositoryCountSearchLimitGuard {
    async fn find_by_id(&self, _id: Uuid) -> AppResult<Option<Equipment>> {
        unreachable_call()
    }

    async fn find_all(&self, _limit: i64, _offset: i64) -> AppResult<Vec<Equipment>> {
        unreachable_call()
    }

    async fn search(
        &self,
        _params: &EquipmentSearchParams,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        self.search_calls
            .lock()
            .expect("search_calls mutex poisoned")
            .push((limit, offset));
        if limit > 10_000 {
            return Err(AppError::BadRequest(
                "count_search requested an unsafe page size".to_string(),
            ));
        }
        Ok(Vec::new())
    }

    async fn find_by_owner(&self, _owner_id: Uuid) -> AppResult<Vec<Equipment>> {
        unreachable_call()
    }

    async fn create(&self, _equipment: &Equipment) -> AppResult<Equipment> {
        unreachable_call()
    }

    async fn update(&self, _equipment: &Equipment) -> AppResult<Equipment> {
        unreachable_call()
    }

    async fn delete(&self, _id: Uuid) -> AppResult<()> {
        unreachable_call()
    }

    async fn add_photo(&self, _photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        unreachable_call()
    }

    async fn find_photos(&self, _equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        unreachable_call()
    }

    async fn find_photo_by_id(&self, _photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>> {
        unreachable_call()
    }

    async fn update_photo(&self, _photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        unreachable_call()
    }

    async fn delete_photo(&self, _photo_id: Uuid) -> AppResult<()> {
        unreachable_call()
    }
}

#[tokio::test]
async fn equipment_repository_search_calls_find_all_when_all_filters_none() {
    let repository = EquipmentRepositorySpy::default();
    let params = EquipmentSearchParams::default();

    let result = repository.search(&params, 25, 10).await;

    assert!(result.is_ok());
    let calls = repository.calls.lock().expect("calls mutex poisoned");
    assert_eq!(calls.as_slice(), &[(25, 10)]);
}

#[tokio::test]
async fn equipment_repository_search_returns_error_when_filters_are_provided() {
    let repository = EquipmentRepositorySpy::default();
    let params = EquipmentSearchParams {
        is_available: Some(true),
        ..EquipmentSearchParams::default()
    };

    let result = repository.search(&params, 25, 10).await;

    match result {
        Err(AppError::BadRequest(message)) => {
            assert!(message.contains("not supported"));
        }
        other => panic!("expected bad request error, got: {other:?}"),
    }
    let calls = repository.calls.lock().expect("calls mutex poisoned");
    assert!(calls.is_empty());
}

#[tokio::test]
async fn message_repository_find_participant_ids_returns_empty_vec_by_default() {
    let repository = MessageRepositoryDefaultsOnly;

    let participant_ids = repository
        .find_participant_ids(Uuid::new_v4())
        .await
        .expect("default implementation should succeed");

    assert!(participant_ids.is_empty());
}

#[tokio::test]
async fn equipment_repository_count_search_uses_bounded_page_size() {
    let repository = EquipmentRepositoryCountSearchLimitGuard::default();
    let params = EquipmentSearchParams::default();

    let result = repository.count_search(&params).await;

    assert!(result.is_ok(), "count_search should avoid huge page sizes");
    let calls = repository
        .search_calls
        .lock()
        .expect("search_calls mutex poisoned");
    assert!(!calls.is_empty(), "count_search should call search");
    assert!(
        calls.iter().all(|(limit, _)| *limit <= 10_000),
        "count_search should use bounded limits"
    );
}
