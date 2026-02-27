use crate::common::mocks::{MockMessageRepo, MockUserRepo};
use chrono::{Duration, Utc};
use rust_backend::application::MessageService;
use rust_backend::domain::{Role, User};
use std::sync::Arc;
use uuid::Uuid;

pub fn test_user(id: Uuid, role: Role) -> User {
    User {
        id,
        email: format!("user-{}@example.com", id),
        role,
        username: Some(format!("user-{}", id)),
        full_name: Some(format!("User {}", id)),
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now(),
    }
}

pub fn service_with_limit(
    participant_limit: usize,
) -> (Arc<MockUserRepo>, Arc<MockMessageRepo>, MessageService) {
    let user_repo = Arc::new(MockUserRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    message_repo.with_limit(participant_limit);
    let service = MessageService::new(user_repo.clone(), message_repo.clone());
    (user_repo, message_repo, service)
}

pub fn service() -> (Arc<MockUserRepo>, Arc<MockMessageRepo>, MessageService) {
    service_with_limit(100)
}
