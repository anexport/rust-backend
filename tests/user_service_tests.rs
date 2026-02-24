use std::sync::{Arc, Mutex};

use actix_rt::test;
use async_trait::async_trait;
use chrono::Utc;
use rust_backend::api::dtos::UpdateUserRequest;
use rust_backend::application::UserService;
use rust_backend::domain::{Condition, Equipment, EquipmentPhoto, Role, User};
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::repositories::{
    EquipmentRepository, EquipmentSearchParams, UserRepository,
};
use rust_decimal::Decimal;
use uuid::Uuid;

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<Vec<User>>,
}

impl MockUserRepo {
    fn push(&self, user: User) {
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
struct MockEquipmentRepo {
    equipment: Mutex<Vec<Equipment>>,
}

impl MockEquipmentRepo {
    fn push(&self, equipment: Equipment) {
        self.equipment
            .lock()
            .expect("equipment mutex poisoned")
            .push(equipment);
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
        _params: &EquipmentSearchParams,
        _limit: i64,
        _offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        Ok(self
            .equipment
            .lock()
            .expect("equipment mutex poisoned")
            .clone())
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
        Ok(photo.clone())
    }

    async fn find_photos(&self, _equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        Ok(Vec::new())
    }

    async fn delete_photo(&self, _photo_id: Uuid) -> AppResult<()> {
        Ok(())
    }
}

fn test_user(id: Uuid, role: Role, email: &str) -> User {
    User {
        id,
        email: email.to_string(),
        role,
        username: Some("initial-user".to_string()),
        full_name: Some("Initial Name".to_string()),
        avatar_url: Some("https://example.com/initial.png".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_equipment(id: Uuid, owner_id: Uuid, condition: Condition) -> Equipment {
    Equipment {
        id,
        owner_id,
        category_id: Uuid::new_v4(),
        title: "Lens Kit".to_string(),
        description: None,
        daily_rate: Decimal::new(2500, 2),
        condition,
        location: None,
        coordinates: Some("40.7128,-74.0060".to_string()),
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
async fn get_public_profile_returns_not_found_when_missing() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = UserService::new(user_repo, equipment_repo);

    let result = service.get_public_profile(Uuid::new_v4()).await;

    assert!(matches!(result, Err(AppError::NotFound(message)) if message == "user not found"));
}

#[test]
async fn update_profile_self_updates_allowed_fields() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = UserService::new(user_repo.clone(), equipment_repo);

    let user_id = Uuid::new_v4();
    user_repo.push(test_user(user_id, Role::Renter, "self-update@example.com"));

    let result = service
        .update_profile(
            user_id,
            user_id,
            UpdateUserRequest {
                username: Some("updated-user".to_string()),
                full_name: Some("Updated Name".to_string()),
                avatar_url: Some("https://example.com/updated.png".to_string()),
            },
        )
        .await
        .expect("self update should succeed");

    assert_eq!(result.id, user_id);
    assert_eq!(result.username.as_deref(), Some("updated-user"));
    assert_eq!(result.full_name.as_deref(), Some("Updated Name"));
    assert_eq!(
        result.avatar_url.as_deref(),
        Some("https://example.com/updated.png")
    );
    assert_eq!(result.role, "renter");
    assert_eq!(result.email, "self-update@example.com");
}

#[test]
async fn update_profile_non_admin_cannot_update_others() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = UserService::new(user_repo.clone(), equipment_repo);

    let actor_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    user_repo.push(test_user(actor_id, Role::Owner, "actor@example.com"));
    user_repo.push(test_user(target_id, Role::Renter, "target@example.com"));

    let result = service
        .update_profile(
            actor_id,
            target_id,
            UpdateUserRequest {
                username: Some("blocked-change".to_string()),
                full_name: None,
                avatar_url: None,
            },
        )
        .await;

    assert!(
        matches!(result, Err(AppError::Forbidden(message)) if message == "You can only modify your own profile")
    );
}

#[test]
async fn update_profile_admin_can_update_others() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = UserService::new(user_repo.clone(), equipment_repo);

    let admin_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    user_repo.push(test_user(admin_id, Role::Admin, "admin@example.com"));
    user_repo.push(test_user(
        target_id,
        Role::Owner,
        "target-owner@example.com",
    ));

    let result = service
        .update_profile(
            admin_id,
            target_id,
            UpdateUserRequest {
                username: None,
                full_name: Some("Admin Updated".to_string()),
                avatar_url: None,
            },
        )
        .await
        .expect("admin update should succeed");

    assert_eq!(result.id, target_id);
    assert_eq!(result.full_name.as_deref(), Some("Admin Updated"));
    assert_eq!(result.role, "owner");
}

#[test]
async fn my_equipment_maps_defaults_and_condition_strings() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = UserService::new(user_repo, equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_owner_id = Uuid::new_v4();

    equipment_repo.push(test_equipment(
        Uuid::new_v4(),
        owner_id,
        Condition::Excellent,
    ));
    equipment_repo.push(test_equipment(Uuid::new_v4(), owner_id, Condition::Fair));
    equipment_repo.push(test_equipment(
        Uuid::new_v4(),
        other_owner_id,
        Condition::New,
    ));

    let rows = service
        .my_equipment(owner_id)
        .await
        .expect("my equipment should succeed");

    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.owner_id == owner_id));
    assert!(rows.iter().all(|row| row.description.is_empty()));
    assert!(rows.iter().all(|row| row.location.is_empty()));
    assert!(rows.iter().all(|row| row.coordinates.is_some()));
    assert!(rows.iter().all(|row| {
        row.coordinates
            .as_ref()
            .is_some_and(|coords| (coords.latitude - 40.7128).abs() < 0.0001)
    }));
    assert!(rows.iter().all(|row| {
        row.coordinates
            .as_ref()
            .is_some_and(|coords| (coords.longitude - (-74.0060)).abs() < 0.0001)
    }));
    assert!(rows.iter().all(|row| row.photos.is_empty()));
    assert!(rows.iter().any(|row| row.condition == "excellent"));
    assert!(rows.iter().any(|row| row.condition == "fair"));
}
