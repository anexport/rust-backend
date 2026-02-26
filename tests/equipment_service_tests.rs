use std::sync::{Arc, Mutex};

use actix_rt::test;
use async_trait::async_trait;
use chrono::Utc;
use rust_backend::api::dtos::{
    Coordinates, CreateEquipmentRequest, EquipmentQueryParams, UpdateEquipmentRequest,
};
use rust_backend::application::EquipmentService;
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

    async fn find_by_email(&self, _email: &str) -> AppResult<Option<User>> {
        Ok(None)
    }

    async fn find_by_username(&self, _username: &str) -> AppResult<Option<User>> {
        Ok(None)
    }

    async fn create(&self, user: &User) -> AppResult<User> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, _user: &User) -> AppResult<User> {
        unimplemented!()
    }

    async fn delete(&self, _id: Uuid) -> AppResult<()> {
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
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        let equipment = self.equipment.lock().expect("equipment mutex poisoned");
        let start = offset as usize;
        let end = (start + limit as usize).min(equipment.len());
        if start >= equipment.len() {
            return Ok(Vec::new());
        }
        Ok(equipment[start..end].to_vec())
    }

    async fn count_search(&self, _params: &EquipmentSearchParams) -> AppResult<i64> {
        Ok(self.equipment.lock().expect("equipment mutex poisoned").len() as i64)
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

fn test_user(id: Uuid, role: Role) -> User {
    User {
        id,
        email: format!("user-{}@example.com", id),
        role,
        username: Some(format!("user-{}", id)),
        full_name: Some("Test User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn test_equipment(id: Uuid, owner_id: Uuid) -> Equipment {
    Equipment {
        id,
        owner_id,
        category_id: Uuid::new_v4(),
        title: "Test Equipment".to_string(),
        description: Some("Test Description".to_string()),
        daily_rate: Decimal::new(1000, 2),
        condition: Condition::Good,
        location: Some("Test Location".to_string()),
        coordinates: None,
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
async fn create_equipment_validates_daily_rate() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo);

    let owner_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id: Uuid::new_v4(),
        title: "Invalid Rate".to_string(),
        description: "Valid Description".to_string(),
        daily_rate: Decimal::ZERO,
        condition: "good".to_string(),
        location: "Loc".to_string(),
        coordinates: None,
    };

    let result = service.create(owner_id, request).await;
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
    if let Err(AppError::ValidationError { message, .. }) = result {
        assert!(message.contains("Daily rate must be greater than zero"));
    }
}

#[test]
async fn create_equipment_validates_condition() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo);

    let owner_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id: Uuid::new_v4(),
        title: "Invalid Condition".to_string(),
        description: "Valid Description".to_string(),
        daily_rate: Decimal::new(1000, 2),
        condition: "broken".to_string(),
        location: "Loc".to_string(),
        coordinates: None,
    };

    let result = service.create(owner_id, request).await;
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
    if let Err(AppError::ValidationError { message, .. }) = result {
        assert!(message.contains("Condition must be one of"));
    }
}

#[test]
async fn create_equipment_handles_valid_coordinates() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo);

    let owner_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id: Uuid::new_v4(),
        title: "With Coords".to_string(),
        description: "Valid Description".to_string(),
        daily_rate: Decimal::new(1000, 2),
        condition: "new".to_string(),
        location: "NYC".to_string(),
        coordinates: Some(Coordinates {
            latitude: 40.7128,
            longitude: -74.0060,
        }),
    };

    let result = service.create(owner_id, request).await.unwrap();
    assert!(result.coordinates.is_some());
    let coords = result.coordinates.unwrap();
    assert!((coords.latitude - 40.7128).abs() < 0.0001);
    assert!((coords.longitude - (-74.0060)).abs() < 0.0001);
}

#[test]
async fn create_equipment_rejects_out_of_range_coordinates() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo);

    let owner_id = Uuid::new_v4();
    let request = CreateEquipmentRequest {
        category_id: Uuid::new_v4(),
        title: "Bad Coords".to_string(),
        description: "Valid Description".to_string(),
        daily_rate: Decimal::new(1000, 2),
        condition: "new".to_string(),
        location: "NYC".to_string(),
        coordinates: Some(Coordinates {
            latitude: 95.0, // Invalid
            longitude: -74.0060,
        }),
    };

    let result = service.create(owner_id, request).await;
    assert!(matches!(result, Err(AppError::ValidationError { .. })));
}

#[test]
async fn update_equipment_authorization() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    user_repo.push(test_user(owner_id, Role::Owner));
    user_repo.push(test_user(other_user_id, Role::Renter));
    user_repo.push(test_user(admin_id, Role::Admin));

    let eq_id = Uuid::new_v4();
    equipment_repo.push(test_equipment(eq_id, owner_id));

    let request = UpdateEquipmentRequest {
        title: Some("Updated".to_string()),
        ..Default::default()
    };

    // Owner can update
    let result = service.update(owner_id, eq_id, request.clone()).await;
    assert!(result.is_ok());

    // Other user cannot update
    let result = service.update(other_user_id, eq_id, request.clone()).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));

    // Admin can update
    let result = service.update(admin_id, eq_id, request.clone()).await;
    assert!(result.is_ok());
}

#[test]
async fn list_equipment_pagination_math() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo.clone());

    // Add 25 items
    for _ in 0..25 {
        equipment_repo.push(test_equipment(Uuid::new_v4(), Uuid::new_v4()));
    }

    // Page 1, limit 10
    let params = EquipmentQueryParams {
        page: Some(1),
        limit: Some(10),
        ..Default::default()
    };
    let result = service.list(params).await.unwrap();
    assert_eq!(result.items.len(), 10);
    assert_eq!(result.total, 25);
    assert_eq!(result.total_pages, 3);
    assert_eq!(result.page, 1);

    // Page 3, limit 10
    let params = EquipmentQueryParams {
        page: Some(3),
        limit: Some(10),
        ..Default::default()
    };
    let result = service.list(params).await.unwrap();
    assert_eq!(result.items.len(), 5);
    assert_eq!(result.total_pages, 3);
    assert_eq!(result.page, 3);
}

#[test]
async fn list_equipment_clamping() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo, equipment_repo.clone());

    for _ in 0..5 {
        equipment_repo.push(test_equipment(Uuid::new_v4(), Uuid::new_v4()));
    }

    // Limit too high
    let params = EquipmentQueryParams {
        limit: Some(1000),
        ..Default::default()
    };
    let result = service.list(params).await.unwrap();
    assert_eq!(result.limit, 100);

    // Limit too low
    let params = EquipmentQueryParams {
        limit: Some(0),
        ..Default::default()
    };
    let result = service.list(params).await.unwrap();
    assert_eq!(result.limit, 1);

    // Page too low
    let params = EquipmentQueryParams {
        page: Some(0),
        ..Default::default()
    };
    let result = service.list(params).await.unwrap();
    assert_eq!(result.page, 1);
}

#[test]
async fn delete_equipment_authorization() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let service = EquipmentService::new(user_repo.clone(), equipment_repo.clone());

    let owner_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    user_repo.push(test_user(owner_id, Role::Owner));
    user_repo.push(test_user(other_user_id, Role::Renter));
    user_repo.push(test_user(admin_id, Role::Admin));

    let eq_id = Uuid::new_v4();
    
    // Test owner delete
    equipment_repo.push(test_equipment(eq_id, owner_id));
    let result = service.delete(owner_id, eq_id).await;
    assert!(result.is_ok());
    assert!(equipment_repo.equipment.lock().unwrap().is_empty());

    // Test other user delete
    let eq_id2 = Uuid::new_v4();
    equipment_repo.push(test_equipment(eq_id2, owner_id));
    let result = service.delete(other_user_id, eq_id2).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
    assert_eq!(equipment_repo.equipment.lock().unwrap().len(), 1);

    // Test admin delete
    let result = service.delete(admin_id, eq_id2).await;
    assert!(result.is_ok());
    assert!(equipment_repo.equipment.lock().unwrap().is_empty());
}
