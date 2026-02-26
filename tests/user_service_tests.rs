use std::sync::{Arc, Mutex};

mod common;

use crate::common::mocks::{MockEquipmentRepo, MockUserRepo};
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
