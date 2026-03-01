use std::sync::Arc;

use crate::common::mocks::MockUserRepo;
use actix_rt::test;
use chrono::Utc;
use rust_backend::application::check_equipment_access;
use rust_backend::domain::Role;
use rust_backend::error::{AppError, AppResult};
use uuid::Uuid;

fn test_user(id: Uuid, role: Role) -> rust_backend::domain::User {
    rust_backend::domain::User {
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

#[test]
async fn check_equipment_access_allows_owner() {
    let user_repo = Arc::new(MockUserRepo::default());
    let owner_id = Uuid::new_v4();

    user_repo.push(test_user(owner_id, Role::Owner));

    let result: AppResult<()> = check_equipment_access(&*user_repo, owner_id, owner_id).await;
    assert!(result.is_ok());
}

#[test]
async fn check_equipment_access_allows_renter_owner() {
    let user_repo = Arc::new(MockUserRepo::default());
    let owner_id = Uuid::new_v4();

    user_repo.push(test_user(owner_id, Role::Renter));

    let result: AppResult<()> = check_equipment_access(&*user_repo, owner_id, owner_id).await;
    assert!(result.is_ok());
}

#[test]
async fn check_equipment_access_allows_admin() {
    let user_repo = Arc::new(MockUserRepo::default());
    let admin_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    user_repo.push(test_user(admin_id, Role::Admin));
    user_repo.push(test_user(owner_id, Role::Owner));

    let result: AppResult<()> = check_equipment_access(&*user_repo, admin_id, owner_id).await;
    assert!(result.is_ok());
}

#[test]
async fn check_equipment_access_forbids_non_owner_renter() {
    let user_repo = Arc::new(MockUserRepo::default());
    let renter_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    user_repo.push(test_user(renter_id, Role::Renter));
    user_repo.push(test_user(owner_id, Role::Owner));

    let result: AppResult<()> = check_equipment_access(&*user_repo, renter_id, owner_id).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
    if let Err(AppError::Forbidden(msg)) = result {
        assert!(msg.contains("permission"));
    }
}

#[test]
async fn check_equipment_access_forbids_non_owner_owner() {
    let user_repo = Arc::new(MockUserRepo::default());
    let owner1_id = Uuid::new_v4();
    let owner2_id = Uuid::new_v4();

    user_repo.push(test_user(owner1_id, Role::Owner));
    user_repo.push(test_user(owner2_id, Role::Owner));

    let result: AppResult<()> = check_equipment_access(&*user_repo, owner1_id, owner2_id).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn check_equipment_access_unauthorized_for_unknown_actor() {
    let user_repo = Arc::new(MockUserRepo::default());
    let unknown_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();

    user_repo.push(test_user(owner_id, Role::Owner));

    let result: AppResult<()> = check_equipment_access(&*user_repo, unknown_id, owner_id).await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

#[test]
async fn check_equipment_access_allows_different_users_same_id() {
    let user_repo = Arc::new(MockUserRepo::default());
    let user_id = Uuid::new_v4();

    user_repo.push(test_user(user_id, Role::Renter));

    // Same user ID for actor and owner means they are the same person
    let result: AppResult<()> = check_equipment_access(&*user_repo, user_id, user_id).await;
    assert!(result.is_ok());
}

#[test]
async fn check_equipment_access_role_independence_for_owner() {
    let user_repo = Arc::new(MockUserRepo::default());

    // Test that owners can access their own equipment regardless of role
    for role in [Role::Renter, Role::Owner, Role::Admin] {
        let owner_id = Uuid::new_v4();
        user_repo.push(test_user(owner_id, role));

        let result: AppResult<()> = check_equipment_access(&*user_repo, owner_id, owner_id).await;
        assert!(
            result.is_ok(),
            "Owner should be able to access their own equipment with role {:?}",
            role
        );
    }
}

#[test]
async fn check_equipment_access_allows_admin_any_equipment() {
    let user_repo = Arc::new(MockUserRepo::default());
    let admin_id = Uuid::new_v4();
    let owner_ids = vec![
        (Uuid::new_v4(), Role::Renter),
        (Uuid::new_v4(), Role::Owner),
        (Uuid::new_v4(), Role::Admin),
    ];

    user_repo.push(test_user(admin_id, Role::Admin));
    for (owner_id, role) in &owner_ids {
        user_repo.push(test_user(*owner_id, *role));
    }

    // Admin should be able to access any equipment
    for (owner_id, _) in owner_ids {
        let result: AppResult<()> = check_equipment_access(&*user_repo, admin_id, owner_id).await;
        assert!(
            result.is_ok(),
            "Admin should be able to access equipment owned by anyone"
        );
    }
}
