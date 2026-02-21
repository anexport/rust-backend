mod common;

use rust_backend::api::dtos::{
    CreateEquipmentRequest, LoginRequest, RegisterRequest, UpdateEquipmentRequest,
};
use rust_backend::application::{AuthService, EquipmentService};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, EquipmentRepositoryImpl, UserRepositoryImpl,
};
use rust_decimal::Decimal;

#[actix_rt::test]
async fn db_auth_register_login_me_flow() {
    let Some(test_db) = common::TestDb::new().await else {
        eprintln!(
            "Skipping db_auth_register_login_me_flow: TEST_DATABASE_URL or DATABASE_URL not set"
        );
        return;
    };

    let user_repo = std::sync::Arc::new(UserRepositoryImpl::new(test_db.pool().clone()));
    let auth_repo = std::sync::Arc::new(AuthRepositoryImpl::new(test_db.pool().clone()));
    let auth_service = AuthService::new(user_repo.clone(), auth_repo, common::test_auth_config());

    let register = auth_service
        .register(RegisterRequest {
            email: "phase1-auth@example.com".to_string(),
            password: "this-is-a-valid-password".to_string(),
            username: Some("phase1-auth-user".to_string()),
            full_name: Some("Phase One Auth".to_string()),
        })
        .await
        .expect("register should succeed");
    assert!(!register.access_token.is_empty());

    let login = auth_service
        .login(LoginRequest {
            email: "phase1-auth@example.com".to_string(),
            password: "this-is-a-valid-password".to_string(),
        })
        .await
        .expect("login should succeed");
    assert!(!login.access_token.is_empty());

    let me = auth_service
        .me(register.user.id)
        .await
        .expect("me should succeed");
    assert_eq!(me.email, "phase1-auth@example.com");
}

#[actix_rt::test]
async fn db_equipment_crud_flow() {
    let Some(test_db) = common::TestDb::new().await else {
        eprintln!("Skipping db_equipment_crud_flow: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let owner_id = common::insert_owner_user(test_db.pool(), "phase1-owner@example.com")
        .await
        .expect("owner user insert should succeed");
    let category_id = common::insert_category(test_db.pool(), "Phase1 Category")
        .await
        .expect("category insert should succeed");

    let user_repo = std::sync::Arc::new(UserRepositoryImpl::new(test_db.pool().clone()));
    let equipment_repo = std::sync::Arc::new(EquipmentRepositoryImpl::new(test_db.pool().clone()));
    let service = EquipmentService::new(user_repo, equipment_repo.clone());

    let created = service
        .create(
            owner_id,
            CreateEquipmentRequest {
                category_id,
                title: "Phase1 Camera".to_string(),
                description: "A camera for phase 1 acceptance integration tests".to_string(),
                daily_rate: Decimal::new(12500, 2),
                condition: "excellent".to_string(),
                location: "Austin".to_string(),
                coordinates: None,
            },
        )
        .await
        .expect("equipment create should succeed");

    let fetched = service
        .get_by_id(created.id)
        .await
        .expect("equipment fetch should succeed");
    assert_eq!(fetched.title, "Phase1 Camera");

    let updated = service
        .update(
            owner_id,
            created.id,
            UpdateEquipmentRequest {
                title: Some("Phase1 Camera Updated".to_string()),
                description: Some("Updated description for phase 1 integration test".to_string()),
                daily_rate: Some(Decimal::new(13500, 2)),
                condition: Some("good".to_string()),
                location: Some("Dallas".to_string()),
                coordinates: None,
                is_available: Some(true),
            },
        )
        .await
        .expect("equipment update should succeed");
    assert_eq!(updated.title, "Phase1 Camera Updated");

    service
        .delete(owner_id, created.id)
        .await
        .expect("equipment delete should succeed");

    let deleted = service.get_by_id(created.id).await;
    assert!(matches!(deleted, Err(AppError::NotFound(_))));
}
