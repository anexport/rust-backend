use super::*;
use crate::common::fixtures;
use crate::common::fixtures::next_id;
use crate::common::TestDb;
use chrono::Utc;
use rust_backend::domain::*;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::*;
use uuid::Uuid;

#[tokio::test]
async fn user_repository_create_and_find() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created = repo.create(&user).await.unwrap();

    assert_eq!(created.id, user.id);
    assert_eq!(created.email, user.email);
    assert_eq!(created.role, user.role);

    let found = repo.find_by_id(user.id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().email, user.email);
}

#[tokio::test]
async fn user_repository_find_by_email_case_sensitivity() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let email = "TestUser@Example.COM";
    let mut user = user;
    user.email = email.to_string();
    repo.create(&user).await.unwrap();

    // Test exact match (PostgreSQL is case-sensitive for text)
    let found = repo.find_by_email(email).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().email, email);

    // Test case-insensitive matching - should NOT match due to case sensitivity
    let not_found = repo.find_by_email(&email.to_lowercase()).await.unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
async fn user_repository_find_by_username_positive_and_negative() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let mut user = fixtures::test_user();
    user.username = Some("lookup_user".to_string());
    let created = repo.create(&user).await.unwrap();

    let found = repo.find_by_username("lookup_user").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, created.id);

    let missing = repo.find_by_username("missing_user").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn user_repository_update_partial_fields() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let original_email = user.email.clone();
    let created = repo.create(&user).await.unwrap();

    // Update only some fields
    let mut updated_user = created.clone();
    updated_user.email = "updated@example.com".to_string();
    updated_user.full_name = Some("Updated Name".to_string());
    updated_user.username = Some("updateduser".to_string());

    let updated = repo.update(&updated_user).await.unwrap();

    assert_eq!(updated.id, created.id);
    assert_eq!(updated.email, "updated@example.com");
    assert_eq!(updated.full_name, Some("Updated Name".to_string()));
    assert_eq!(updated.username, Some("updateduser".to_string()));
    assert_eq!(updated.role, created.role);
    assert_ne!(updated.email, original_email);

    // Verify persisted
    let found = repo.find_by_id(updated.id).await.unwrap().unwrap();
    assert_eq!(found.email, "updated@example.com");
    assert_eq!(found.full_name, Some("Updated Name".to_string()));
}

#[tokio::test]
async fn user_repository_update_avatar_url() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created = repo.create(&user).await.unwrap();

    assert!(created.avatar_url.is_none());

    let mut updated_user = created;
    updated_user.avatar_url = Some("https://example.com/avatar.jpg".to_string());

    let updated = repo.update(&updated_user).await.unwrap();

    assert_eq!(
        updated.avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );
}

#[tokio::test]
async fn user_repository_delete_cascade_auth_identities() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    let _created_identity = auth_repo.create_identity(&identity).await.unwrap();

    // Verify identity exists via find_by_user_id
    let found = auth_repo
        .find_identity_by_user_id(created_user.id, "auth0")
        .await
        .unwrap();
    assert!(found.is_some());

    // Delete user
    user_repo.delete(created_user.id).await.unwrap();

    // Verify user is gone
    let found_user = user_repo.find_by_id(created_user.id).await.unwrap();
    assert!(found_user.is_none());

    // Verify identity is cascade deleted
    let found_identity = auth_repo
        .find_identity_by_provider_id(
            "auth0",
            identity
                .provider_id
                .as_deref()
                .expect("provider_id should exist"),
        )
        .await
        .unwrap();
    assert!(found_identity.is_none());
}

#[tokio::test]
async fn user_repository_delete_non_existent_id_is_noop() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    repo.delete(non_existent_id).await.unwrap();

    let found = repo.find_by_id(non_existent_id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn user_repository_list_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    // Create users with different roles
    let user1 = fixtures::test_user();
    let user1_mut = user1.clone();
    let mut user1 = user1_mut;
    user1.email = "user1@example.com".to_string();
    user1.role = Role::Renter;
    repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let user2_mut = user2.clone();
    let mut user2 = user2_mut;
    user2.email = "user2@example.com".to_string();
    user2.role = Role::Owner;
    repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let user3_mut = user3.clone();
    let mut user3 = user3_mut;
    user3.email = "user3@example.com".to_string();
    user3.role = Role::Admin;
    repo.create(&user3).await.unwrap();

    let all_users = repo.list_all(10, 0, None, None).await.unwrap();
    assert_eq!(all_users.len(), 3);
}

#[tokio::test]
async fn user_repository_list_all_with_pagination() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    // Create 15 users
    for i in 0..15 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("user{}@example.com", i);
        repo.create(&user).await.unwrap();
    }

    let page1 = repo.list_all(10, 0, None, None).await.unwrap();
    assert_eq!(page1.len(), 10);

    let page2 = repo.list_all(10, 10, None, None).await.unwrap();
    assert_eq!(page2.len(), 5);
}

#[tokio::test]
async fn user_repository_list_all_with_search() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let user1_mut = user1.clone();
    let mut user1 = user1_mut;
    user1.email = "alice@example.com".to_string();
    user1.username = Some("alicename".to_string());
    repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let user2_mut = user2.clone();
    let mut user2 = user2_mut;
    user2.email = "bob@example.com".to_string();
    user2.username = Some("bobby".to_string());
    repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let user3_mut = user3.clone();
    let mut user3 = user3_mut;
    user3.email = "alice.smith@example.com".to_string();
    user3.username = Some("alices".to_string());
    repo.create(&user3).await.unwrap();

    // Search for "alice"
    let alice_results = repo.list_all(10, 0, Some("alice"), None).await.unwrap();
    assert_eq!(alice_results.len(), 2);
    assert!(alice_results
        .iter()
        .all(|u| u.email.contains("alice")
            || u.username.as_ref().is_some_and(|u| u.contains("alice"))));

    // Search for "bob"
    let bob_results = repo.list_all(10, 0, Some("bob"), None).await.unwrap();
    assert_eq!(bob_results.len(), 1);
    assert_eq!(bob_results[0].email, "bob@example.com");
}

#[tokio::test]
async fn user_repository_list_all_with_role_filter() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    // Create users with different roles
    for i in 0..3 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("renter{}@example.com", i);
        user.role = Role::Renter;
        repo.create(&user).await.unwrap();
    }

    for i in 0..5 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("owner{}@example.com", i);
        user.role = Role::Owner;
        repo.create(&user).await.unwrap();
    }

    for i in 0..2 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("admin{}@example.com", i);
        user.role = Role::Admin;
        repo.create(&user).await.unwrap();
    }

    let owners = repo.list_all(10, 0, None, Some(Role::Owner)).await.unwrap();
    assert_eq!(owners.len(), 5);
    assert!(owners.iter().all(|u| u.role == Role::Owner));

    let admins = repo.list_all(10, 0, None, Some(Role::Admin)).await.unwrap();
    assert_eq!(admins.len(), 2);
    assert!(admins.iter().all(|u| u.role == Role::Admin));

    let renters = repo
        .list_all(10, 0, None, Some(Role::Renter))
        .await
        .unwrap();
    assert_eq!(renters.len(), 3);
    assert!(renters.iter().all(|u| u.role == Role::Renter));
}

#[tokio::test]
async fn user_repository_count_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let count_empty = repo.count_all(None, None).await.unwrap();
    assert_eq!(count_empty, 0);

    // Create users
    for i in 0..7 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("user{}@example.com", i);
        repo.create(&user).await.unwrap();
    }

    let count = repo.count_all(None, None).await.unwrap();
    assert_eq!(count, 7);
}

#[tokio::test]
async fn user_repository_count_all_with_search() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let user1_mut = user1.clone();
    let mut user1 = user1_mut;
    user1.email = "john.doe@example.com".to_string();
    user1.username = Some("johndoe".to_string());
    repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let user2_mut = user2.clone();
    let mut user2 = user2_mut;
    user2.email = "jane.smith@example.com".to_string();
    user2.username = Some("janesmith".to_string());
    repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let user3_mut = user3.clone();
    let mut user3 = user3_mut;
    user3.email = "bob@example.com".to_string();
    user3.username = Some("bobusername".to_string());
    repo.create(&user3).await.unwrap();

    let john_count = repo.count_all(Some("john"), None).await.unwrap();
    assert_eq!(john_count, 1);

    let total_count = repo.count_all(None, None).await.unwrap();
    assert_eq!(total_count, 3);
}

#[tokio::test]
async fn user_repository_count_all_with_role_filter() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    // Create users with different roles
    for i in 0..4 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("renter{}@example.com", i);
        user.role = Role::Renter;
        repo.create(&user).await.unwrap();
    }

    for i in 0..6 {
        let user = fixtures::test_user();
        let user_mut = user.clone();
        let mut user = user_mut;
        user.email = format!("owner{}@example.com", i);
        user.role = Role::Owner;
        repo.create(&user).await.unwrap();
    }

    let renter_count = repo.count_all(None, Some(Role::Renter)).await.unwrap();
    assert_eq!(renter_count, 4);

    let owner_count = repo.count_all(None, Some(Role::Owner)).await.unwrap();
    assert_eq!(owner_count, 6);
}

#[tokio::test]
async fn user_repository_update_role() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let user_mut = user.clone();
    let mut user = user_mut;
    user.role = Role::Renter;
    let created = repo.create(&user).await.unwrap();
    assert_eq!(created.role, Role::Renter);

    let updated = repo.update_role(created.id, Role::Owner).await.unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.role, Role::Owner);

    // Verify persisted
    let found = repo.find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(found.role, Role::Owner);
}

#[tokio::test]
async fn user_repository_update_role_nonexistent_returns_not_found() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let result = repo.update_role(non_existent_id, Role::Admin).await;
    assert!(matches!(result, Err(AppError::NotFound(_))));
}

#[tokio::test]
async fn user_repository_update_role_multiple_transitions() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let user_mut = user.clone();
    let mut user = user_mut;
    user.role = Role::Renter;
    let created = repo.create(&user).await.unwrap();

    // Renter -> Owner
    let owner = repo.update_role(created.id, Role::Owner).await.unwrap();
    assert_eq!(owner.role, Role::Owner);

    // Owner -> Admin
    let admin = repo.update_role(created.id, Role::Admin).await.unwrap();
    assert_eq!(admin.role, Role::Admin);

    // Admin -> Renter
    let renter = repo.update_role(created.id, Role::Renter).await.unwrap();
    assert_eq!(renter.role, Role::Renter);
}

#[tokio::test]
async fn user_repository_find_by_id_nonexistent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let found = repo.find_by_id(non_existent_id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn user_repository_find_by_email_nonexistent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let found = repo.find_by_email("nonexistent@example.com").await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn user_repository_find_by_username_nonexistent() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let found = repo.find_by_username("nonexistent").await.unwrap();
    assert!(found.is_none());
}
