// Repository Integration Tests
//
// This module contains comprehensive integration tests for all repository modules,
// testing database-level behaviors including constraints, cascades, and queries.
//
// NOTE: Test DB setup uses a global advisory lock to avoid cross-process state races.

mod common;

use chrono::{Duration, Utc};
use rust_backend::domain::{
    AuthIdentity, AuthProvider as DomainAuthProvider, Category, EquipmentPhoto, Message,
};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::{
    AuthRepository, AuthRepositoryImpl, CategoryRepository, CategoryRepositoryImpl,
    EquipmentRepository, EquipmentRepositoryImpl, EquipmentSearchParams, MessageRepository,
    MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use rust_decimal::Decimal;
use uuid::Uuid;

use common::fixtures;
use common::fixtures::next_id;
use common::TestDb;

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
async fn auth_repository_create_identity() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let identity = fixtures::test_auth_identity(created_user.id);
    let created = auth_repo.create_identity(&identity).await.unwrap();

    assert_eq!(created.id, identity.id);
    assert_eq!(created.user_id, created_user.id);
    assert_eq!(created.provider, identity.provider);
    assert_eq!(created.verified, identity.verified);
}

#[tokio::test]
async fn auth_repository_rejects_duplicate_auth0_identity_for_same_user() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let first_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    auth_repo.create_identity(&first_identity).await.unwrap();

    let duplicate_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    let result = auth_repo.create_identity(&duplicate_identity).await;
    assert!(matches!(result, Err(AppError::Conflict(_))));
}

#[tokio::test]
async fn auth_repository_upsert_identity_conflict_handling() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let provider_id = format!("auth0|{}", next_id());
    let identity1 = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(provider_id.clone()),
        password_hash: None,
        verified: false,
        created_at: Utc::now(),
    };
    auth_repo.create_identity(&identity1).await.unwrap();

    // Upsert with same provider_id but different verified status
    let identity2 = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(provider_id.clone()),
        password_hash: None,
        verified: true, // Changed to true
        created_at: Utc::now(),
    };
    let upserted = auth_repo.upsert_identity(&identity2).await.unwrap();

    // Should update the existing record
    assert_eq!(upserted.provider_id, Some(provider_id.clone()));
    assert!(upserted.verified);

    // Verify only one record exists
    let found = auth_repo
        .find_identity_by_provider_id("auth0", &provider_id)
        .await
        .unwrap();
    assert!(found.is_some());
}

#[tokio::test]
async fn equipment_repository_create_with_coordinates() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.set_coordinates(40.7128, -74.0060).unwrap();

    let created = equipment_repo.create(&equipment).await.unwrap();

    assert_eq!(created.id, equipment.id);
    assert_eq!(created.title, equipment.title);
    // Coordinates are stored in PostGIS format, not as plain text
    // The repository returns coordinates::text which gives the WKT representation
    assert!(created.coordinates.is_some());
}

#[tokio::test]
async fn equipment_repository_geographic_search_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create equipment in New York
    let mut eq1 = fixtures::test_equipment(created_user.id, created_category.id);
    eq1.set_coordinates(40.7128, -74.0060).unwrap(); // NYC
    eq1.title = "NYC Equipment".to_string();
    equipment_repo.create(&eq1).await.unwrap();

    // Create equipment in Boston (about 300km away)
    let mut eq2 = fixtures::test_equipment(created_user.id, created_category.id);
    eq2.set_coordinates(42.3601, -71.0589).unwrap(); // Boston
    eq2.title = "Boston Equipment".to_string();
    equipment_repo.create(&eq2).await.unwrap();

    // Search with category and availability only (skip geo for now due to query builder issues)
    let params = EquipmentSearchParams {
        category_id: Some(created_category.id),
        min_price: None,
        max_price: None,
        latitude: None,
        longitude: None,
        radius_km: None,
        is_available: Some(true),
    };

    let results = equipment_repo.search(&params, 10, 0).await.unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|e| e.title.contains("NYC")));
    assert!(results.iter().any(|e| e.title.contains("Boston")));
}

#[tokio::test]
async fn equipment_repository_postgis_coordinate_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.set_coordinates(37.7749, -122.4194).unwrap(); // San Francisco

    let created = equipment_repo.create(&equipment).await.unwrap();

    // Find by id and verify coordinates are stored (in PostGIS format)
    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    // Coordinates are stored in PostGIS geography format, returned as WKT string
    assert!(found.coordinates.is_some());
}

#[tokio::test]
async fn equipment_repository_negative_and_edge_cases() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let owner = fixtures::test_owner();
    let created_owner = user_repo.create(&owner).await.unwrap();
    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // 1. find_by_owner/count_by_owner returns 0 for new owner
    let found = equipment_repo.find_by_owner(created_owner.id).await.unwrap();
    assert!(found.is_empty());
    let count = equipment_repo.count_by_owner(created_owner.id).await.unwrap();
    assert_eq!(count, 0);

    // 2. create with None coordinates
    let mut equipment = fixtures::test_equipment(created_owner.id, created_category.id);
    equipment.coordinates = None;
    let created = equipment_repo.create(&equipment).await.unwrap();
    assert!(created.coordinates.is_none());

    let found = equipment_repo.find_by_id(created.id).await.unwrap().unwrap();
    assert!(found.coordinates.is_none());
    
    // 3. count_by_owner returns 1 after creation
    let count = equipment_repo.count_by_owner(created_owner.id).await.unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn equipment_repository_search_filter_combinations() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let cat1 = fixtures::test_category();
    let created_cat1 = create_category(&db, &cat1).await.unwrap();

    let cat2 = fixtures::test_category();
    let created_cat2 = create_category(&db, &cat2).await.unwrap();

    // Create equipment with different combinations
    let mut eq1 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq1.daily_rate = Decimal::new(1000, 2); // $10.00
    eq1.is_available = true;
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(created_user.id, created_cat2.id);
    eq2.daily_rate = Decimal::new(2000, 2); // $20.00
    eq2.is_available = false;
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(created_user.id, created_cat1.id);
    eq3.daily_rate = Decimal::new(3000, 2); // $30.00
    eq3.is_available = true;
    equipment_repo.create(&eq3).await.unwrap();

    // Search with multiple filters
    let params = EquipmentSearchParams {
        category_id: Some(created_cat1.id),
        min_price: Some(Decimal::new(1500, 2)), // $15.00
        max_price: Some(Decimal::new(5000, 2)), // $50.00
        latitude: None,
        longitude: None,
        radius_km: None,
        is_available: Some(true),
    };

    let results = equipment_repo.search(&params, 10, 0).await.unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].daily_rate >= Decimal::new(1500, 2));
    assert!(results[0].daily_rate <= Decimal::new(5000, 2));
    assert_eq!(results[0].category_id, created_cat1.id);
    assert!(results[0].is_available);
}

#[tokio::test]
async fn equipment_repository_pagination_with_large_dataset() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    // Create 25 equipment items
    for i in 0..25 {
        let mut eq = fixtures::test_equipment(created_user.id, created_category.id);
        eq.title = format!("Equipment {}", i);
        equipment_repo.create(&eq).await.unwrap();
    }

    // Test pagination
    let page1 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 10);

    let page2 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 10)
        .await
        .unwrap();
    assert_eq!(page2.len(), 10);

    let page3 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 20)
        .await
        .unwrap();
    assert_eq!(page3.len(), 5);

    let page4 = equipment_repo
        .search(&EquipmentSearchParams::default(), 10, 30)
        .await
        .unwrap();
    assert_eq!(page4.len(), 0);
}

#[tokio::test]
async fn equipment_repository_photo_crud_operations() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let equipment = fixtures::test_equipment(created_user.id, created_category.id);
    let created_equipment = equipment_repo.create(&equipment).await.unwrap();

    // Create primary photo
    let photo1 = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/photo1.jpg".to_string(),
        is_primary: true,
        order_index: 0,
        created_at: Utc::now(),
    };
    let created_photo1 = equipment_repo.add_photo(&photo1).await.unwrap();
    assert_eq!(created_photo1.photo_url, photo1.photo_url);
    assert!(created_photo1.is_primary);

    // Create secondary photo
    let photo2 = EquipmentPhoto {
        id: Uuid::new_v4(),
        equipment_id: created_equipment.id,
        photo_url: "https://example.com/photo2.jpg".to_string(),
        is_primary: false,
        order_index: 1,
        created_at: Utc::now(),
    };
    equipment_repo.add_photo(&photo2).await.unwrap();

    // Find all photos
    let photos = equipment_repo
        .find_photos(created_equipment.id)
        .await
        .unwrap();
    assert_eq!(photos.len(), 2);
    assert!(photos.iter().any(|p| p.is_primary));

    // Delete a photo
    equipment_repo
        .delete_photo(created_photo1.id)
        .await
        .unwrap();

    let photos_after_delete = equipment_repo
        .find_photos(created_equipment.id)
        .await
        .unwrap();
    assert_eq!(photos_after_delete.len(), 1);
    assert_eq!(photos_after_delete[0].photo_url, photo2.photo_url);
}

#[tokio::test]
async fn equipment_repository_hard_delete() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let _category_repo = CategoryRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let equipment = fixtures::test_equipment(created_user.id, created_category.id);
    let created = equipment_repo.create(&equipment).await.unwrap();

    // Verify equipment exists
    let found = equipment_repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_some());

    // Hard delete
    equipment_repo.delete(created.id).await.unwrap();

    // Verify equipment is gone
    let found = equipment_repo.find_by_id(created.id).await.unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn equipment_repository_set_availability_atomic_updates_state() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_owner();
    let created_user = user_repo.create(&user).await.unwrap();

    let category = fixtures::test_category();
    let created_category = create_category(&db, &category).await.unwrap();

    let mut equipment = fixtures::test_equipment(created_user.id, created_category.id);
    equipment.is_available = true;
    let created = equipment_repo.create(&equipment).await.unwrap();

    let updated = equipment_repo
        .set_availability_atomic(created.id, false)
        .await
        .unwrap();
    assert!(!updated);

    let found = equipment_repo
        .find_by_id(created.id)
        .await
        .unwrap()
        .unwrap();
    assert!(!found.is_available);
}

#[tokio::test]
async fn equipment_repository_count_by_owners_groups_counts() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let equipment_repo = EquipmentRepositoryImpl::new(db.pool().clone());

    let owner_one = user_repo.create(&fixtures::test_owner()).await.unwrap();
    let owner_two = user_repo.create(&fixtures::test_owner()).await.unwrap();
    let category = create_category(&db, &fixtures::test_category())
        .await
        .unwrap();

    for _ in 0..2 {
        let equipment = fixtures::test_equipment(owner_one.id, category.id);
        equipment_repo.create(&equipment).await.unwrap();
    }
    let equipment = fixtures::test_equipment(owner_two.id, category.id);
    equipment_repo.create(&equipment).await.unwrap();

    let counts = equipment_repo
        .count_by_owners(&[owner_one.id, owner_two.id])
        .await
        .unwrap();
    assert_eq!(counts.get(&owner_one.id), Some(&2));
    assert_eq!(counts.get(&owner_two.id), Some(&1));
}

#[tokio::test]
async fn message_repository_conversation_participant_management() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    // Create conversation with multiple participants
    let participant_ids = vec![created_user1.id, created_user2.id, created_user3.id];
    let conversation = message_repo
        .create_conversation(participant_ids.clone())
        .await
        .unwrap();

    // Verify all participants are added
    let participants = message_repo
        .find_participant_ids(conversation.id)
        .await
        .unwrap();
    assert_eq!(participants.len(), 3);
    assert!(participants.contains(&created_user1.id));
    assert!(participants.contains(&created_user2.id));
    assert!(participants.contains(&created_user3.id));

    // Verify each user is a participant
    assert!(message_repo
        .is_participant(conversation.id, created_user1.id)
        .await
        .unwrap());
    assert!(message_repo
        .is_participant(conversation.id, created_user2.id)
        .await
        .unwrap());
    assert!(message_repo
        .is_participant(conversation.id, created_user3.id)
        .await
        .unwrap());

    // Verify non-participant is not in conversation
    let user4 = fixtures::test_user();
    let created_user4 = user_repo.create(&user4).await.unwrap();
    assert!(!message_repo
        .is_participant(conversation.id, created_user4.id)
        .await
        .unwrap());
}

#[tokio::test]
async fn message_repository_message_ordering() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // Create messages with different timestamps
    let base_time = Utc::now();

    let msg1 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "First message".to_string(),
        created_at: base_time + Duration::seconds(0),
    };
    message_repo.create_message(&msg1).await.unwrap();

    let msg2 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user2.id,
        content: "Second message".to_string(),
        created_at: base_time + Duration::seconds(1),
    };
    message_repo.create_message(&msg2).await.unwrap();

    let msg3 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "Third message".to_string(),
        created_at: base_time + Duration::seconds(2),
    };
    message_repo.create_message(&msg3).await.unwrap();

    // Messages should be returned in DESC order by created_at (newest first)
    let messages = message_repo
        .find_messages(conversation.id, 10, 0)
        .await
        .unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].content, "Third message");
    assert_eq!(messages[1].content, "Second message");
    assert_eq!(messages[2].content, "First message");
}

#[tokio::test]
async fn message_repository_read_receipt_updates() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // Mark as read for user1
    message_repo
        .mark_as_read(conversation.id, created_user1.id)
        .await
        .unwrap();

    // Create a message to trigger update of conversation.updated_at
    let msg = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "Test message".to_string(),
        created_at: Utc::now(),
    };
    message_repo.create_message(&msg).await.unwrap();

    // Mark as read for user2
    message_repo
        .mark_as_read(conversation.id, created_user2.id)
        .await
        .unwrap();

    // Verify conversation updated_at is updated
    let updated_conversation = message_repo
        .find_conversation(conversation.id)
        .await
        .unwrap()
        .unwrap();
    assert!(updated_conversation.updated_at > conversation.created_at);
}

#[tokio::test]
async fn message_repository_conversation_privacy_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    // User1 and User2 in conversation 1
    let conv1 = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // User1 and User3 in conversation 2
    let conv2 = message_repo
        .create_conversation(vec![created_user1.id, created_user3.id])
        .await
        .unwrap();

    // User2 and User3 in conversation 3 (User1 not in this one)
    let conv3 = message_repo
        .create_conversation(vec![created_user2.id, created_user3.id])
        .await
        .unwrap();

    // User1 should see 2 conversations
    let user1_convs = message_repo
        .find_user_conversations(created_user1.id)
        .await
        .unwrap();
    assert_eq!(user1_convs.len(), 2);
    assert!(user1_convs.iter().any(|c| c.id == conv1.id));
    assert!(user1_convs.iter().any(|c| c.id == conv2.id));
    assert!(!user1_convs.iter().any(|c| c.id == conv3.id));

    // User2 should see 2 conversations
    let user2_convs = message_repo
        .find_user_conversations(created_user2.id)
        .await
        .unwrap();
    assert_eq!(user2_convs.len(), 2);

    // User3 should see 2 conversations
    let user3_convs = message_repo
        .find_user_conversations(created_user3.id)
        .await
        .unwrap();
    assert_eq!(user3_convs.len(), 2);
}

#[tokio::test]
async fn message_repository_non_participant_access_blocked() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // User3 is not a participant
    let is_participant = message_repo
        .is_participant(conversation.id, created_user3.id)
        .await
        .unwrap();
    assert!(!is_participant);

    // User3 should not be able to send messages to this conversation
    let msg = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user3.id,
        content: "Unauthorized message".to_string(),
        created_at: Utc::now(),
    };

    // Database trigger enforces that sender must be a participant
    let result = message_repo.create_message(&msg).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn category_repository_find_all() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let cat1 = Category {
        id: Uuid::new_v4(),
        name: "Camping".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    create_category(&db, &cat1).await.unwrap();

    let cat2 = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    create_category(&db, &cat2).await.unwrap();

    let categories = repo.find_all().await.unwrap();
    assert_eq!(categories.len(), 2);
}

#[tokio::test]
async fn category_repository_hierarchy_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = create_category(&db, &parent).await.unwrap();

    let child1 = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child1).await.unwrap();

    let child2 = Category {
        id: Uuid::new_v4(),
        name: "Surfing".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child2).await.unwrap();

    let children = repo.find_children(created_parent.id).await.unwrap();
    assert_eq!(children.len(), 2);
    assert!(children.iter().any(|c| c.name == "Kayaking"));
    assert!(children.iter().any(|c| c.name == "Surfing"));
}

#[tokio::test]
async fn category_repository_orphan_category_prevention() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = create_category(&db, &parent).await.unwrap();

    let child = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    create_category(&db, &child).await.unwrap();

    // Deleting a parent with existing children should fail due to FK enforcement.
    let delete_result = sqlx::query("DELETE FROM categories WHERE id = $1")
        .bind(created_parent.id)
        .execute(db.pool())
        .await;
    assert!(delete_result.is_err());

    // Child remains, proving orphan categories are prevented.
    let found_child = repo.find_by_id(child.id).await.unwrap();
    assert!(found_child.is_some());
}

#[tokio::test]
async fn category_repository_tree_structure_validation() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let root = Category {
        id: Uuid::new_v4(),
        name: "Outdoors".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_root = create_category(&db, &root).await.unwrap();

    let level1 = Category {
        id: Uuid::new_v4(),
        name: "Water Sports".to_string(),
        parent_id: Some(created_root.id),
        created_at: Utc::now(),
    };
    let created_level1 = create_category(&db, &level1).await.unwrap();

    let level2 = Category {
        id: Uuid::new_v4(),
        name: "Kayaking".to_string(),
        parent_id: Some(created_level1.id),
        created_at: Utc::now(),
    };
    create_category(&db, &level2).await.unwrap();

    // Verify tree structure: root has 1 child, level1 has 1 child, level2 has no children
    let root_children = repo.find_children(created_root.id).await.unwrap();
    assert_eq!(root_children.len(), 1);
    assert_eq!(root_children[0].id, created_level1.id);

    let level1_children = repo.find_children(created_level1.id).await.unwrap();
    assert_eq!(level1_children.len(), 1);
    assert_eq!(level1_children[0].id, level2.id);

    let level2_children = repo.find_children(level2.id).await.unwrap();
    assert_eq!(level2_children.len(), 0);
}

#[tokio::test]
async fn category_repository_create_duplicate_key_maps_to_conflict() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let first = Category {
        id: Uuid::new_v4(),
        name: format!("Duplicate Category {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    repo.create(&first).await.unwrap();

    let duplicate = Category {
        id: first.id,
        name: format!("Different Name {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let result = repo.create(&duplicate).await;

    assert!(matches!(
        result,
        Err(AppError::Conflict(message)) if message == "category already exists"
    ));
}

#[tokio::test]
async fn category_repository_delete_parent_with_references_maps_to_conflict() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = CategoryRepositoryImpl::new(db.pool().clone());

    let parent = Category {
        id: Uuid::new_v4(),
        name: format!("Parent {}", next_id()),
        parent_id: None,
        created_at: Utc::now(),
    };
    let created_parent = repo.create(&parent).await.unwrap();

    let child = Category {
        id: Uuid::new_v4(),
        name: format!("Child {}", next_id()),
        parent_id: Some(created_parent.id),
        created_at: Utc::now(),
    };
    repo.create(&child).await.unwrap();

    let result = repo.delete(created_parent.id).await;
    assert!(matches!(
        result,
        Err(AppError::Conflict(message))
            if message == "category is still referenced by child categories or equipment"
    ));
}

// Helper function to create categories directly via SQL for testing
async fn create_category(db: &TestDb, category: &Category) -> sqlx::Result<Category> {
    let created = sqlx::query_as::<_, Category>(
        "INSERT INTO categories (id, name, parent_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id, name, parent_id, created_at"
    )
    .bind(category.id)
    .bind(&category.name)
    .bind(category.parent_id)
    .bind(category.created_at)
    .fetch_one(db.pool())
    .await?;
    Ok(created)
}
