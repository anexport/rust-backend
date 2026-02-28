use crate::domain::EquipmentPhoto;
use crate::error::AppResult;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn add_photo(pool: &PgPool, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
    let created = sqlx::query_as!(
        EquipmentPhoto,
        r#"
        INSERT INTO equipment_photos (id, equipment_id, photo_url, is_primary, order_index, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, equipment_id, photo_url, is_primary, order_index, created_at
        "#,
        photo.id,
        photo.equipment_id,
        photo.photo_url,
        photo.is_primary,
        photo.order_index,
        photo.created_at
    )
    .fetch_one(pool)
    .await?;
    Ok(created)
}

pub async fn find_photos(pool: &PgPool, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
    let photos = sqlx::query_as!(
        EquipmentPhoto,
        "SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE equipment_id = $1 ORDER BY order_index",
        equipment_id
    )
    .fetch_all(pool)
    .await?;
    Ok(photos)
}

pub async fn find_photo_by_id(pool: &PgPool, photo_id: Uuid) -> AppResult<Option<EquipmentPhoto>> {
    let photo = sqlx::query_as!(
        EquipmentPhoto,
        "SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE id = $1",
        photo_id
    )
    .fetch_optional(pool)
    .await?;
    Ok(photo)
}

pub async fn update_photo(pool: &PgPool, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
    let updated = sqlx::query_as!(
        EquipmentPhoto,
        r#"
        UPDATE equipment_photos 
        SET photo_url = $1, is_primary = $2, order_index = $3
        WHERE id = $4
        RETURNING id, equipment_id, photo_url, is_primary, order_index, created_at
        "#,
        photo.photo_url,
        photo.is_primary,
        photo.order_index,
        photo.id
    )
    .fetch_one(pool)
    .await?;
    Ok(updated)
}

pub async fn delete_photo(pool: &PgPool, photo_id: Uuid) -> AppResult<()> {
    sqlx::query!("DELETE FROM equipment_photos WHERE id = $1", photo_id)
        .execute(pool)
        .await?;
    Ok(())
}
