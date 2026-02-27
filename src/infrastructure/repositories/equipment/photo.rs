use crate::domain::EquipmentPhoto;
use crate::error::AppResult;
use sqlx::{PgPool};
use uuid::Uuid;

pub async fn add_photo(pool: &PgPool, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
    let created = sqlx::query_as::<_, EquipmentPhoto>(
        r#"
        INSERT INTO equipment_photos (id, equipment_id, photo_url, is_primary, order_index, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, equipment_id, photo_url, is_primary, order_index, created_at
        "#
    )
    .bind(photo.id)
    .bind(photo.equipment_id)
    .bind(&photo.photo_url)
    .bind(photo.is_primary)
    .bind(photo.order_index)
    .bind(photo.created_at)
    .fetch_one(pool)
    .await?;
    Ok(created)
}

pub async fn find_photos(pool: &PgPool, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
    let photos = sqlx::query_as::<_, EquipmentPhoto>(
        "SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE equipment_id = $1 ORDER BY order_index"
    )
    .bind(equipment_id)
    .fetch_all(pool)
    .await?;
    Ok(photos)
}

pub async fn delete_photo(pool: &PgPool, photo_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM equipment_photos WHERE id = $1")
        .bind(photo_id)
        .execute(pool)
        .await?;
    Ok(())
}
