use crate::domain::{Equipment, EquipmentPhoto};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::traits::{
    EquipmentRepository, EquipmentSearchParams, EquipmentWithOwner,
};
use crate::infrastructure::repositories::utils::escape_like_pattern;
use async_trait::async_trait;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub mod photo;
pub mod search;

pub struct EquipmentRepositoryImpl {
    pool: PgPool,
}

impl EquipmentRepositoryImpl {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EquipmentRepository for EquipmentRepositoryImpl {
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<Equipment>> {
        let equipment = sqlx::query_as::<_, Equipment>(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(equipment)
    }

    async fn find_all(&self, limit: i64, offset: i64) -> AppResult<Vec<Equipment>> {
        let equipment = sqlx::query_as::<_, Equipment>(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(equipment)
    }

    async fn search(
        &self,
        params: &EquipmentSearchParams,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Equipment>> {
        search::search(&self.pool, params, limit, offset).await
    }

    async fn count_search(&self, params: &EquipmentSearchParams) -> AppResult<i64> {
        search::count_search(&self.pool, params).await
    }

    async fn find_by_owner(&self, owner_id: Uuid) -> AppResult<Vec<Equipment>> {
        let equipment = sqlx::query_as::<_, Equipment>(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE owner_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(owner_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(equipment)
    }

    async fn count_by_owner(&self, owner_id: Uuid) -> AppResult<i64> {
        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM equipment
            WHERE owner_id = $1
            "#,
        )
        .bind(owner_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn count_by_owners(&self, owner_ids: &[Uuid]) -> AppResult<HashMap<Uuid, i64>> {
        if owner_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = sqlx::query_as::<_, (Uuid, i64)>(
            r#"
            SELECT owner_id, COUNT(*)::BIGINT AS count
            FROM equipment
            WHERE owner_id = ANY($1)
            GROUP BY owner_id
            "#,
        )
        .bind(owner_ids)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    async fn create(&self, equipment: &Equipment) -> AppResult<Equipment> {
        let created = sqlx::query_as::<_, Equipment>(
            r#"
            INSERT INTO equipment (id, owner_id, category_id, title, description, daily_rate, condition, location, coordinates, is_available, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ST_SetSRID(ST_MakePoint(CAST($9 AS float), CAST($10 AS float)), 4326)::geography, $11, $12, $13)
            RETURNING id, owner_id, category_id, title, description, daily_rate, condition,
                      location, coordinates::text as coordinates, is_available, created_at, updated_at
            "#
        )
        .bind(equipment.id)
        .bind(equipment.owner_id)
        .bind(equipment.category_id)
        .bind(&equipment.title)
        .bind(&equipment.description)
        .bind(equipment.daily_rate)
        .bind(equipment.condition)
        .bind(&equipment.location)
        .bind(equipment.coordinates_tuple().map(|(_lat, lng)| lng))
        .bind(equipment.coordinates_tuple().map(|(lat, _lng)| lat))
        .bind(equipment.is_available)
        .bind(equipment.created_at)
        .bind(equipment.updated_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }

    async fn update(&self, equipment: &Equipment) -> AppResult<Equipment> {
        let updated = sqlx::query_as::<_, Equipment>(
            r#"
            UPDATE equipment
            SET title = $2, description = $3, daily_rate = $4, condition = $5, location = $6,
                coordinates = ST_SetSRID(ST_MakePoint(CAST($7 AS float), CAST($8 AS float)), 4326)::geography,
                is_available = $9
            WHERE id = $1
            RETURNING id, owner_id, category_id, title, description, daily_rate, condition,
                      location, coordinates::text as coordinates, is_available, created_at, updated_at
            "#
        )
        .bind(equipment.id)
        .bind(&equipment.title)
        .bind(&equipment.description)
        .bind(equipment.daily_rate)
        .bind(equipment.condition)
        .bind(&equipment.location)
        .bind(equipment.coordinates_tuple().map(|(_lat, lng)| lng))
        .bind(equipment.coordinates_tuple().map(|(lat, _lng)| lat))
        .bind(equipment.is_available)
        .fetch_one(&self.pool)
        .await?;
        Ok(updated)
    }

    async fn delete(&self, id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM equipment WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_availability_atomic(&self, id: Uuid, is_available: bool) -> AppResult<bool> {
        let updated = sqlx::query_as::<_, (bool,)>(
            r#"
            UPDATE equipment
            SET is_available = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING is_available
            "#,
        )
        .bind(id)
        .bind(is_available)
        .fetch_optional(&self.pool)
        .await?;

        updated
            .map(|(value,)| value)
            .ok_or_else(|| AppError::NotFound("equipment not found".to_string()))
    }

    async fn count_all(&self, search: Option<&str>) -> AppResult<i64> {
        let escaped_search = search.map(escape_like_pattern);
        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM equipment e
            JOIN profiles p ON p.id = e.owner_id
            JOIN categories c ON c.id = e.category_id
            WHERE ($1::TEXT IS NULL OR e.title ILIKE '%' || $1 || '%' ESCAPE '' OR p.email ILIKE '%' || $1 || '%' ESCAPE '')
            "#,
        )
        .bind(escaped_search.as_deref())
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    async fn list_all_with_owner(
        &self,
        limit: i64,
        offset: i64,
        search: Option<&str>,
    ) -> AppResult<Vec<EquipmentWithOwner>> {
        let escaped_search = search.map(escape_like_pattern);
        let rows = sqlx::query_as::<_, EquipmentWithOwner>(
            r#"
            SELECT
                e.id,
                e.owner_id,
                e.category_id,
                e.title,
                e.daily_rate,
                e.is_available,
                e.created_at,
                p.email AS owner_email,
                c.name AS category_name
            FROM equipment e
            JOIN profiles p ON p.id = e.owner_id
            JOIN categories c ON c.id = e.category_id
            WHERE ($3::TEXT IS NULL OR e.title ILIKE '%' || $3 || '%' ESCAPE '' OR p.email ILIKE '%' || $3 || '%' ESCAPE '')
            ORDER BY e.created_at DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(limit)
        .bind(offset)
        .bind(escaped_search.as_deref())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn add_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
        photo::add_photo(&self.pool, photo).await
    }

    async fn find_photos(&self, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        photo::find_photos(&self.pool, equipment_id).await
    }

    async fn delete_photo(&self, photo_id: Uuid) -> AppResult<()> {
        photo::delete_photo(&self.pool, photo_id).await
    }
}
