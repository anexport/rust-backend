use super::traits::{EquipmentRepository, EquipmentSearchParams};
use crate::domain::{Equipment, EquipmentPhoto};
use crate::error::AppResult;
use async_trait::async_trait;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

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
        let mut builder = QueryBuilder::<Postgres>::new(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment
            WHERE 1=1
            "#,
        );

        if let Some(category_id) = params.category_id {
            builder.push(" AND category_id = ");
            builder.push_bind(category_id);
        }
        if let Some(min_price) = params.min_price {
            builder.push(" AND daily_rate >= ");
            builder.push_bind(min_price);
        }
        if let Some(max_price) = params.max_price {
            builder.push(" AND daily_rate <= ");
            builder.push_bind(max_price);
        }
        if let Some(is_available) = params.is_available {
            builder.push(" AND is_available = ");
            builder.push_bind(is_available);
        }

        let geo_filter = params.latitude.zip(params.longitude).zip(params.radius_km);
        if let Some(((latitude, longitude), radius_km)) = geo_filter {
            builder.push(
                " AND coordinates IS NOT NULL AND ST_DWithin(
                    coordinates,
                    ST_SetSRID(ST_MakePoint(",
            );
            builder.push_bind(longitude);
            builder.push(", ");
            builder.push_bind(latitude);
            builder.push("), 4326)::geography, ");
            builder.push_bind(radius_km * 1000.0);
            builder.push(")");
        }

        if let Some(((latitude, longitude), _)) = geo_filter {
            builder.push(
                " ORDER BY ST_Distance(
                    coordinates,
                    ST_SetSRID(ST_MakePoint(",
            );
            builder.push_bind(longitude);
            builder.push(", ");
            builder.push_bind(latitude);
            builder.push("), 4326)::geography");
        } else {
            builder.push(" ORDER BY created_at DESC");
        }

        builder.push(" LIMIT ");
        builder.push_bind(limit);
        builder.push(" OFFSET ");
        builder.push_bind(offset);

        let equipment = builder
            .build_query_as::<Equipment>()
            .fetch_all(&self.pool)
            .await?;
        Ok(equipment)
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

    async fn add_photo(&self, photo: &EquipmentPhoto) -> AppResult<EquipmentPhoto> {
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
        .fetch_one(&self.pool)
        .await?;
        Ok(created)
    }

    async fn find_photos(&self, equipment_id: Uuid) -> AppResult<Vec<EquipmentPhoto>> {
        let photos = sqlx::query_as::<_, EquipmentPhoto>(
            "SELECT id, equipment_id, photo_url, is_primary, order_index, created_at FROM equipment_photos WHERE equipment_id = $1 ORDER BY order_index"
        )
        .bind(equipment_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(photos)
    }

    async fn delete_photo(&self, photo_id: Uuid) -> AppResult<()> {
        sqlx::query("DELETE FROM equipment_photos WHERE id = $1")
            .bind(photo_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
