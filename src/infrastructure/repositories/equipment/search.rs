use crate::domain::Equipment;
use crate::error::AppResult;
use crate::infrastructure::repositories::traits::EquipmentSearchParams;
use sqlx::{PgPool, Postgres, QueryBuilder};

pub async fn search(
    pool: &PgPool,
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
        .fetch_all(pool)
        .await?;
    Ok(equipment)
}

pub async fn count_search(pool: &PgPool, params: &EquipmentSearchParams) -> AppResult<i64> {
    let mut builder = QueryBuilder::<Postgres>::new(
        r#"
        SELECT COUNT(*) AS count
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

    if let Some(((latitude, longitude), radius_km)) =
        params.latitude.zip(params.longitude).zip(params.radius_km)
    {
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

    let (count,): (i64,) = builder.build_query_as().fetch_one(pool).await?;
    Ok(count)
}
