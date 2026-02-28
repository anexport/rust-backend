import re

def fix_mod_rs():
    with open('src/infrastructure/repositories/equipment/mod.rs', 'r') as f:
        content = f.read()

    # We need to manually fix this properly. I will write python to do exact string replacements on blocks.
    
    # 1. find_by_id
    content = content.replace('''        let equipment = sqlx::query_as::<_, Equipment>(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)''', '''        let equipment = sqlx::query_as!(
            Equipment,
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition as "condition: _",
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)''')

    # 2. find_all
    content = content.replace('''        let equipment = sqlx::query_as::<_, Equipment>(
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
        .fetch_all(&self.pool)''', '''        let equipment = sqlx::query_as!(
            Equipment,
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition as "condition: _",
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&self.pool)''')

    # 3. find_by_owner
    content = content.replace('''        let equipment = sqlx::query_as::<_, Equipment>(
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition,
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE owner_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(owner_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)''', '''        let equipment = sqlx::query_as!(
            Equipment,
            r#"
            SELECT id, owner_id, category_id, title, description, daily_rate, condition as "condition: _",
                   location, coordinates::text as coordinates, is_available, created_at, updated_at
            FROM equipment WHERE owner_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            owner_id,
            limit,
            offset
        )
        .fetch_all(&self.pool)''')

    # 4. count_by_owner
    content = content.replace('''        let (count,): (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*)::BIGINT
            FROM equipment
            WHERE owner_id = $1
            "#,
        )
        .bind(owner_id)
        .fetch_one(&self.pool)''', '''        let record = sqlx::query!(
            r#"
            SELECT COUNT(*)::BIGINT as count
            FROM equipment
            WHERE owner_id = $1
            "#,
            owner_id
        )
        .fetch_one(&self.pool)''').replace('Ok(count)', 'Ok(record.count.unwrap_or(0))')

    # 5. count_by_owners (Skipping query_as! here because ANY($1) is notoriously tricky with SQLx macros without specific driver support)
    # The requirement specifically mentions find_by_owner and update_photo_availability, we will skip ANY($1) if needed, but let's try it.
    
    with open('src/infrastructure/repositories/equipment/mod.rs', 'w') as f:
        f.write(content)

fix_mod_rs()
