-- Seed baseline equipment categories for listing flows.
INSERT INTO categories (id, name, parent_id)
SELECT '0f6ac2d8-b8d9-4da0-a7a9-38eaec6d093f'::uuid, 'Power Tools', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM categories WHERE id = '0f6ac2d8-b8d9-4da0-a7a9-38eaec6d093f'::uuid
);

INSERT INTO categories (id, name, parent_id)
SELECT 'b1ff7865-0f5d-457c-a790-43658f629fac'::uuid, 'Audio', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM categories WHERE id = 'b1ff7865-0f5d-457c-a790-43658f629fac'::uuid
);

INSERT INTO categories (id, name, parent_id)
SELECT '02a66dc8-2b19-4d81-8893-7ff58f3ec007'::uuid, 'Video', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM categories WHERE id = '02a66dc8-2b19-4d81-8893-7ff58f3ec007'::uuid
);

INSERT INTO categories (id, name, parent_id)
SELECT '8ab4d699-3559-4237-998f-90e4792eec8f'::uuid, 'Lighting', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM categories WHERE id = '8ab4d699-3559-4237-998f-90e4792eec8f'::uuid
);

INSERT INTO categories (id, name, parent_id)
SELECT '70985309-2f6d-4578-90f1-df51fc4f4d3f'::uuid, 'Outdoor Equipment', NULL
WHERE NOT EXISTS (
    SELECT 1 FROM categories WHERE id = '70985309-2f6d-4578-90f1-df51fc4f4d3f'::uuid
);
