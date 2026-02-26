-- Add full btree index on is_available column
-- This complements the existing partial index WHERE is_available = TRUE
--
-- DESIGN NOTE: This full index has low selectivity for boolean columns.
-- Consideration: If queries for is_available = FALSE become common, a partial
-- index (WHERE is_available = FALSE) would be more efficient. Kept as a full
-- index for now since both values may be queried and this provides simpler
-- query planning without index hints.
CREATE INDEX IF NOT EXISTS idx_equipment_is_available ON equipment(is_available);
