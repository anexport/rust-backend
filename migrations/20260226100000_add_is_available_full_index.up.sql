-- Add full btree index on is_available column
-- This complements the existing partial index WHERE is_available = TRUE
CREATE INDEX IF NOT EXISTS idx_equipment_is_available ON equipment(is_available);
