BEGIN;

ALTER TABLE equipment DROP CONSTRAINT IF EXISTS equipment_owner_id_fkey;
ALTER TABLE equipment ADD CONSTRAINT equipment_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES profiles(id);

ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_sender_id_fkey;
ALTER TABLE messages ADD CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES profiles(id);

COMMIT;
