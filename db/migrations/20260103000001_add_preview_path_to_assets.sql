-- migrate:up
ALTER TABLE assets ADD COLUMN preview_path VARCHAR(500);

-- migrate:down
ALTER TABLE assets DROP COLUMN preview_path;
