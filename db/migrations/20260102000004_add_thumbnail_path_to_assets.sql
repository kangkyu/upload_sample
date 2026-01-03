-- migrate:up
ALTER TABLE assets ADD COLUMN thumbnail_path VARCHAR(500);

-- migrate:down
ALTER TABLE assets DROP COLUMN thumbnail_path;
