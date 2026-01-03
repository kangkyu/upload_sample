-- migrate:up
CREATE TABLE youtube_videos (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    youtube_id VARCHAR(20) NOT NULL,
    title VARCHAR(255),
    privacy_status VARCHAR(20) DEFAULT 'private',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id)
);

CREATE INDEX idx_youtube_videos_asset_id ON youtube_videos(asset_id);

-- migrate:down
DROP TABLE IF EXISTS youtube_videos;
