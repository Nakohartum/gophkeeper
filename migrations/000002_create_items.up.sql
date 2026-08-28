CREATE TABLE IF NOT EXISTS items (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    id TEXT NOT NULL,
    ciphertext TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL CHECK (version > 0),
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE INDEX IF NOT EXISTS items_user_updated_idx
    ON items (user_id, updated_at, id);
