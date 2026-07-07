-- +goose Up
CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

INSERT INTO users (email, password_hash, role)
VALUES
    (
        'admin@nakpanel.test',
        '$argon2id$v=19$m=65536,t=3,p=1$mbXIySwFFOyBbennOd6VXg$t9OemJpWxhoZkhVwLMjs683eTtXPcaMOk31aHZtwWMM',
        'admin'
    ),
    (
        'client@nakpanel.test',
        '$argon2id$v=19$m=65536,t=3,p=1$CtuDwkxvRQbtZgjhC3Jkog$JAqH/qKCmBZdQmLhykEgWmDnYOlHZxAG5vzSf4FViyQ',
        'client'
    )
ON CONFLICT (email) DO UPDATE
SET
    password_hash = EXCLUDED.password_hash,
    role = EXCLUDED.role,
    updated_at = now();

-- +goose Down
DELETE FROM users
WHERE email IN ('admin@nakpanel.test', 'client@nakpanel.test');

DROP TABLE IF EXISTS sessions;
