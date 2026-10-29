-- The single local administrator. id is constrained to 1, so a second
-- INSERT fails: first-run setup is race-safe by the primary key alone.
-- password_hash is an argon2id PHC string. credential_generation is bumped
-- (in the same transaction that deletes every session) whenever the
-- credentials change or are reset; a session is only inserted, and only
-- honoured, while its generation equals the admin's.
CREATE TABLE admins (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    username              TEXT NOT NULL,
    password_hash         TEXT NOT NULL,
    created_at            INTEGER NOT NULL,
    credential_generation INTEGER NOT NULL DEFAULT 0
);

-- Login sessions. id_hash is the hex SHA-256 of the random session ID (the
-- cookie value is never stored); csrf is the per-session token the client
-- echoes in a header on state-changing requests. generation is the admin
-- credential_generation the password was verified against. Times are UTC
-- unix seconds.
CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    csrf       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0
);
