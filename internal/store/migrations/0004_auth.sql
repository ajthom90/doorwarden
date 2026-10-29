-- The single local administrator. id is constrained to 1, so a second
-- INSERT fails: first-run setup is race-safe by the primary key alone.
-- password_hash is an argon2id PHC string.
CREATE TABLE admins (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

-- Login sessions. id_hash is the hex SHA-256 of the random session ID (the
-- cookie value is never stored); csrf is the per-session token the client
-- echoes in a header on state-changing requests. Times are UTC unix seconds.
CREATE TABLE sessions (
    id_hash    TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    csrf       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);
