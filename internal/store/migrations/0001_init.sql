-- Times are stored as UTC unix seconds (INTEGER); nullable times are NULL.
CREATE TABLE services (
    key            TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    state          TEXT NOT NULL,
    overrides_json TEXT NOT NULL DEFAULT '{}',
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    removed_after  INTEGER
);

-- Ownership is per (provider, zone, name, type): at most one record of a given
-- type per name is managed by us (round-robin/multi-value sets are out of
-- scope); value is mutable and not part of the key. name is stored lowercase
-- without trailing dot and type uppercase (normalized by the store). A row's
-- owner_key cannot be taken over by another owner (enforced in AddOwnedRecord).
CREATE TABLE dns_records (
    provider           TEXT NOT NULL,
    zone               TEXT NOT NULL,
    name               TEXT NOT NULL,
    type               TEXT NOT NULL,
    value              TEXT NOT NULL,
    provider_record_id TEXT NOT NULL DEFAULT '',
    owner_key          TEXT NOT NULL DEFAULT '',
    created_at         INTEGER NOT NULL,
    removed_after      INTEGER,
    PRIMARY KEY (provider, zone, name, type)
);

CREATE TABLE certs (
    id           TEXT PRIMARY KEY,
    zone         TEXT NOT NULL,
    domains_json TEXT NOT NULL DEFAULT '[]',
    issuer       TEXT NOT NULL DEFAULT '',
    staging      INTEGER NOT NULL DEFAULT 0,
    not_after    INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    last_result  TEXT NOT NULL DEFAULT '',
    last_error   TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    managed      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE activity (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    level   TEXT NOT NULL,
    kind    TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX activity_ts ON activity (ts DESC, id DESC);

CREATE TABLE kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
