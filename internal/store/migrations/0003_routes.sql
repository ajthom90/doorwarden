-- The persisted route set: one route per service key, maintained only by the
-- reconciler's RouteWrite/RouteRemove/ScheduleRemoval/CancelRemoval actions
-- and rendered by the Traefik writer. hostname and zone are stored lowercase
-- without trailing dot. hostname is deliberately NOT unique: a hostname
-- conflict loser may share it with the winner until its RouteRemove applies.
-- removed_after and updated_at are UTC unix seconds.
CREATE TABLE routes (
    key              TEXT PRIMARY KEY,
    source           TEXT NOT NULL,
    zone             TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    scheme           TEXT NOT NULL,
    host             TEXT NOT NULL,
    port             INTEGER NOT NULL,
    skip_verify      INTEGER NOT NULL DEFAULT 0,
    websockets       INTEGER NOT NULL DEFAULT 0,
    middlewares_json TEXT NOT NULL DEFAULT '[]',
    removed_after    INTEGER NULL,
    updated_at       INTEGER NOT NULL
);
CREATE INDEX routes_hostname ON routes (hostname);
