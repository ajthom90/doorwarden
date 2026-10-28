package store

import (
	"context"
	"database/sql"
	"time"
)

// Service is a discovered service. FirstSeen is set on insert and preserved on update.
type Service struct {
	Key           string
	Source        string
	State         string
	OverridesJSON string
	FirstSeen     time.Time
	LastSeen      time.Time
	RemovedAfter  *time.Time
}

// UpsertService inserts or updates by key, keeping the original first_seen.
func (s *Store) UpsertService(ctx context.Context, v Service) error {
	if v.OverridesJSON == "" {
		v.OverridesJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO services (key, source, state, overrides_json, first_seen, last_seen, removed_after)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET source=excluded.source, state=excluded.state,
			overrides_json=excluded.overrides_json, last_seen=excluded.last_seen, removed_after=excluded.removed_after`,
		v.Key, v.Source, v.State, v.OverridesJSON, toUnix(v.FirstSeen), toUnix(v.LastSeen), nullTime(v.RemovedAfter))
	return err
}

// ListServices returns all services ordered by key.
func (s *Store) ListServices(ctx context.Context) ([]Service, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, source, state, overrides_json, first_seen, last_seen, removed_after FROM services ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Service
	for rows.Next() {
		var v Service
		var fs, ls int64
		var ra sql.NullInt64
		if err := rows.Scan(&v.Key, &v.Source, &v.State, &v.OverridesJSON, &fs, &ls, &ra); err != nil {
			return nil, err
		}
		v.FirstSeen, v.LastSeen, v.RemovedAfter = fromUnix(fs), fromUnix(ls), scanNullTime(ra)
		out = append(out, v)
	}
	return out, rows.Err()
}
