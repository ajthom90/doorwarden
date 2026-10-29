package store

import (
	"context"
	"database/sql"
	"errors"
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

// TouchService records that a source reported key in state at now: it
// updates source, state and last_seen only (overrides_json and
// removed_after are never touched); a new key is inserted with empty
// overrides, first_seen = now and no scheduled removal.
func (s *Store) TouchService(ctx context.Context, key, source, state string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO services (key, source, state, overrides_json, first_seen, last_seen, removed_after)
		VALUES (?, ?, ?, '{}', ?, ?, NULL)
		ON CONFLICT(key) DO UPDATE SET source=excluded.source, state=excluded.state, last_seen=excluded.last_seen`,
		key, source, state, toUnix(now), toUnix(now))
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

// GetService returns the service row for key; ok is false when there is none.
func (s *Store) GetService(ctx context.Context, key string) (Service, bool, error) {
	v := Service{Key: key}
	var fs, ls int64
	var ra sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT source, state, overrides_json, first_seen, last_seen, removed_after FROM services WHERE key = ?`, key).
		Scan(&v.Source, &v.State, &v.OverridesJSON, &fs, &ls, &ra)
	if errors.Is(err, sql.ErrNoRows) {
		return Service{}, false, nil
	}
	if err != nil {
		return Service{}, false, err
	}
	v.FirstSeen, v.LastSeen, v.RemovedAfter = fromUnix(fs), fromUnix(ls), scanNullTime(ra)
	return v, true, nil
}

// SetServiceOverrides stores the UI overrides of key. It changes only
// overrides_json (the mirror of TouchService, which never touches it); a
// new key is inserted as discovered with first_seen = last_seen = now.
func (s *Store) SetServiceOverrides(ctx context.Context, key, source, overridesJSON string, now time.Time) error {
	if overridesJSON == "" {
		overridesJSON = "{}"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO services (key, source, state, overrides_json, first_seen, last_seen, removed_after)
		VALUES (?, ?, 'discovered', ?, ?, ?, NULL)
		ON CONFLICT(key) DO UPDATE SET overrides_json=excluded.overrides_json`,
		key, source, overridesJSON, toUnix(now), toUnix(now))
	return err
}
