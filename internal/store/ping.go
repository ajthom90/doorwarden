package store

import (
	"context"
	"fmt"
)

// Ping reports whether the store is usable: the database answers a read
// and accepts a write. The write probe runs in a transaction that is rolled
// back, so nothing persists. It is the /healthz store check.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: ping: %w", err)
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		return fmt.Errorf("store: read probe: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: write probe: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // the probe is always rolled back
	if _, err := tx.ExecContext(ctx, `INSERT INTO kv (key, value) VALUES ('health/probe', '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
		return fmt.Errorf("store: write probe: %w", err)
	}
	return nil
}
