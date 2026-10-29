package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// SetApproval records (or replaces) the approval for key with fingerprint.
func (s *Store) SetApproval(ctx context.Context, key, fingerprint string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO approvals (key, fingerprint, approved_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET fingerprint=excluded.fingerprint, approved_at=excluded.approved_at`,
		key, fingerprint, toUnix(time.Now()))
	return err
}

// ClearApproval removes the approval for key; absent is not an error.
func (s *Store) ClearApproval(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM approvals WHERE key = ?`, key)
	return err
}

// GetApproval returns the stored fingerprint for key.
func (s *Store) GetApproval(ctx context.Context, key string) (string, bool, error) {
	var fp string
	err := s.db.QueryRowContext(ctx, `SELECT fingerprint FROM approvals WHERE key = ?`, key).Scan(&fp)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return fp, true, nil
}

// ListApprovals returns key -> fingerprint for all approvals.
func (s *Store) ListApprovals(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, fingerprint FROM approvals`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, f string
		if err := rows.Scan(&k, &f); err != nil {
			return nil, err
		}
		out[k] = f
	}
	return out, rows.Err()
}
