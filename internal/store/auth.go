package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrAdminExists is returned by CreateAdmin when the administrator already
// exists.
var ErrAdminExists = errors.New("store: an administrator already exists")

// Admin is the local administrator.
type Admin struct {
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

// CreateAdmin inserts the administrator. The table holds at most one row
// (id = 1), so of two concurrent calls exactly one succeeds; the other gets
// ErrAdminExists.
func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admins (id, username, password_hash, created_at) VALUES (1, ?, ?, ?)`,
		username, passwordHash, toUnix(now))
	if err != nil && isConstraint(err) {
		return ErrAdminExists
	}
	return err
}

func isConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "constraint")
}

// GetAdmin returns the administrator; ok is false when there is none.
func (s *Store) GetAdmin(ctx context.Context) (Admin, bool, error) {
	var a Admin
	var ts int64
	err := s.db.QueryRowContext(ctx, `SELECT username, password_hash, created_at FROM admins WHERE id = 1`).
		Scan(&a.Username, &a.PasswordHash, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, false, nil
	}
	if err != nil {
		return Admin{}, false, err
	}
	a.CreatedAt = fromUnix(ts)
	return a, true, nil
}

// SetAdminPassword replaces the administrator's password hash.
func (s *Store) SetAdminPassword(ctx context.Context, passwordHash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET password_hash = ? WHERE id = 1`, passwordHash)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return errors.New("store: no administrator")
	}
	return nil
}

// Session is a login session (see migration 0004).
type Session struct {
	IDHash    string
	Username  string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
}

// CreateSession inserts a session.
func (s *Store) CreateSession(ctx context.Context, v Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, username, csrf, created_at, last_seen) VALUES (?, ?, ?, ?, ?)`,
		v.IDHash, v.Username, v.CSRF, toUnix(v.CreatedAt), toUnix(v.LastSeen))
	return err
}

// GetSession returns the session with idHash; ok is false when there is none.
func (s *Store) GetSession(ctx context.Context, idHash string) (Session, bool, error) {
	v := Session{IDHash: idHash}
	var c, l int64
	err := s.db.QueryRowContext(ctx, `SELECT username, csrf, created_at, last_seen FROM sessions WHERE id_hash = ?`, idHash).
		Scan(&v.Username, &v.CSRF, &c, &l)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	v.CreatedAt, v.LastSeen = fromUnix(c), fromUnix(l)
	return v, true, nil
}

// TouchSession records activity on a session.
func (s *Store) TouchSession(ctx context.Context, idHash string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, toUnix(now), idHash)
	return err
}

// DeleteSession removes a session; a missing one is not an error.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteAllSessions removes every session (password change).
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

// DeleteExpiredSessions removes sessions last seen before idleBefore or
// created before createdBefore, and returns how many it removed.
func (s *Store) DeleteExpiredSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen < ? OR created_at < ?`,
		toUnix(idleBefore), toUnix(createdBefore))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
