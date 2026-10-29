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

// ErrStaleCredentials is returned when the administrator's credential
// generation is not the one the caller verified against: a concurrent
// password change or reset won, so the operation must not take effect.
var ErrStaleCredentials = errors.New("store: credentials changed concurrently")

// Admin is the local administrator. Generation is the credential
// generation: it increases on every password change or reset.
type Admin struct {
	Username     string
	PasswordHash string
	CreatedAt    time.Time
	Generation   int64
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
	err := s.db.QueryRowContext(ctx, `SELECT username, password_hash, created_at, credential_generation FROM admins WHERE id = 1`).
		Scan(&a.Username, &a.PasswordHash, &ts, &a.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, false, nil
	}
	if err != nil {
		return Admin{}, false, err
	}
	a.CreatedAt = fromUnix(ts)
	return a, true, nil
}

// ChangeAdminPassword replaces the password hash only if the credential
// generation is still expectGen, bumps the generation and deletes every
// session, all in one transaction. It returns the new generation, or
// ErrStaleCredentials when another change won.
func (s *Store) ChangeAdminPassword(ctx context.Context, passwordHash string, expectGen int64) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	res, err := tx.ExecContext(ctx, `UPDATE admins SET password_hash = ?, credential_generation = credential_generation + 1
		WHERE id = 1 AND credential_generation = ?`, passwordHash, expectGen)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n == 0 {
		return 0, ErrStaleCredentials
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expectGen + 1, nil
}

// ResetCredentials bumps the credential generation unconditionally and
// deletes every session in one transaction; a non-empty passwordHash also
// replaces the password. It is the out-of-band recovery path (CLI).
func (s *Store) ResetCredentials(ctx context.Context, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	res, err := tx.ExecContext(ctx, `UPDATE admins SET credential_generation = credential_generation + 1,
		password_hash = CASE WHEN ? = '' THEN password_hash ELSE ? END WHERE id = 1`, passwordHash, passwordHash)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errors.New("store: no administrator")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
		return err
	}
	return tx.Commit()
}

// Session is a login session (see migration 0004).
type Session struct {
	IDHash    string
	Username  string
	CSRF      string
	CreatedAt time.Time
	LastSeen  time.Time
	// Generation is the admin credential generation the password was
	// verified against.
	Generation int64
}

// CreateSession inserts a session only if v.Generation is still the
// administrator's credential generation. The check and the insert are one
// statement, so a password change that commits first makes this fail with
// ErrStaleCredentials instead of leaving a session minted from the old
// password.
func (s *Store) CreateSession(ctx context.Context, v Session) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO sessions (id_hash, username, csrf, created_at, last_seen, generation)
		SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM admins WHERE id = 1 AND credential_generation = ?)`,
		v.IDHash, v.Username, v.CSRF, toUnix(v.CreatedAt), toUnix(v.LastSeen), v.Generation, v.Generation)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrStaleCredentials
	}
	return nil
}

// GetSession returns the session with idHash; ok is false when there is none.
func (s *Store) GetSession(ctx context.Context, idHash string) (Session, bool, error) {
	v := Session{IDHash: idHash}
	var c, l int64
	err := s.db.QueryRowContext(ctx, `SELECT s.username, s.csrf, s.created_at, s.last_seen, s.generation
		FROM sessions s JOIN admins a ON a.id = 1 AND a.credential_generation = s.generation
		WHERE s.id_hash = ?`, idHash).
		Scan(&v.Username, &v.CSRF, &c, &l, &v.Generation)
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
