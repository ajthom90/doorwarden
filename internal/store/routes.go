package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrRouteNotFound is returned by SetRouteRemoval when no route exists for
// the key. Nothing is written in that case.
var ErrRouteNotFound = errors.New("store: route not found")

// Route is one persisted route, keyed by service key. It is the source of
// truth the Traefik writer renders from; only the reconciler's route actions
// change it.
type Route struct {
	Key, Source, Zone, Hostname, Scheme, Host string
	Port                                      int
	SkipVerify, Websockets                    bool
	// Middlewares is nil when there are none.
	Middlewares []string
	// RemovedAfter is the scheduled removal time. UpsertRoute ignores it;
	// only SetRouteRemoval changes it.
	RemovedAfter *time.Time
	UpdatedAt    time.Time
}

func normRouteName(n string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(n)), ".")
}

// normalize returns r with names normalized, or an error if r cannot be
// routed. A route with an empty backend can never be persisted.
func (r Route) normalize() (Route, error) {
	r.Key = strings.TrimSpace(r.Key)
	r.Source = strings.TrimSpace(r.Source)
	r.Zone = normRouteName(r.Zone)
	r.Hostname = normRouteName(r.Hostname)
	r.Scheme = strings.ToLower(strings.TrimSpace(r.Scheme))
	r.Host = strings.TrimSpace(r.Host)
	var probs []string
	if r.Key == "" {
		probs = append(probs, "empty key")
	}
	// An empty source would make the reconciler treat the route as "source
	// unknown" forever, so it could never be removed.
	if r.Source == "" {
		probs = append(probs, "empty source")
	}
	if r.Zone == "" {
		probs = append(probs, "empty zone")
	}
	if r.Hostname == "" {
		probs = append(probs, "empty hostname")
	}
	if r.Scheme != "http" && r.Scheme != "https" {
		probs = append(probs, fmt.Sprintf("scheme %q must be http or https", r.Scheme))
	}
	if r.Host == "" {
		probs = append(probs, "empty backend host")
	}
	if r.Port < 1 || r.Port > 65535 {
		probs = append(probs, fmt.Sprintf("backend port %d out of range 1..65535", r.Port))
	}
	if len(probs) > 0 {
		return r, fmt.Errorf("store: invalid route %q: %s", r.Key, strings.Join(probs, "; "))
	}
	return r, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UpsertRoute inserts or replaces the route for r.Key after normalizing
// (zone/hostname lowercase without trailing dot, scheme lowercase) and
// validating it; an invalid route returns an error and writes nothing.
// r.RemovedAfter is ignored: an existing removal schedule is preserved and a
// new row starts without one (use SetRouteRemoval). A zero UpdatedAt is
// stored as the current time.
func (s *Store) UpsertRoute(ctx context.Context, r Route) error {
	r, err := r.normalize()
	if err != nil {
		return err
	}
	mw := r.Middlewares
	if mw == nil {
		mw = []string{}
	}
	mwJSON, err := json.Marshal(mw)
	if err != nil {
		return err
	}
	upd := r.UpdatedAt
	if upd.IsZero() {
		upd = time.Now()
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO routes
		(key, source, zone, hostname, scheme, host, port, skip_verify, websockets, middlewares_json, removed_after, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
		ON CONFLICT(key) DO UPDATE SET source=excluded.source, zone=excluded.zone, hostname=excluded.hostname,
			scheme=excluded.scheme, host=excluded.host, port=excluded.port, skip_verify=excluded.skip_verify,
			websockets=excluded.websockets, middlewares_json=excluded.middlewares_json, updated_at=excluded.updated_at`,
		r.Key, r.Source, r.Zone, r.Hostname, r.Scheme, r.Host, r.Port, boolInt(r.SkipVerify), boolInt(r.Websockets),
		string(mwJSON), toUnix(upd))
	return err
}

// DeleteRoute removes the route for key; absent is not an error.
func (s *Store) DeleteRoute(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM routes WHERE key = ?`, strings.TrimSpace(key))
	return err
}

// SetRouteRemoval sets (at non-nil) or clears (at nil) the scheduled removal
// of key's route. It returns ErrRouteNotFound, writing nothing, when there is
// no route for key.
func (s *Store) SetRouteRemoval(ctx context.Context, key string, at *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE routes SET removed_after = ? WHERE key = ?`, nullTime(at), strings.TrimSpace(key))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %q", ErrRouteNotFound, key)
	}
	return nil
}

const routeCols = `key, source, zone, hostname, scheme, host, port, skip_verify, websockets, middlewares_json, removed_after, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanRoute(sc rowScanner) (Route, error) {
	var (
		r          Route
		sv, ws     int
		mwJSON     string
		removed    sql.NullInt64
		updatedSec int64
	)
	if err := sc.Scan(&r.Key, &r.Source, &r.Zone, &r.Hostname, &r.Scheme, &r.Host, &r.Port, &sv, &ws, &mwJSON,
		&removed, &updatedSec); err != nil {
		return Route{}, err
	}
	r.SkipVerify, r.Websockets = sv != 0, ws != 0
	if err := json.Unmarshal([]byte(mwJSON), &r.Middlewares); err != nil {
		return Route{}, fmt.Errorf("store: route %q middlewares: %w", r.Key, err)
	}
	if len(r.Middlewares) == 0 {
		r.Middlewares = nil
	}
	r.RemovedAfter = scanNullTime(removed)
	r.UpdatedAt = fromUnix(updatedSec)
	return r, nil
}

// GetRoute returns the route for key; ok is false when there is none.
func (s *Store) GetRoute(ctx context.Context, key string) (Route, bool, error) {
	r, err := scanRoute(s.db.QueryRowContext(ctx, `SELECT `+routeCols+` FROM routes WHERE key = ?`, strings.TrimSpace(key)))
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, false, nil
	}
	if err != nil {
		return Route{}, false, err
	}
	return r, true, nil
}

// ListRoutes returns all routes sorted by key.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+routeCols+` FROM routes ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
