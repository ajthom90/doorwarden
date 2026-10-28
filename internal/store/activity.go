package store

import (
	"context"
	"time"
)

// ActivityEntry is one line of the activity log.
type ActivityEntry struct {
	TS      time.Time
	Level   string
	Kind    string
	Message string
}

// AppendActivity appends an entry.
func (s *Store) AppendActivity(ctx context.Context, e ActivityEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO activity (ts, level, kind, message) VALUES (?, ?, ?, ?)`,
		toUnix(e.TS), e.Level, e.Kind, e.Message)
	return err
}

// ListActivity returns up to limit entries, newest first.
func (s *Store) ListActivity(ctx context.Context, limit int) ([]ActivityEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, level, kind, message FROM activity ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActivityEntry
	for rows.Next() {
		var e ActivityEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Level, &e.Kind, &e.Message); err != nil {
			return nil, err
		}
		e.TS = fromUnix(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
