package store

import (
	"context"
	"strings"
)

// ListSettingKeys returns the kv keys starting with prefix, sorted.
func (s *Store) ListSettingKeys(ctx context.Context, prefix string) ([]string, error) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
	rows, err := s.db.QueryContext(ctx, `SELECT key FROM kv WHERE key LIKE ? ESCAPE '\' ORDER BY key`, esc+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		// LIKE is case-insensitive for ASCII in SQLite; keep exact prefixes.
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}
