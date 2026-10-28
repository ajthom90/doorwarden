package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrOwnerConflict is returned by AddOwnedRecord when a row for the same
// (provider, zone, name, type) already belongs to a different owner_key.
var ErrOwnerConflict = errors.New("store: dns record already owned by a different owner")

// normName lowercases a DNS name and strips trailing dots.
func normName(n string) string { return strings.TrimRight(strings.ToLower(n), ".") }

func normType(t string) string { return strings.ToUpper(t) }

// DNSRecord is a DNS record this tool owns (created and may delete).
type DNSRecord struct {
	Provider         string
	Zone             string
	Name             string
	Type             string
	Value            string
	ProviderRecordID string
	OwnerKey         string
	CreatedAt        time.Time
	RemovedAfter     *time.Time
}

// AddOwnedRecord records ownership of one record. Name and type are normalized
// (lowercase name without trailing dot, uppercase type). The model is exactly
// one managed record per (provider, zone, name, type); round-robin or
// multi-value sets are out of scope. If a row already exists with the same
// owner_key, its value and provider_record_id are updated in place; if it
// belongs to a different owner_key, ErrOwnerConflict is returned and nothing
// changes.
func (s *Store) AddOwnedRecord(ctx context.Context, r DNSRecord) error {
	res, err := s.db.ExecContext(ctx, `INSERT INTO dns_records
		(provider, zone, name, type, value, provider_record_id, owner_key, created_at, removed_after)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, zone, name, type) DO UPDATE SET value=excluded.value,
			provider_record_id=excluded.provider_record_id, removed_after=excluded.removed_after
		WHERE dns_records.owner_key = excluded.owner_key`,
		r.Provider, r.Zone, normName(r.Name), normType(r.Type), r.Value, r.ProviderRecordID, r.OwnerKey, toUnix(r.CreatedAt), nullTime(r.RemovedAfter))
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrOwnerConflict
	}
	return nil
}

// ListOwnedRecords returns owned records for one provider and zone.
func (s *Store) ListOwnedRecords(ctx context.Context, provider, zone string) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider, zone, name, type, value, provider_record_id, owner_key, created_at, removed_after
		FROM dns_records WHERE provider = ? AND zone = ? ORDER BY name, type`, provider, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var r DNSRecord
		var ca int64
		var ra sql.NullInt64
		if err := rows.Scan(&r.Provider, &r.Zone, &r.Name, &r.Type, &r.Value, &r.ProviderRecordID, &r.OwnerKey, &ca, &ra); err != nil {
			return nil, err
		}
		r.CreatedAt, r.RemovedAfter = fromUnix(ca), scanNullTime(ra)
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteOwnedRecord forgets ownership of a record (no error if absent).
// Matching is exact on (provider, zone, normalized name, normalized type). The
// caller must only delete records it has verified it owns.
func (s *Store) DeleteOwnedRecord(ctx context.Context, provider, zone, name, typ string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE provider = ? AND zone = ? AND name = ? AND type = ?`, provider, zone, normName(name), normType(typ))
	return err
}
