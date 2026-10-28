package store

import (
	"context"
	"database/sql"
	"time"
)

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

// AddOwnedRecord records ownership, replacing any existing row with the same
// (provider, zone, name, type); the value and provider id may change.
func (s *Store) AddOwnedRecord(ctx context.Context, r DNSRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO dns_records
		(provider, zone, name, type, value, provider_record_id, owner_key, created_at, removed_after)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider, zone, name, type) DO UPDATE SET value=excluded.value,
			provider_record_id=excluded.provider_record_id, owner_key=excluded.owner_key,
			removed_after=excluded.removed_after`,
		r.Provider, r.Zone, r.Name, r.Type, r.Value, r.ProviderRecordID, r.OwnerKey, toUnix(r.CreatedAt), nullTime(r.RemovedAfter))
	return err
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
func (s *Store) DeleteOwnedRecord(ctx context.Context, provider, zone, name, typ string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE provider = ? AND zone = ? AND name = ? AND type = ?`, provider, zone, name, typ)
	return err
}
