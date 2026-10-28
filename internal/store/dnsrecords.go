package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrOwnerConflict is returned by AddOwnedRecord when a row for the same
// (provider, zone, name, type) already belongs to a different owner_key.
var ErrOwnerConflict = errors.New("store: dns record already owned by a different owner")

// ErrOwnedRecordNotFound is returned by SetOwnedRemoval when no row for the
// (provider, zone, name, type) is owned by the given owner key.
var ErrOwnedRecordNotFound = errors.New("store: no dns record owned by this owner")

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

// ListAllOwnedRecords returns every ownership row, of every provider and
// zone (also those no longer configured), sorted by provider, zone, name and
// type.
func (s *Store) ListAllOwnedRecords(ctx context.Context) ([]DNSRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT provider, zone, name, type, value, provider_record_id, owner_key, created_at, removed_after
		FROM dns_records ORDER BY provider, zone, name, type`)
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

// DeleteOwnedRecord forgets ownership of a record (no error if absent),
// whoever owns it. Matching is exact on (provider, zone, normalized name,
// normalized type). It is for UI/admin paths only (an explicit user
// decision); the reconciler uses the conditional DeleteOwnedRecordIfDue and
// DeleteOwnedRecordOwned.
func (s *Store) DeleteOwnedRecord(ctx context.Context, provider, zone, name, typ string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE provider = ? AND zone = ? AND name = ? AND type = ?`, provider, zone, normName(name), normType(typ))
	return err
}

// DeleteOwnedRecordIfDue deletes the row for (provider, zone, normalized
// name, normalized type) only if it is owned by owner AND its removed_after
// is set and strictly before notAfter (compared in whole seconds, the stored
// precision). deleted reports whether a row was deleted; a row that is
// absent, owned by another key, not scheduled or not yet due is left alone.
func (s *Store) DeleteOwnedRecordIfDue(ctx context.Context, provider, zone, name, typ, owner string, notAfter time.Time) (deleted bool, err error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE provider = ? AND zone = ? AND name = ? AND type = ?
		AND owner_key = ? AND removed_after IS NOT NULL AND removed_after < ?`,
		provider, zone, normName(name), normType(typ), owner, toUnix(notAfter))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// DeleteOwnedRecordOwned deletes the row for (provider, zone, normalized
// name, normalized type) only if it is owned by owner; deleted reports
// whether a row was deleted.
func (s *Store) DeleteOwnedRecordOwned(ctx context.Context, provider, zone, name, typ, owner string) (deleted bool, err error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dns_records WHERE provider = ? AND zone = ? AND name = ? AND type = ? AND owner_key = ?`,
		provider, zone, normName(name), normType(typ), owner)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ReassignOwnedRecord transfers the row for (provider, zone, normalized name,
// normalized type) from oldOwner to newOwner and clears its removed_after, in
// one UPDATE guarded by owner_key = oldOwner. Value, provider record ID and
// created_at are kept. No such row (absent, or owned by another key) writes
// nothing and returns ErrOwnedRecordNotFound. newOwner must be non-empty,
// without surrounding whitespace, and not a "zone:" key (the wildcard
// record's owner never changes).
func (s *Store) ReassignOwnedRecord(ctx context.Context, provider, zone, name, typ, oldOwner, newOwner string) error {
	if newOwner == "" || strings.TrimSpace(newOwner) != newOwner || strings.HasPrefix(strings.ToLower(newOwner), "zone:") {
		return fmt.Errorf("store: invalid new owner key %q", newOwner)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE dns_records SET owner_key = ?, removed_after = NULL
		WHERE provider = ? AND zone = ? AND name = ? AND type = ? AND owner_key = ?`,
		newOwner, provider, zone, normName(name), normType(typ), oldOwner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrOwnedRecordNotFound
	}
	return nil
}

// SetOwnedRemoval sets (at non-nil) or clears (at nil) removed_after of the
// ownership row for (provider, zone, normalized name, normalized type), only
// if that row's owner_key equals owner. Nothing else in the row changes. When
// no such row exists (absent, or owned by another key) it writes nothing and
// returns ErrOwnedRecordNotFound.
func (s *Store) SetOwnedRemoval(ctx context.Context, provider, zone, name, typ, owner string, at *time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE dns_records SET removed_after = ?
		WHERE provider = ? AND zone = ? AND name = ? AND type = ? AND owner_key = ?`,
		nullTime(at), provider, zone, normName(name), normType(typ), owner)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrOwnedRecordNotFound
	}
	return nil
}
