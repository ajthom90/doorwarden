package store

import (
	"context"
	"time"
)

// Cert is certificate metadata (no key material).
type Cert struct {
	ID          string
	Zone        string
	DomainsJSON string
	Issuer      string
	Staging     bool
	NotAfter    time.Time
	Status      string
	LastResult  string
	LastError   string
	Path        string
	Managed     bool
}

// UpsertCert inserts or replaces a cert by id.
func (s *Store) UpsertCert(ctx context.Context, c Cert) error {
	if c.DomainsJSON == "" {
		c.DomainsJSON = "[]"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO certs (id, zone, domains_json, issuer, staging, not_after, status, last_result, last_error, path, managed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET zone=excluded.zone, domains_json=excluded.domains_json, issuer=excluded.issuer,
			staging=excluded.staging, not_after=excluded.not_after, status=excluded.status,
			last_result=excluded.last_result, last_error=excluded.last_error, path=excluded.path, managed=excluded.managed`,
		c.ID, c.Zone, c.DomainsJSON, c.Issuer, c.Staging, toUnix(c.NotAfter), c.Status, c.LastResult, c.LastError, c.Path, c.Managed)
	return err
}

// ListCerts returns all certs ordered by id.
func (s *Store) ListCerts(ctx context.Context) ([]Cert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, zone, domains_json, issuer, staging, not_after, status, last_result, last_error, path, managed FROM certs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		var c Cert
		var na int64
		if err := rows.Scan(&c.ID, &c.Zone, &c.DomainsJSON, &c.Issuer, &c.Staging, &na, &c.Status, &c.LastResult, &c.LastError, &c.Path, &c.Managed); err != nil {
			return nil, err
		}
		c.NotAfter = fromUnix(na)
		out = append(out, c)
	}
	return out, rows.Err()
}
