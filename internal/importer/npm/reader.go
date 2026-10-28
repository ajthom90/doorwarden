// Package npm reads a Nginx Proxy Manager SQLite database (read-only) and
// classifies its proxy hosts against what Doorwarden discovers. It never
// writes to the NPM database and never reads credential-bearing columns
// (certificate.meta, proxy_host.meta, advanced_config text).
package npm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver
)

// Options configure Open.
type Options struct {
	// NoCopy reads the original file in place instead of a private snapshot
	// copy. Unsafe: SQLite may create -wal/-shm files next to NPM's database
	// (root-owned leftovers can break NPM). It is refused when WAL sidecars
	// exist or the directory is not writable by this process. The default
	// (false) snapshots the database, -wal and -shm into a 0700 temp dir
	// named doorwarden-npm-* and reads that copy.
	NoCopy bool
}

// TempPrefix is the name prefix of the temporary snapshot directory. The copy
// contains NPM's data (including credentials); it is removed on Close and on
// SIGINT/SIGTERM, but a kill -9 can leave it behind.
const TempPrefix = "doorwarden-npm-"

// Reader is a read-only handle on an NPM database.
type Reader struct {
	db      *sql.DB
	cleanup func()
}

// Queries lists every SQL statement the importer runs. It is exported so a
// test can assert that no credential-bearing column (meta) is ever selected.
var Queries = []string{
	qProxyHosts, qCertificates,
}

const (
	qProxyHosts = `SELECT id, domain_names, forward_scheme, forward_host, forward_port,
 COALESCE(certificate_id,0), COALESCE(access_list_id,0), COALESCE(allow_websocket_upgrade,0),
 COALESCE(ssl_forced,0), COALESCE(length(advanced_config),0), COALESCE(enabled,1)
 FROM proxy_host WHERE COALESCE(is_deleted,0)=0 ORDER BY id`
	qCertificates = `SELECT id, COALESCE(provider,''), COALESCE(nice_name,''), domain_names, expires_on
 FROM certificate WHERE COALESCE(is_deleted,0)=0 ORDER BY id`
)

// countTables maps the Snapshot count fields to NPM table names (fixed
// identifiers, never user input).
var countTables = []string{"stream", "access_list", "redirection_host", "dead_host"}

// Open opens path read-only. It refuses to create a missing file.
func Open(path string, opts ...Options) (*Reader, error) {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("npm database: %w", err)
	}
	cleanup := func() {}
	if o.NoCopy {
		if err := checkInPlace(path); err != nil {
			return nil, err
		}
	} else {
		dir, err := os.MkdirTemp("", TempPrefix+"*")
		if err != nil {
			return nil, err
		}
		cleanup = func() { os.RemoveAll(dir) }
		dst := filepath.Join(dir, "database.sqlite")
		for _, suf := range []string{"", "-wal", "-shm"} {
			if err := copyFile(path+suf, dst+suf, suf != ""); err != nil {
				cleanup()
				return nil, fmt.Errorf("copy npm database: %w", err)
			}
		}
		path = dst
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	q := url.Values{
		"_pragma": {"query_only(1)", "busy_timeout(5000)"},
	}
	if o.NoCopy {
		q.Set("mode", "ro")
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		cleanup()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return &Reader{db: db, cleanup: cleanup}, nil
}

// checkInPlace refuses unsafe in-place reads.
func checkInPlace(path string) error {
	for _, suf := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + suf); err == nil {
			return fmt.Errorf("refusing --no-copy: %s exists next to the database (NPM is running or was not shut down cleanly); use the default snapshot copy", filepath.Base(path+suf))
		}
	}
	if err := syscall.Access(filepath.Dir(path), 2); err != nil {
		return fmt.Errorf("refusing --no-copy: directory %s is not writable by this user, so SQLite could not create its sidecar files safely; use the default snapshot copy", filepath.Dir(path))
	}
	return nil
}

func copyFile(src, dst string, optional bool) error {
	in, err := os.Open(src)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Close releases the database and removes any temp copy.
func (r *Reader) Close() error {
	err := r.db.Close()
	r.cleanup()
	return err
}

// ProxyHost is one NPM proxy host. The custom nginx config is represented
// only by its length: the text is never read.
type ProxyHost struct {
	ID                int
	Domains           []string
	Scheme, Host      string
	Port              int
	CertificateID     int
	AccessListID      int
	Websockets        bool
	SSLForced         bool
	AdvancedConfigLen int
	Enabled           bool
}

// Certificate is certificate metadata only.
type Certificate struct {
	ID         int
	Provider   string
	NiceName   string
	Domains    []string
	ExpiresOn  string
	IsWildcard bool
}

// Snapshot is the importer's view of an NPM database.
type Snapshot struct {
	ProxyHosts                                    []ProxyHost
	Certificates                                  []Certificate
	Streams, AccessLists, Redirections, DeadHosts int
}

func parseDomains(raw string) []string {
	var d []string
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return nil
	}
	out := d[:0]
	for _, x := range d {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// Read loads the snapshot.
func (r *Reader) Read(ctx context.Context) (*Snapshot, error) {
	s := &Snapshot{}
	rows, err := r.db.QueryContext(ctx, qProxyHosts)
	if err != nil {
		return nil, fmt.Errorf("read proxy_host: %w", err)
	}
	for rows.Next() {
		var h ProxyHost
		var dom string
		var ws, ssl, en int
		if err := rows.Scan(&h.ID, &dom, &h.Scheme, &h.Host, &h.Port, &h.CertificateID, &h.AccessListID, &ws, &ssl, &h.AdvancedConfigLen, &en); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan proxy_host: %w", err)
		}
		h.Domains, h.Websockets, h.SSLForced, h.Enabled = parseDomains(dom), ws != 0, ssl != 0, en != 0
		s.ProxyHosts = append(s.ProxyHosts, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	crows, err := r.db.QueryContext(ctx, qCertificates)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	defer crows.Close()
	for crows.Next() {
		var c Certificate
		var dom string
		var exp any
		if err := crows.Scan(&c.ID, &c.Provider, &c.NiceName, &dom, &exp); err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		c.Domains = parseDomains(dom)
		switch v := exp.(type) {
		case string:
			c.ExpiresOn = v
		case time.Time:
			c.ExpiresOn = v.UTC().Format(time.RFC3339)
		case []byte:
			c.ExpiresOn = string(v)
		case int64:
			c.ExpiresOn = time.Unix(v/1000, 0).UTC().Format(time.RFC3339)
		}
		for _, d := range c.Domains {
			if strings.HasPrefix(d, "*.") {
				c.IsWildcard = true
			}
		}
		s.Certificates = append(s.Certificates, c)
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}
	crows.Close()

	for _, t := range countTables {
		n, err := r.count(ctx, t)
		if err != nil {
			return nil, err
		}
		switch t {
		case "stream":
			s.Streams = n
		case "access_list":
			s.AccessLists = n
		case "redirection_host":
			s.Redirections = n
		case "dead_host":
			s.DeadHosts = n
		}
	}
	return s, nil
}

// count returns the non-deleted rows of a fixed table name; a missing table
// (older NPM schema) counts as 0.
func (r *Reader) count(ctx context.Context, table string) (int, error) {
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	var n int
	if err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE COALESCE(is_deleted,0)=0").Scan(&n); err != nil {
		return 0, fmt.Errorf("count %s: %w", table, err)
	}
	return n, nil
}
