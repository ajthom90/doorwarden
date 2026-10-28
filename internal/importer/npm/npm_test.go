package npm

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
	_ "modernc.org/sqlite"
)

const sentinel = "SENTINEL-SECRET-DO-NOT-LEAK"
const secretConfig = "location /secret-path { proxy_pass http://x; }"

func newDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := []string{
		`CREATE TABLE proxy_host(id INTEGER PRIMARY KEY, domain_names TEXT, forward_scheme TEXT, forward_host TEXT, forward_port INT, certificate_id INT, access_list_id INT, allow_websocket_upgrade INT, ssl_forced INT, advanced_config TEXT, enabled INT, is_deleted INT, meta TEXT)`,
		`CREATE TABLE certificate(id INTEGER PRIMARY KEY, provider TEXT, nice_name TEXT, domain_names TEXT, expires_on TEXT, is_deleted INT, meta TEXT)`,
		`CREATE TABLE stream(id INTEGER PRIMARY KEY, is_deleted INT)`,
		`CREATE TABLE access_list(id INTEGER PRIMARY KEY, is_deleted INT)`,
		`CREATE TABLE redirection_host(id INTEGER PRIMARY KEY, is_deleted INT)`,
		`CREATE TABLE dead_host(id INTEGER PRIMARY KEY, is_deleted INT)`,
		`INSERT INTO certificate VALUES(1,'letsencrypt','wild','["*.example.test","example.test"]','2027-01-01 00:00:00',0,'{"dns_provider":"x","dns_provider_credentials":"` + sentinel + `"}')`,
		`INSERT INTO certificate VALUES(2,'letsencrypt','single','["solo.example.test","other.invalid"]','2027-01-01 00:00:00',0,'{"dns_provider_credentials":"` + sentinel + `"}')`,
		// auto: matches truenas app 192.0.2.10:30001
		`INSERT INTO proxy_host VALUES(1,'["app.example.test"]','http','192.0.2.10',30001,1,0,1,1,'',1,0,'{"k":"` + sentinel + `"}')`,
		// label: docker
		`INSERT INTO proxy_host VALUES(2,'["dock.example.test"]','http','192.0.2.10',8081,1,0,0,1,'',1,0,'{}')`,
		// static, hostname upstream, custom config
		`INSERT INTO proxy_host VALUES(3,'["nas.example.test"]','https','nas.internal.test',443,2,5,0,0,'` + secretConfig + `',1,0,'{}')`,
		// static, off-box IP, outside zone
		`INSERT INTO proxy_host VALUES(4,'["a.other.test","b.example.test"]','http','198.51.100.7',8080,0,0,0,1,'',1,0,'{}')`,
		// deleted
		`INSERT INTO proxy_host VALUES(5,'["gone.example.test"]','http','192.0.2.10',1,0,0,0,1,'',1,1,'{}')`,
		`INSERT INTO stream VALUES(1,0)`, `INSERT INTO stream VALUES(2,1)`,
		`INSERT INTO access_list VALUES(1,0)`, `INSERT INTO redirection_host VALUES(1,0)`, `INSERT INTO dead_host VALUES(1,0)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	return path
}

func testCfg() *config.Config {
	return &config.Config{Zones: []config.Zone{{Name: "example.test", TargetIP: "192.0.2.10"}}}
}

func discovered() []model.Service {
	return []model.Service{
		{Key: "truenas:myapp", Name: "myapp", Backend: model.Backend{Scheme: "http", Host: "192.0.2.10", Port: 30001}},
		{Key: "docker:dock", Name: "dock", Backend: model.Backend{Scheme: "http", Host: "192.0.2.10", Port: 8081}},
	}
}

func readSnap(t *testing.T, path string, copyFirst bool) *Snapshot {
	t.Helper()
	r, err := Open(path, Options{CopyFirst: copyFirst})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestReadAndCopyFirst(t *testing.T) {
	path := newDB(t)
	for _, cp := range []bool{false, true} {
		s := readSnap(t, path, cp)
		if len(s.ProxyHosts) != 4 || len(s.Certificates) != 2 {
			t.Fatalf("copy=%v hosts=%d certs=%d", cp, len(s.ProxyHosts), len(s.Certificates))
		}
		if s.Streams != 1 || s.AccessLists != 1 || s.Redirections != 1 || s.DeadHosts != 1 {
			t.Fatalf("counts %+v", s)
		}
		if !s.Certificates[0].IsWildcard || s.Certificates[1].IsWildcard {
			t.Fatal("wildcard detection")
		}
		if s.ProxyHosts[2].AdvancedConfigLen != len(secretConfig) {
			t.Fatalf("len %d", s.ProxyHosts[2].AdvancedConfigLen)
		}
	}
}

func TestReadOnlyNeverWrites(t *testing.T) {
	path := newDB(t)
	before, _ := os.ReadFile(path)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec(`DELETE FROM proxy_host`); err == nil {
		t.Fatal("write through reader succeeded")
	}
	// A second ro connection also cannot write.
	db2, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if _, err := db2.Exec(`DELETE FROM proxy_host`); err == nil {
		t.Fatal("mode=ro connection wrote")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("database bytes changed")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing.sqlite")); err == nil {
		t.Fatal("missing file must error, not be created")
	}
}

func TestQueriesNeverSelectMeta(t *testing.T) {
	for _, q := range Queries {
		for _, bad := range []string{"meta", "credentials", "advanced_config,", "SELECT *"} {
			if strings.Contains(strings.ToLower(q), strings.ToLower(bad)) {
				t.Errorf("query touches %q: %s", bad, q)
			}
		}
	}
}

func byDomain(ms []Mapping) map[string]Mapping {
	m := map[string]Mapping{}
	for _, x := range ms {
		m[x.Domain] = x
	}
	return m
}

func hasFlag(m Mapping, sub string) bool {
	for _, f := range m.Flags {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestPlanClassification(t *testing.T) {
	s := readSnap(t, newDB(t), false)
	ms := byDomain(Plan(s, discovered(), testCfg()))
	if len(ms) != 5 {
		t.Fatalf("mappings %d", len(ms))
	}
	if m := ms["app.example.test"]; m.Class != ClassAuto || m.MatchedService != "truenas:myapp" || !hasFlag(m, "websockets") {
		t.Fatalf("app: %+v", m)
	}
	if m := ms["dock.example.test"]; m.Class != ClassLabel {
		t.Fatalf("dock: %+v", m)
	}
	nas := ms["nas.example.test"]
	if nas.Class != ClassStatic || nas.SuggestedStatic != nil {
		t.Fatalf("nas must be refused: %+v", nas)
	}
	for _, f := range []string{"hostname upstream: verify", "custom nginx config", "access list attached", "per-host certificate", "outside configured zones", "ssl_forced off", "skip_verify suggested"} {
		if !hasFlag(nas, f) {
			t.Errorf("nas missing flag %q: %v", f, nas.Flags)
		}
	}
	b := ms["b.example.test"]
	if b.Class != ClassStatic || b.SuggestedStatic == nil || !hasFlag(b, "off-box upstream IP") {
		t.Fatalf("b: %+v", b)
	}
	if b.SuggestedStatic.Problems() != nil {
		t.Fatal(b.SuggestedStatic.Problems())
	}
	if a := ms["a.other.test"]; !hasFlag(a, "no zone") || a.SuggestedStatic != nil {
		t.Fatalf("a: %+v", a)
	}
	if m := ms["app.example.test"]; hasFlag(m, "per-host") {
		t.Fatal("wildcard cert flagged per-host")
	}
	notes := strings.Join(Notes(s), "\n")
	for _, w := range []string{"1 stream", "1 access list", "1 redirection", "1 404/dead"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes missing %q: %s", w, notes)
		}
	}
	if !strings.Contains(CertGuidance(s), "npm-1") {
		t.Fatal(CertGuidance(s))
	}
}

func TestOutputsNeverLeakAndYAMLRoundTrips(t *testing.T) {
	s := readSnap(t, newDB(t), true)
	ms := Plan(s, discovered(), testCfg())
	var tbl, y bytes.Buffer
	Render(&tbl, ms)
	if err := RenderYAML(&y, ms); err != nil {
		t.Fatal(err)
	}
	all := tbl.String() + y.String() + strings.Join(Notes(s), "") + CertGuidance(s)
	for _, bad := range []string{sentinel, "secret-path", "dns_provider"} {
		if strings.Contains(all, bad) {
			t.Fatalf("output leaks %q", bad)
		}
	}
	if !strings.Contains(tbl.String(), "DOMAIN") || !strings.Contains(tbl.String(), "custom nginx config present (") {
		t.Fatal(tbl.String())
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, y.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p, func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("strict load: %v\n%s", err, y.String())
	}
	if len(cfg.Static) != 1 || cfg.Static[0].Problems() != nil {
		t.Fatalf("%+v", cfg.Static)
	}
}
