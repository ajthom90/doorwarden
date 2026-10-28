package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	var out bytes.Buffer
	if c := run([]string{"healthcheck", "--url", ok.URL}, &out); c != 0 {
		t.Fatalf("ok server: %d", c)
	}
	if c := run([]string{"healthcheck", "--url", bad.URL}, &out); c != 1 {
		t.Fatalf("503: %d", c)
	}
	if c := run([]string{"healthcheck", "--url", "http://127.0.0.1:1/x", "--timeout", "500ms"}, &out); c != 1 {
		t.Fatalf("refused: %d", c)
	}
}

func TestImportNPMCommand(t *testing.T) {
	p := filepath.Join(t.TempDir(), "database.sqlite")
	db, _ := sql.Open("sqlite", p)
	for _, s := range []string{
		`CREATE TABLE proxy_host(id INTEGER PRIMARY KEY, domain_names TEXT, forward_scheme TEXT, forward_host TEXT, forward_port INT, certificate_id INT, access_list_id INT, allow_websocket_upgrade INT, ssl_forced INT, advanced_config TEXT, enabled INT, is_deleted INT)`,
		`CREATE TABLE certificate(id INTEGER PRIMARY KEY, provider TEXT, nice_name TEXT, domain_names TEXT, expires_on TEXT, is_deleted INT)`,
		`INSERT INTO proxy_host VALUES(1,'["x.example.test"]','http','192.0.2.9',80,0,0,0,1,'',1,0)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	var out bytes.Buffer
	if c := run([]string{"import-npm", "--db", p}, &out); c != 0 || !strings.Contains(out.String(), "x.example.test") {
		t.Fatalf("code %d out %s", c, out.String())
	}
	if c := run([]string{"import-npm"}, &out); c == 0 {
		t.Fatal("missing --db must fail")
	}
}
