package store

import "testing"

func TestPragmas(t *testing.T) {
	s, _ := openTemp(t)
	var jm string
	var fk int
	s.db.QueryRow(`PRAGMA journal_mode`).Scan(&jm)
	s.db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk)
	if jm != "wal" || fk != 1 {
		t.Fatalf("journal=%s fk=%d", jm, fk)
	}
}
