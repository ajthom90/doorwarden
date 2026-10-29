package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// OpenReadOnly reads an existing database and refuses every write.
func TestOpenReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dw.db")
	st, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.UpsertCert(ctx, Cert{ID: "c1", Zone: "example.test", DomainsJSON: `["a.example.test"]`, NotAfter: time.Now(), Status: "imported"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	ro, err := OpenReadOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	rows, err := ro.ListCerts(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if err := ro.UpsertCert(ctx, Cert{ID: "c2", Zone: "example.test", DomainsJSON: `[]`}); err == nil {
		t.Fatal("write through a read-only store succeeded")
	}
	if _, err := OpenReadOnly(filepath.Join(t.TempDir(), "nope.db")); err == nil {
		t.Fatal("missing database opened")
	}
}
