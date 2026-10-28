package dnstest

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/ajthom90/doorwarden/internal/dns"
)

// WriteStatus is an HTTP error answer to a mutating request and how the write
// must be classified.
type WriteStatus struct {
	Status      int
	ContentType string
	Body        string
	// Ambiguous: the write may have been applied, so Create/Update must return
	// the attempted Record with an error wrapping dns.ErrUnconfirmed and Delete
	// an error wrapping it. Otherwise the answer is a definitive refusal: a plain
	// error and an empty Record.
	Ambiguous bool
}

// WriteStatuses are the answers the write-classification checks use: a 4xx is
// a refusal; every 5xx (including a reverse proxy's HTML 502/504 page) leaves
// the outcome unknown.
var WriteStatuses = []WriteStatus{
	{409, "application/json", `{"message":"conflict","success":false,"status":"error","errorMessage":"conflict"}`, false},
	{422, "application/json", `{"message":"invalid","success":false,"status":"error","errorMessage":"invalid"}`, false},
	{500, "application/json", `{"message":"internal error"}`, true},
	{502, "text/html", `<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>`, true},
	{503, "text/plain", `service unavailable`, true},
	{504, "text/html", `<html><head><title>504 Gateway Time-out</title></head><body><h1>504 Gateway Time-out</h1></body></html>`, true},
}

// AnswerWrites returns a handler that answers every request match selects with
// ws (without passing it to inner) and counts those requests in hits; every
// other request goes to inner.
func AnswerWrites(inner http.Handler, match func(*http.Request) bool, ws WriteStatus, hits *atomic.Int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !match(r) {
			inner.ServeHTTP(w, r)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", ws.ContentType)
		w.WriteHeader(ws.Status)
		_, _ = w.Write([]byte(ws.Body))
	})
}

// WriteStatusHarness describes a provider for CheckWriteStatuses.
type WriteStatusHarness struct {
	Zone string
	// New builds a fresh fake backend and returns two providers on it: seed
	// talks to the backend directly, p through the handler wrap returns.
	New func(t *testing.T, wrap func(http.Handler) http.Handler) (seed, p dns.Provider)
	// IsWrite selects the mutating requests (only those get the error status;
	// reads before the write must succeed so the status is met AT the write).
	IsWrite func(*http.Request) bool
	// Create is a record that does not exist yet; Existing is created through
	// seed before each Update/Delete, which change it to UpdateValue / remove it.
	Create, Existing dns.Record
	UpdateValue      string
}

// CheckWriteStatuses answers the mutating request of each of Create, Update and
// Delete with every WriteStatuses entry and checks the classification.
func CheckWriteStatuses(t *testing.T, h WriteStatusHarness) {
	t.Helper()
	ctx := context.Background()
	for _, ws := range WriteStatuses {
		for _, op := range []string{"create", "update", "delete"} {
			var hits atomic.Int32
			seed, p := h.New(t, func(inner http.Handler) http.Handler { return AnswerWrites(inner, h.IsWrite, ws, &hits) })
			if op != "create" {
				if _, err := seed.CreateRecord(ctx, h.Zone, h.Existing); err != nil {
					t.Fatalf("seed: %v", err)
				}
			}
			var got dns.Record
			var err error
			want := h.Create
			switch op {
			case "create":
				got, err = p.CreateRecord(ctx, h.Zone, h.Create)
			case "update":
				want = h.Existing
				want.Value = h.UpdateValue
				got, err = p.UpdateRecord(ctx, h.Zone, want)
			case "delete":
				err = p.DeleteRecord(ctx, h.Zone, h.Existing)
			}
			if hits.Load() == 0 {
				t.Errorf("status %d %s: the mutating request was never sent (err %v)", ws.Status, op, err)
				continue
			}
			unconfirmed := errors.Is(err, dns.ErrUnconfirmed)
			switch {
			case err == nil:
				t.Errorf("status %d %s: no error", ws.Status, op)
			case ws.Ambiguous && !unconfirmed:
				t.Errorf("status %d %s: must wrap ErrUnconfirmed (the write may have been applied), got %v", ws.Status, op, err)
			case !ws.Ambiguous && unconfirmed:
				t.Errorf("status %d %s: a 4xx refusal must be a plain error, got %v", ws.Status, op, err)
			case op != "delete" && ws.Ambiguous && (got.Name != want.Name || got.Type != want.Type || got.Value != want.Value):
				t.Errorf("status %d %s: ErrUnconfirmed must come with the attempted record %+v, got %+v", ws.Status, op, want, got)
			case op != "delete" && !ws.Ambiguous && got != (dns.Record{}):
				t.Errorf("status %d %s: a refusal must return an empty Record, got %+v", ws.Status, op, got)
			}
		}
	}
}
