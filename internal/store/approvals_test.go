package store

import (
	"context"
	"reflect"
	"testing"
)

func TestApprovalsRoundtripUpsertClear(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	if _, ok, err := s.GetApproval(ctx, "k"); err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if err := s.SetApproval(ctx, "k", "f1"); err != nil {
		t.Fatal(err)
	}
	if fp, ok, err := s.GetApproval(ctx, "k"); err != nil || !ok || fp != "f1" {
		t.Fatalf("%q %v %v", fp, ok, err)
	}
	if err := s.SetApproval(ctx, "k", "f2"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetApproval(ctx, "j", "g"); err != nil {
		t.Fatal(err)
	}
	m, err := s.ListApprovals(ctx)
	if err != nil || !reflect.DeepEqual(m, map[string]string{"k": "f2", "j": "g"}) {
		t.Fatalf("%v %v", m, err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ClearApproval(ctx, "k"); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok, _ := s.GetApproval(ctx, "k"); ok {
		t.Fatal("still present")
	}
}

func TestApprovalsSurviveReopenAndServiceUpserts(t *testing.T) {
	s, p := openTemp(t)
	ctx := context.Background()
	if err := s.SetApproval(ctx, "k", "f"); err != nil {
		t.Fatal(err)
	}
	for _, o := range []string{`{"a":1}`, `{}`} {
		if err := s.UpsertService(ctx, Service{Key: "k", Source: "x", State: "pending", OverridesJSON: o, FirstSeen: t0, LastSeen: t0}); err != nil {
			t.Fatal(err)
		}
	}
	if fp, ok, _ := s.GetApproval(ctx, "k"); !ok || fp != "f" {
		t.Fatalf("clobbered: %q %v", fp, ok)
	}
	s.Close()
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if fp, ok, _ := s2.GetApproval(ctx, "k"); !ok || fp != "f" {
		t.Fatalf("after reopen: %q %v", fp, ok)
	}
}
