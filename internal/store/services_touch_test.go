package store

import (
	"context"
	"testing"
	"time"
)

// TouchService updates source/state/last_seen only: overrides and the
// scheduled removal survive; a new key is inserted with defaults.
func TestTouchServiceKeepsOverridesAndRemoval(t *testing.T) {
	s, _ := openTemp(t)
	ctx := context.Background()
	t0 := time.Unix(1_800_000_000, 0)
	if err := s.TouchService(ctx, "docker/app", "docker", "discovered", t0); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListServices(ctx)
	if len(got) != 1 || got[0].OverridesJSON != "{}" || got[0].RemovedAfter != nil || !got[0].FirstSeen.Equal(t0) {
		t.Fatalf("insert = %+v", got)
	}
	ra := t0.Add(time.Hour)
	if err := s.UpsertService(ctx, Service{Key: "docker/app", Source: "docker", State: "discovered",
		OverridesJSON: `{"rename":"x"}`, FirstSeen: t0, LastSeen: t0, RemovedAfter: &ra}); err != nil {
		t.Fatal(err)
	}
	t1 := t0.Add(time.Minute)
	if err := s.TouchService(ctx, "docker/app", "docker", "stopped", t1); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListServices(ctx)
	v := got[0]
	if v.OverridesJSON != `{"rename":"x"}` || v.RemovedAfter == nil || !v.RemovedAfter.Equal(ra) ||
		v.State != "stopped" || !v.LastSeen.Equal(t1) || !v.FirstSeen.Equal(t0) {
		t.Fatalf("touch = %+v", v)
	}
}
