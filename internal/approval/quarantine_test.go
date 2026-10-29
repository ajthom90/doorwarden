package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ajthom90/doorwarden/internal/model"
)

// legacyV1 is the pre-43df75d fingerprint, kept here independently of
// FingerprintV1 so the test pins the stored format.
func TestFingerprintV1MatchesLegacyFormat(t *testing.T) {
	s := svc("docker:a", model.StateDiscovered)
	s.Options.Middlewares = []string{"rl", "auth"}
	sum := sha256.Sum256([]byte(`["docker:a","docker:a","","example.test","http",false,false,["auth","rl"]]`))
	got := FingerprintV1(s)
	if got != hex.EncodeToString(sum[:]) || got == Fingerprint(s) {
		t.Fatalf("v1 %q", got)
	}
	s2 := s
	s2.Backend.Port = 9999 // v1 ignores the backend host/port
	s2.Options.Middlewares = []string{"auth", "rl"}
	if FingerprintV1(s2) != got {
		t.Fatal("v1 depends on the port or middleware order")
	}
}

// A changed backend under an existing approval makes the service Pending
// and quarantined; the stored approval is left untouched. Re-approval
// publishes it again.
func TestResolveQuarantinesChangedApproved(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	if err := f.SetApproval(ctx, s.Key, Fingerprint(s)); err != nil {
		t.Fatal(err)
	}
	r, err := g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if err != nil || r.Services[0].State != model.StatePublished || len(r.Quarantined) != 0 {
		t.Fatalf("unchanged: %+v %v", r, err)
	}
	s.Backend.Port = 8081
	r, err = g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if err != nil || r.Services[0].State != model.StatePending || !r.Quarantined[s.Key] || len(r.Migrated) != 0 {
		t.Fatalf("changed: %+v %v", r, err)
	}
	old := Fingerprint(svc("docker:a", model.StateDiscovered))
	if f.m[s.Key] != old {
		t.Fatal("stored approval rewritten for changed content")
	}
	if err := g.Approve(ctx, s.Key, Fingerprint(s)); err != nil {
		t.Fatal(err)
	}
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if r.Services[0].State != model.StatePublished || r.Quarantined[s.Key] {
		t.Fatalf("re-approved: %+v", r)
	}
}

// A service with no approval at all is Pending, never quarantined; auto
// mode never quarantines, even with a stale approval row.
func TestResolveQuarantineOnlyWithStaleApproval(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	r, _ := g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if r.Services[0].State != model.StatePending || len(r.Quarantined) != 0 {
		t.Fatalf("unapproved: %+v", r)
	}
	_ = f.SetApproval(ctx, s.Key, "stale")
	r, _ = g.ResolveDetail(ctx, ModeAuto, []model.Service{s})
	if r.Services[0].State != model.StatePublished || len(r.Quarantined) != 0 || len(r.Migrated) != 0 {
		t.Fatalf("auto: %+v", r)
	}
	// Stopped/Error keep their state and are never quarantined.
	st := svc("docker:a", model.StateStopped)
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{st})
	if r.Services[0].State != model.StateStopped || len(r.Quarantined) != 0 {
		t.Fatalf("stopped: %+v", r)
	}
}

// A legacy v1 approval of the current content is rewritten to v2 once
// (reported as migrated) and the service stays Published; a v1 approval
// of other content is not migrated: Pending and quarantined.
func TestResolveMigratesV1Approval(t *testing.T) {
	f := newFake()
	g := NewGate(f)
	s := svc("docker:a", model.StateDiscovered)
	_ = f.SetApproval(ctx, s.Key, FingerprintV1(s))
	r, err := g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if err != nil || r.Services[0].State != model.StatePublished || len(r.Migrated) != 1 || r.Migrated[0] != s.Key || len(r.Quarantined) != 0 {
		t.Fatalf("migrate: %+v %v", r, err)
	}
	if f.m[s.Key] != Fingerprint(s) {
		t.Fatal("not rewritten to v2")
	}
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{s})
	if len(r.Migrated) != 0 || r.Services[0].State != model.StatePublished {
		t.Fatalf("second resolve: %+v", r)
	}

	b := svc("docker:b", model.StateDiscovered)
	_ = f.SetApproval(ctx, b.Key, FingerprintV1(b))
	b.Zone = "other.test" // content changed after the v1 approval
	r, _ = g.ResolveDetail(ctx, ModeApprove, []model.Service{b})
	if r.Services[0].State != model.StatePending || !r.Quarantined[b.Key] || len(r.Migrated) != 0 {
		t.Fatalf("changed v1: %+v", r)
	}
	if f.m[b.Key] == Fingerprint(b) {
		t.Fatal("changed v1 approval migrated")
	}
}
