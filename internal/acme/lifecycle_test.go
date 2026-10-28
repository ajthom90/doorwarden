package acme

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// --- Wanted filter ---

func wantedHarness(t *testing.T, wanted map[string][]string) *harness {
	t.Helper()
	cfg := testConfig()
	return newHarness(t, cfg, func(mc *ManagerConfig) {
		mc.Wanted = func(zone string) []string { return wanted[zone] }
	})
}

func TestWantedFilterSkipsUnwantedRows(t *testing.T) {
	wanted := map[string][]string{"other.test": {"a.other.test", "b.other.test"}}
	h := wantedHarness(t, wanted)
	ra := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test", "b.other.test"}})
	if len(ra) != 2 || ra[0].Err != nil || ra[1].Err != nil {
		t.Fatalf("%+v", ra)
	}
	wc, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	idA, idB := ra[0].CertID, ra[1].CertID
	if !strings.Contains(strings.Join(ra[0].Names, ","), "a.other") {
		idA, idB = idB, idA
	}
	// b is no longer wanted; the wildcard row stays wanted while its zone
	// is configured with the wildcard strategy.
	wanted["other.test"] = []string{"a.other.test"}
	h.clock.Add(85 * 24 * time.Hour) // 5 days left: due, and expiry thresholds crossed
	n := h.ca.count()
	res := h.m.Renew(ctx)
	renewed := map[string]bool{}
	for _, r := range res {
		if r.CertID == idB {
			if !r.Skipped || !errors.Is(r.Err, ErrUnwanted) {
				t.Fatalf("unwanted result %+v", r)
			}
			continue
		}
		if r.Err != nil {
			t.Fatalf("%+v", r)
		}
		renewed[r.CertID] = true
	}
	if !renewed[idA] || !renewed[wc.ID] || renewed[idB] || h.ca.count() != n+2 {
		t.Fatalf("renewed %v (orders %d)", renewed, h.ca.count()-n)
	}
	if r := h.row(t, idB); r.Status != StatusUnwanted {
		t.Fatalf("status %q", r.Status)
	}
	for _, e := range h.evs.list() {
		if e.CertID == idB {
			t.Fatalf("notification for unwanted row: %+v", e)
		}
	}
	// Wanted again: status restored and renewed.
	wanted["other.test"] = []string{"a.other.test", "b.other.test"}
	res = h.m.Renew(ctx)
	found := false
	for _, r := range res {
		if r.CertID == idB {
			found = r.Err == nil && !r.Skipped
		}
	}
	if !found {
		t.Fatalf("re-wanted row not renewed: %+v", res)
	}
	if r := h.row(t, idB); r.Status != StatusValid {
		t.Fatalf("status %q", r.Status)
	}
}

func TestWantedWildcardRowUnwantedWhenStrategyChanges(t *testing.T) {
	h := wantedHarness(t, map[string][]string{})
	wc, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	h.m.cfg.Zones[0].Certificate.Strategy = StrategyPerHost
	h.clock.Add(85 * 24 * time.Hour)
	res := h.m.Renew(ctx)
	if len(res) != 1 || !errors.Is(res[0].Err, ErrUnwanted) || res[0].CertID != wc.ID {
		t.Fatalf("%+v", res)
	}
}

func TestWantedNilKeepsBehavior(t *testing.T) {
	h := newHarness(t, nil, nil)
	ra := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"a.other.test"}})
	if ra[0].Err != nil {
		t.Fatal(ra[0].Err)
	}
	h.clock.Add(85 * 24 * time.Hour)
	if res := h.m.Renew(ctx); len(res) != 1 || res[0].Err != nil {
		t.Fatalf("%+v", res)
	}
}

// --- Imported adoption ---

func TestImportedAdoptedOnlyWhenDueAndZoneHasIssuer(t *testing.T) {
	h := newHarness(t, nil, nil)
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0.Add(60*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	chain2, key2 := h.ca.ca.leaf(t, []string{"app.noissuer.test"}, t0.Add(60*24*time.Hour))
	ir2, err := h.m.ImportPEM(ctx, "noissuer.test", chain2, key2)
	if err != nil {
		t.Fatal(err)
	}
	// 60 days left: not due, nothing happens.
	if res := h.m.Renew(ctx); len(res) != 0 || h.ca.count() != 0 {
		t.Fatalf("%+v", res)
	}
	if r := h.row(t, ir.Bundle.ID); r.Managed {
		t.Fatal("adopted before renew_before")
	}
	// 29 days left: due; adopted where the zone has an issuer.
	h.clock.Add(31 * 24 * time.Hour)
	res := h.m.Renew(ctx)
	var adopted, skipped bool
	for _, r := range res {
		switch r.CertID {
		case ir.Bundle.ID:
			adopted = r.Err == nil && !r.Skipped
		case ir2.Bundle.ID:
			skipped = r.Skipped && errors.Is(r.Err, ErrImported)
		}
	}
	if !adopted || !skipped || h.ca.count() != 1 {
		t.Fatalf("%+v (orders %d)", res, h.ca.count())
	}
	if r := h.row(t, ir.Bundle.ID); !r.Managed || r.Status != StatusValid || r.Issuer != "le" {
		t.Fatalf("row %+v", r)
	}
	if r := h.row(t, ir2.Bundle.ID); r.Managed || r.Status != StatusImported {
		t.Fatalf("row %+v", r)
	}
}

// --- Issuer switching ---

func TestRenewNowReissuesAcrossDirectoryChange(t *testing.T) {
	cfg := testConfig()
	h := newHarness(t, cfg, nil)
	b, _ := h.m.Issue(ctx, wildcardReq())
	is := cfg.Issuers["le"]
	is.Directory = "production" // config edited by hand
	cfg.Issuers["le"] = is
	h.clock.Add(70 * 24 * time.Hour)
	n := h.ca.count()
	res := h.m.Renew(ctx)
	if len(res) != 1 || !errors.Is(res[0].Err, ErrNeedsSwitch) || !res[0].Skipped || h.ca.count() != n {
		t.Fatalf("Renew re-issued on a directory change: %+v", res)
	}
	if !strings.Contains(ErrNeedsSwitch.Error(), "RenewNow") {
		t.Fatalf("message does not say how to fix it: %v", ErrNeedsSwitch)
	}
	if r := h.m.RenewNow(ctx, b.ID); r.Err != nil {
		t.Fatalf("%+v", r)
	}
	if o := h.ca.last(); o.Dir.URL != LEProductionURL {
		t.Fatalf("RenewNow used %s", o.Dir.URL)
	}
	if r := h.row(t, b.ID); r.Staging {
		t.Fatal("row still staging")
	}
}

func TestSwitchIssuerPerRowResults(t *testing.T) {
	h := newHarness(t, nil, nil)
	wc, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	ra := h.m.IssueAll(ctx, IssueRequest{Zone: "other.test", Names: []string{"x.other.test"}})
	if ra[0].Err != nil {
		t.Fatal(ra[0].Err)
	}
	ca := h.m.obtain
	h.m.obtain = func(ctx context.Context, o order) (obtained, error) {
		if strings.Contains(strings.Join(o.Names, ","), "other.test") {
			return obtained{}, errTest("rejected")
		}
		return ca(ctx, o)
	}
	res, err := h.m.SwitchIssuer(ctx, "le", "production")
	if err != nil || len(res) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, r := range res {
		if (r.CertID == wc.ID) != (r.Err == nil) {
			t.Fatalf("per-row result %+v", r)
		}
	}
	if r := h.row(t, ra[0].CertID); !r.Staging {
		t.Fatal("failed row lost its staging flag")
	}
	h.m.obtain = ca
	h.clock.Add(time.Hour)
	if r := h.m.RenewNow(ctx, ra[0].CertID); r.Err != nil {
		t.Fatalf("failed row not eligible for RenewNow: %+v", r)
	}
	if r := h.row(t, ra[0].CertID); r.Staging {
		t.Fatal("still staging")
	}
}

func TestSwitchOverrideClearedWhenConfigDirectoryChanges(t *testing.T) {
	cfg := testConfig()
	h := newHarness(t, cfg, nil)
	if _, err := h.m.Issue(ctx, wildcardReq()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.m.SwitchIssuer(ctx, "le", "production"); err != nil {
		t.Fatal(err)
	}
	dir := func(m *Manager) directory {
		d, _, err := m.effectiveDirectory(ctx, "le")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	// Restart with the same configuration: the switch is kept.
	if d := dir(h.reopen(t)); d.Staging {
		t.Fatal("override lost on restart")
	}
	// Configuration edited to production, then back to staging: the
	// earlier switch no longer applies.
	setDir := func(v string) {
		is := cfg.Issuers["le"]
		is.Directory = v
		cfg.Issuers["le"] = is
	}
	setDir("production")
	h.reopen(t)
	if _, ok, _ := h.st.GetSetting(ctx, overrideKey("le")); ok {
		t.Fatal("override kept after the configured directory changed")
	}
	setDir("staging")
	if d := dir(h.reopen(t)); !d.Staging {
		t.Fatal("stale override applied after the configuration changed back")
	}
}

// A stored switch that was not recorded for the configured directory is
// ignored (and deleted at the next start).
func TestSwitchOverrideMustMatchConfiguredDirectory(t *testing.T) {
	h := newHarness(t, nil, nil)
	for _, v := range []string{"production", "production from https://acme.example.test/dir"} {
		if err := h.st.SetSetting(ctx, overrideKey("le"), v); err != nil {
			t.Fatal(err)
		}
		if d, _, _ := h.m.effectiveDirectory(ctx, "le"); !d.Staging {
			t.Fatalf("override %q applied", v)
		}
	}
	h.reopen(t)
	if _, ok, _ := h.st.GetSetting(ctx, overrideKey("le")); ok {
		t.Fatal("foreign override kept")
	}
}
