package acme

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
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
	h := newHarness(t, productionConfig(), nil)
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

// Renew prunes bookkeeping of certificates that no longer exist, expiry
// notices of replaced certificates and expired failed-validation counters.
func TestRenewPrunesStaleState(t *testing.T) {
	h := newHarness(t, nil, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil {
		t.Fatal(err)
	}
	r := h.row(t, b.ID)
	old := time.Unix(r.NotAfter.Unix()-86400, 0)
	now := h.clock.Now()
	set := map[string]string{
		attemptKey("ghost-1"):                       `{"failures":2}`,
		attemptKey(b.ID):                            `{"failures":0}`,
		notifiedKey("ghost-1", 24*time.Hour, old):   "x",
		notifiedKey(b.ID, 24*time.Hour, old):        "x",
		notifiedKey(b.ID, 24*time.Hour, r.NotAfter): "x",
		fvKey("le", "stale.example.test"):           fmt.Sprintf("[%d]", now.Add(-2*time.Hour).Unix()),
		fvKey("le", "fresh.example.test"):           fmt.Sprintf("[%d]", now.Add(-time.Minute).Unix()),
	}
	for k, v := range set {
		if err := h.st.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	h.m.Renew(ctx)
	gone := []string{attemptKey("ghost-1"), notifiedKey("ghost-1", 24*time.Hour, old), notifiedKey(b.ID, 24*time.Hour, old), fvKey("le", "stale.example.test")}
	kept := []string{attemptKey(b.ID), notifiedKey(b.ID, 24*time.Hour, r.NotAfter), fvKey("le", "fresh.example.test")}
	for _, k := range gone {
		if _, ok, _ := h.st.GetSetting(ctx, k); ok {
			t.Errorf("%s not pruned", k)
		}
	}
	for _, k := range kept {
		if _, ok, _ := h.st.GetSetting(ctx, k); !ok {
			t.Errorf("%s pruned", k)
		}
	}
}

// The attempt record of a first issuance in progress (no row yet) is kept.
func TestPruneKeepsInFlightAttempt(t *testing.T) {
	h := newHarness(t, nil, nil)
	if !h.m.markInFlight("pending-1") {
		t.Fatal("mark")
	}
	defer h.m.clearInFlight("pending-1")
	if err := h.st.SetSetting(ctx, attemptKey("pending-1"), `{"failures":1}`); err != nil {
		t.Fatal(err)
	}
	h.m.Renew(ctx)
	if _, ok, _ := h.st.GetSetting(ctx, attemptKey("pending-1")); !ok {
		t.Fatal("in-flight attempt pruned")
	}
}

// RenewNow does not replace a production certificate with a staging one
// unless AllowDowngrade is passed.
func TestRenewNowRefusesDowngradeToStaging(t *testing.T) {
	cfg := testConfig()
	is := cfg.Issuers["le"]
	is.Directory = "production"
	cfg.Issuers["le"] = is
	h := newHarness(t, cfg, nil)
	b, err := h.m.Issue(ctx, wildcardReq())
	if err != nil || b.Staging {
		t.Fatalf("%v %+v", err, b)
	}
	is.Directory = "staging" // config edited back to staging
	cfg.Issuers["le"] = is
	h.clock.Add(time.Hour)
	n := h.ca.count()
	if r := h.m.RenewNow(ctx, b.ID); !errors.Is(r.Err, ErrDowngrade) || h.ca.count() != n {
		t.Fatalf("downgrade not refused: %v (orders %d)", r.Err, h.ca.count()-n)
	}
	if r := h.m.RenewNow(ctx, b.ID, AllowDowngrade()); r.Err != nil {
		t.Fatal(r.Err)
	}
	if o := h.ca.last(); o.Dir.URL != LEStagingURL || !h.row(t, b.ID).Staging {
		t.Fatalf("AllowDowngrade did not re-issue from staging: %s", o.Dir.URL)
	}
}

// The directory-change message does not assume Let's Encrypt.
func TestNeedsSwitchMessageGeneric(t *testing.T) {
	msg := ErrNeedsSwitch.Error()
	if strings.Contains(msg, "other Let's Encrypt directory") || !strings.Contains(msg, "issuer directory changed") {
		t.Fatalf("message: %s", msg)
	}
}

// productionConfig is testConfig with the "le" issuer on production.
func productionConfig() *config.Config {
	cfg := testConfig()
	is := cfg.Issuers["le"]
	is.Directory = "production"
	cfg.Issuers["le"] = is
	return cfg
}

// stagingCA is a test CA whose name carries Let's Encrypt's staging marker.
func stagingCA(t *testing.T) *testCA {
	t.Helper()
	ca := newTestCA(t)
	tmpl := *ca.cert
	tmpl.Subject.CommonName = "(STAGING) Doorwarden Test R1"
	tmpl.RawSubject, tmpl.RawIssuer = nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &ca.key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	ca.cert, _ = x509.ParseCertificate(der)
	return ca
}

// A due imported (production) certificate in a zone whose issuer is a
// staging CA is never replaced from staging: no order, ErrDowngrade
// (Skipped), the row stays imported, the expiry notice still fires and a
// blocked-adoption event is sent once per threshold.
func TestImportedNotAdoptedFromStagingIssuer(t *testing.T) {
	h := newHarness(t, nil, nil) // issuer "le" is staging
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0.Add(10*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	before := h.row(t, ir.Bundle.ID)
	for range 2 {
		res := h.m.Renew(ctx)
		if len(res) != 1 || !errors.Is(res[0].Err, ErrDowngrade) || !errors.Is(res[0].Err, ErrImportedStaging) || !res[0].Skipped {
			t.Fatalf("%+v", res)
		}
	}
	if h.ca.count() != 0 {
		t.Fatalf("%d orders placed from a staging issuer", h.ca.count())
	}
	if r := h.row(t, ir.Bundle.ID); r.Managed || r.Status != StatusImported || r.Path != before.Path || !r.NotAfter.Equal(before.NotAfter) {
		t.Fatalf("row changed: %+v", r)
	}
	var expiring, blocked int
	for _, e := range h.evs.list() {
		switch e.Kind {
		case EventExpiring:
			expiring++
		case EventAdoptionBlocked:
			blocked++
			if !strings.Contains(e.Message, "staging issuer blocks adoption") {
				t.Errorf("message %q", e.Message)
			}
		}
	}
	if expiring != 1 || blocked != 1 {
		t.Fatalf("expiring %d, blocked %d events (want 1, 1): %+v", expiring, blocked, h.evs.list())
	}
	// Crossing the next threshold sends one more.
	h.clock.Add(4 * 24 * time.Hour)
	h.m.Renew(ctx)
	blocked = 0
	for _, e := range h.evs.list() {
		if e.Kind == EventAdoptionBlocked {
			blocked++
		}
	}
	if blocked != 2 {
		t.Fatalf("blocked events %d, want 2", blocked)
	}
}

// RenewNow on an imported production certificate with a staging issuer
// needs AllowDowngrade; an imported staging certificate does not.
func TestRenewNowImportedDowngrade(t *testing.T) {
	h := newHarness(t, nil, nil) // staging issuer
	chain, key := h.ca.ca.leaf(t, []string{"*.example.test", "example.test"}, t0.Add(60*24*time.Hour))
	ir, err := h.m.ImportPEM(ctx, "example.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if r := h.m.RenewNow(ctx, ir.Bundle.ID); !errors.Is(r.Err, ErrDowngrade) || h.ca.count() != 0 {
		t.Fatalf("imported production cert downgraded: %v (orders %d)", r.Err, h.ca.count())
	}
	if r := h.m.RenewNow(ctx, ir.Bundle.ID, AllowDowngrade()); r.Err != nil || h.ca.count() != 1 {
		t.Fatalf("AllowDowngrade: %v (orders %d)", r.Err, h.ca.count())
	}
	if !strings.Contains(h.logs.String(), "replacing a production certificate with a staging one") {
		t.Errorf("no downgrade warning logged")
	}

	sca := stagingCA(t)
	schain, skey := sca.leaf(t, []string{"app.other.test"}, t0.Add(60*24*time.Hour))
	sr, err := h.m.ImportPEM(ctx, "other.test", schain, skey)
	if err != nil {
		t.Fatal(err)
	}
	if r := h.m.RenewNow(ctx, sr.Bundle.ID); r.Err != nil {
		t.Fatalf("imported staging cert refused: %v", r.Err)
	}
}

func TestStagingIssuerMarkers(t *testing.T) {
	for _, tc := range []struct {
		cn, o string
		want  bool
	}{
		{"(STAGING) Pretend Pear X1", "(STAGING) Let's Encrypt", true},
		{"Fake LE Intermediate X1", "", true},
		{"Pebble Intermediate CA 1a2b3c", "", true},
		{"R11", "Let's Encrypt", false},
		{"doorwarden test CA", "", false},
	} {
		c := &x509.Certificate{Issuer: pkix.Name{CommonName: tc.cn}}
		if tc.o != "" {
			c.Issuer.Organization = []string{tc.o}
		}
		if got := stagingIssued(c); got != tc.want {
			t.Errorf("%q/%q: %v", tc.cn, tc.o, got)
		}
	}
}
