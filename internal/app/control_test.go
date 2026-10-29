package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/approval"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/traefik"
	"github.com/ajthom90/doorwarden/internal/web"
)

func hasKind(acts []reconcile.Action, k reconcile.ActionKind) bool {
	for _, x := range acts {
		if x.Kind == k {
			return true
		}
	}
	return false
}

func info(t *testing.T, a *App, key string) web.ServiceInfo {
	t.Helper()
	for _, s := range a.ServiceList() {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("%s not listed: %+v", key, a.ServiceList())
	return web.ServiceInfo{}
}

// UI overrides set through the control plane change what the next cycle
// publishes.
func TestUIOverrideTakesEffect(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	if res := a.RunOnce(ctx); res.Err != nil {
		t.Fatal(res.Err)
	}
	if s := info(t, a, "docker/app"); s.State != model.StatePublished || s.Hostname != "app.example.test" {
		t.Fatalf("before: %+v", s)
	}
	err := a.SetServiceOverride(ctx, "docker/app", func(o *model.UIOverrides) error {
		n, p := "web", 9090
		o.Rename, o.Port = &n, &p
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if res := a.RunOnce(ctx); res.Err != nil || !res.Rendered {
		t.Fatalf("cycle: %+v", res)
	}
	b, err := os.ReadFile(filepath.Join(e.dir, traefik.RoutesFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "web.example.test") || !strings.Contains(string(b), "198.51.100.5:9090") {
		t.Fatalf("override not rendered:\n%s", b)
	}
	if !hasA(t, e.fk, "web.example.test", "192.0.2.10") {
		t.Fatal("no record for the renamed host")
	}
	s := info(t, a, "docker/app")
	if s.Hostname != "web.example.test" || s.Overrides.Rename == nil || s.Backend.Port != 9090 {
		t.Fatalf("listing: %+v", s)
	}
	// Overrides survive cycles (TouchService does not clobber them).
	a.RunOnce(ctx)
	if row, _, _ := e.st.GetService(ctx, "docker/app"); !strings.Contains(row.OverridesJSON, `"rename":"web"`) {
		t.Fatalf("stored overrides: %q", row.OverridesJSON)
	}

	// Unpublish: absent from the plan, removal scheduled after the grace.
	if err := a.SetServiceOverride(ctx, "docker/app", func(o *model.UIOverrides) error { v := true; o.Skip = &v; return nil }); err != nil {
		t.Fatal(err)
	}
	res := a.RunOnce(ctx)
	if !hasKind(res.Actions, reconcile.ScheduleRemoval) {
		t.Fatalf("unpublish scheduled no removal: %+v", res.Actions)
	}
	if s := info(t, a, "docker/app"); s.State != "skipped" {
		t.Fatalf("state after unpublish: %+v", s)
	}
	if err := a.SetServiceOverride(ctx, "docker/app", func(o *model.UIOverrides) error { v := false; o.Skip = &v; return nil }); err != nil {
		t.Fatal(err)
	}
	res = a.RunOnce(ctx)
	if !hasKind(res.Actions, reconcile.CancelRemoval) {
		t.Fatalf("publish did not cancel the removal: %+v", res.Actions)
	}
	if p := a.LastPlan(); p.At.IsZero() || len(p.Actions) != len(res.Actions) {
		t.Fatalf("last plan: %+v", p)
	}
}

func TestUIOverrideValidation(t *testing.T) {
	e := newEnv(t, testYAML)
	s := svc("docker", "app")
	e.src.set(nil, s)
	a := e.app()
	ctx := context.Background()
	a.RunOnce(ctx)
	if err := a.SetServiceOverride(ctx, "docker/nope", func(*model.UIOverrides) error { return nil }); !errors.Is(err, web.ErrUnknownService) {
		t.Fatalf("unknown: %v", err)
	}
	var oe *model.OverrideError
	for name, edit := range map[string]func(*model.UIOverrides) error{
		"port":        func(o *model.UIOverrides) error { p := 70000; o.Port = &p; return nil },
		"rename":      func(o *model.UIOverrides) error { n := "Not A Label"; o.Rename = &n; return nil },
		"skip_verify": func(o *model.UIOverrides) error { v := true; o.SkipVerify = &v; return nil }, // http backend
	} {
		if err := a.SetServiceOverride(ctx, "docker/app", edit); !errors.As(err, &oe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if row, _, _ := e.st.GetService(ctx, "docker/app"); row.OverridesJSON != "" && row.OverridesJSON != "{}" {
		t.Fatalf("invalid override stored: %q", row.OverridesJSON)
	}
}

// An override row that cannot be parsed keeps the service unpublished.
func TestUnreadableOverrideSkips(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app()
	ctx := context.Background()
	a.RunOnce(ctx)
	if err := e.st.SetServiceOverrides(ctx, "docker/app", "docker", `{"skip":false,"bogus":1}`, time.Now()); err != nil {
		t.Fatal(err)
	}
	res := a.RunOnce(ctx)
	if !hasKind(res.Actions, reconcile.ScheduleRemoval) {
		t.Fatalf("unreadable override published: %+v", res.Actions)
	}
}

// In approve mode a stale fingerprint is refused; a rename made by an
// administrator through a UI override carries the approval over in the same
// action (final-review H2 ruling: the admin is the authority; audited).
func TestRenameOverrideReapproves(t *testing.T) {
	e := newEnv(t, testYAML)
	e.src.set(nil, svc("docker", "app"))
	a := e.app(func(o *Options) { o.Sources = []SourceSpec{{Source: e.src, Mode: approval.ModeApprove}} })
	ctx := context.Background()
	a.RunOnce(ctx)
	s := info(t, a, "docker/app")
	if s.State != model.StatePending || s.Fingerprint == "" {
		t.Fatalf("pending: %+v", s)
	}
	if err := a.Approve(ctx, "docker/app", "stale"); !errors.Is(err, approval.ErrStale) {
		t.Fatalf("stale approve: %v", err)
	}
	if err := a.Approve(ctx, "docker/app", s.Fingerprint); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if s := info(t, a, "docker/app"); s.State != model.StatePublished {
		t.Fatalf("approved: %+v", s)
	}
	if err := a.SetServiceOverride(ctx, "docker/app", func(o *model.UIOverrides) error { n := "web"; o.Rename = &n; return nil }); err != nil {
		t.Fatal(err)
	}
	a.RunOnce(ctx)
	if s := info(t, a, "docker/app"); s.State != model.StatePublished || s.Hostname != "web.example.test" {
		t.Fatalf("renamed service not re-approved: %+v", s)
	}
	acts, _ := e.st.ListActivity(ctx, 100)
	found := false
	for _, x := range acts {
		found = found || (x.Kind == "approval" && strings.Contains(x.Message, "docker/app") && strings.Contains(x.Message, "carried over"))
	}
	if !found {
		t.Fatalf("re-approval not audited: %+v", acts)
	}
	// the source changing the backend still needs re-approval
	moved := svc("docker", "app")
	moved.Backend.Port = 8081
	e.src.set(nil, moved)
	a.RunOnce(ctx)
	if s := info(t, a, "docker/app"); s.State != model.StatePending {
		t.Fatalf("source backend change kept the approval: %+v", s)
	}
}

func TestValidateConfigBytes(t *testing.T) {
	env := func(string) (string, bool) { return "", false }
	ok := "zones:\n  - name: example.test\n    target_ip: 192.0.2.10\n"
	if err := validateConfigBytes([]byte(ok), env, false); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigBytes([]byte("zones:\n  - name: example.test\n    target_ip: nope\n"), env, false); err == nil {
		t.Fatal("invalid config accepted")
	}
	issuer := ok + "    certificate: {issuer: le, challenge: dns-01, dns_provider: cf}\nproviders:\n  cf: {type: cloudflare, api_token: x}\nissuers:\n  le: {email: a@example.test}\n"
	if err := validateConfigBytes([]byte(issuer), env, false); err == nil || !strings.Contains(err.Error(), "MASTER_KEY") {
		t.Fatalf("master key requirement: %v", err)
	}
}

// A client's config document is never expanded with the real environment,
// so a validation error cannot carry a variable's value back.
func TestValidateConfigBytesNoEnvLeak(t *testing.T) {
	const secret = "s3cr3t-master-key-value"
	env := func(k string) (string, bool) {
		switch k {
		case "DOORWARDEN_MASTER_KEY":
			return secret, true
		case "OTHER_SECRET":
			return "s3cr3t-other-value", true
		}
		return "", false
	}
	for _, doc := range []string{
		"zones:\n  - name: example.test\n    target_ip: \"${DOORWARDEN_MASTER_KEY}\"\n",
		"zones:\n  - name: example.test\n    target_ip: 192.0.2.10\n    records: {provider: \"${OTHER_SECRET}\", mode: per-host}\n",
		"settings: {grace_period: \"${DOORWARDEN_MASTER_KEY}\"}\nzones:\n  - name: example.test\n    target_ip: 192.0.2.10\n",
	} {
		err := validateConfigBytes([]byte(doc), env, true)
		if err == nil {
			t.Fatalf("accepted: %s", doc)
		}
		if strings.Contains(err.Error(), "s3cr3t") {
			t.Fatalf("environment value leaked: %v", err)
		}
	}
	// An unset variable is reported by name only.
	err := validateConfigBytes([]byte("zones:\n  - name: example.test\n    target_ip: \"${NOT_SET_VAR}\"\n"), env, true)
	if err == nil || !strings.Contains(err.Error(), "NOT_SET_VAR") {
		t.Fatalf("unset variable: %v", err)
	}
	// A set variable in a free-form field still validates.
	ok := "zones:\n  - name: example.test\n    target_ip: 192.0.2.10\n    records: {provider: fk, mode: per-host}\nproviders:\n  fk: {type: fake, token: \"${OTHER_SECRET}\"}\n"
	if err := validateConfigBytes([]byte(ok), env, true); err != nil {
		t.Fatalf("valid document with a set variable: %v", err)
	}
}
