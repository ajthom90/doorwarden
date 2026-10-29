package web

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/reconcile"
	"github.com/ajthom90/doorwarden/internal/store"
)

func (e *testEnv) addService(key string) {
	e.ctl.mu.Lock()
	defer e.ctl.mu.Unlock()
	e.ctl.services = append(e.ctl.services, ServiceInfo{Key: key, Source: "docker", Name: "app", Zone: "example.test",
		Hostname: "app.example.test", Backend: model.Backend{Scheme: "http", Host: "192.0.2.30", Port: 8080}, State: "pending"})
	e.ctl.fps[key] = "fp-1"
}

func (e *testEnv) activity() string {
	rows, err := e.st.ListActivity(context.Background(), 500)
	if err != nil {
		e.t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.Message + "\n")
	}
	return b.String()
}

func TestBodyLimitsAndStrictJSON(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	big := `{"enabled": true, "pad": "` + strings.Repeat("x", smallBody+10) + `"}`
	if w := c.do("POST", "/api/v1/settings/dry-run", big); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d %s", w.Code, w.Body)
	}
	huge := `{"yaml": "` + strings.Repeat("x", maxBody+10) + `"}`
	if w := c.do("PUT", "/api/v1/config", huge); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("huge body: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", `{"enabled": true, "extra": 1}`); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unknown field") {
		t.Fatalf("unknown field: %d %s", w.Code, w.Body)
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", `{"enabled": true} {"enabled": false}`); w.Code != http.StatusBadRequest {
		t.Fatalf("trailing: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", `{"enabled": tru`); w.Code != http.StatusBadRequest {
		t.Fatalf("broken: %d", w.Code)
	}
}

func TestDryRunToggle(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	if w := c.do("POST", "/api/v1/settings/dry-run", map[string]bool{"enabled": true}); w.Code != 200 {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	if !e.ctl.dry {
		t.Fatal("dry run not set")
	}
	var got struct{ Enabled bool }
	w := c.do("GET", "/api/v1/settings/dry-run", nil)
	decodeJSONT(t, w, &got)
	if !got.Enabled {
		t.Fatalf("get: %s", w.Body)
	}
	if w := c.do("POST", "/api/v1/settings/dry-run", map[string]any{}); w.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled: %d", w.Code)
	}
	if !strings.Contains(e.activity(), "local:admin set the global dry run to true") {
		t.Fatalf("no audit: %s", e.activity())
	}
}

func TestConfigMaskedRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	w := c.do("GET", "/api/v1/config", nil)
	if w.Code != 200 {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "s3cr3t") {
		t.Fatalf("secret in GET /config: %s", w.Body)
	}
	var got struct{ YAML string }
	decodeJSONT(t, w, &got)
	if !strings.Contains(got.YAML, "secret:fk-token") || !strings.Contains(got.YAML, Masked) {
		t.Fatalf("masked doc: %s", got.YAML)
	}
	// Put it back with one plain change: secrets are kept.
	edited := strings.Replace(got.YAML, "target_ip: 192.0.2.10", "target_ip: 192.0.2.11", 1)
	w = c.do("PUT", "/api/v1/config", map[string]string{"yaml": edited})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "restart_required") {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	disk, _ := os.ReadFile(e.cfgPath)
	for _, want := range []string{"192.0.2.11", "s3cr3t-provider-token", "s3cr3t-eab-hmac", "s3cr3t-truenas-key", "s3cr3t-smtp-pw", "secret:fk-token"} {
		if !strings.Contains(string(disk), want) {
			t.Errorf("file lost %q:\n%s", want, disk)
		}
	}
	if fi, _ := os.Stat(e.cfgPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode())
	}
	if strings.Contains(e.activity(), "s3cr3t") || strings.Contains(e.logBuf.String(), "s3cr3t") {
		t.Fatal("secret in activity or log")
	}
}

func TestConfigPutRejectsInvalid(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	before, _ := os.ReadFile(e.cfgPath)
	cases := map[string]string{
		"bad yaml":       "zones: [unclosed",
		"invalid config": "zones:\n  - name: example.test\n    target_ip: not-an-ip\n",
		"masked plain":   "settings: {default_zone: '" + Masked + "'}\n",
		"unknown key":    "zones: []\nbogus_key: s3cr3t-provider-token\n",
	}
	for name, doc := range cases {
		w := c.do("PUT", "/api/v1/config", map[string]string{"yaml": doc})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "s3cr3t") {
			t.Errorf("%s: secret echoed: %s", name, w.Body)
		}
	}
	after, _ := os.ReadFile(e.cfgPath)
	if string(before) != string(after) {
		t.Fatal("rejected config was written")
	}
}

func TestServiceOverridesEndpoints(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	e.addService("docker/app")
	k := "/api/v1/services/docker%2Fapp"
	w := c.do("POST", k+"/rename", map[string]string{"name": "web"})
	if w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	if o := e.ctl.overrides["docker/app"]; o.Rename == nil || *o.Rename != "web" {
		t.Fatalf("override not stored: %+v", o)
	}
	if w := c.do("POST", k+"/port", map[string]int{"port": 70000}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad port: %d", w.Code)
	}
	if w := c.do("POST", k+"/port", map[string]int{"port": 9090}); w.Code != 200 {
		t.Fatalf("port: %d", w.Code)
	}
	if w := c.do("POST", k+"/unpublish", nil); w.Code != 200 || e.ctl.overrides["docker/app"].Skip == nil || !*e.ctl.overrides["docker/app"].Skip {
		t.Fatalf("unpublish: %d %+v", w.Code, e.ctl.overrides["docker/app"])
	}
	if w := c.do("POST", k+"/publish", nil); w.Code != 200 || *e.ctl.overrides["docker/app"].Skip {
		t.Fatalf("publish: %d", w.Code)
	}
	if w := c.do("POST", k+"/skip-verify", map[string]any{"skip_verify": nil}); w.Code != 200 {
		t.Fatalf("skip-verify clear: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/services/docker%2Fnope/rename", map[string]string{"name": "x"}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/services/..%2F..%2Fetc/rename", map[string]string{"name": "x"}); w.Code != http.StatusBadRequest {
		t.Fatalf("traversal key: %d", w.Code)
	}
	if w := c.do("POST", k+"/explode", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown action: %d", w.Code)
	}
	// GET never mutates.
	if w := c.do("GET", k+"/unpublish", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET action: %d", w.Code)
	}
	act := e.activity()
	if !strings.Contains(act, "local:admin service docker/app: renamed to web") || !strings.Contains(act, "unpublished") {
		t.Fatalf("audit: %s", act)
	}
}

func TestApproveStale(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	e.addService("docker/app")
	var list struct{ Services []ServiceInfo }
	decodeJSONT(t, c.do("GET", "/api/v1/services", nil), &list)
	if len(list.Services) != 1 || list.Services[0].Fingerprint != "fp-1" {
		t.Fatalf("list: %+v", list)
	}
	// The service changes after it was displayed.
	e.ctl.mu.Lock()
	e.ctl.fps["docker/app"] = "fp-2"
	e.ctl.mu.Unlock()
	w := c.do("POST", "/api/v1/services/docker%2Fapp/approve", map[string]string{"fingerprint": "fp-1"})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale: %d %s", w.Code, w.Body)
	}
	var stale struct{ Service ServiceInfo }
	decodeJSONT(t, w, &stale)
	if stale.Service.Fingerprint != "fp-2" {
		t.Fatalf("409 without fresh data: %s", w.Body)
	}
	if w := c.do("POST", "/api/v1/services/docker%2Fapp/approve", map[string]string{"fingerprint": "fp-2"}); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	if e.ctl.approved["docker/app"] != "fp-2" {
		t.Fatal("not approved")
	}
	if w := c.do("POST", "/api/v1/services/docker%2Fapp/approve", map[string]string{}); w.Code != http.StatusBadRequest {
		t.Fatalf("no fingerprint: %d", w.Code)
	}
}

func conflictAction(typ string) reconcile.Action {
	return reconcile.Action{Kind: reconcile.Conflict, Key: "docker/app", Zone: "example.test", Host: "app.example.test",
		Provider: "fk", Owner: "docker/app", Reason: "a foreign record exists",
		Record: &dns.Record{ID: "rec-1", Name: "app.example.test", Type: typ, Value: "192.0.2.99"}}
}

func TestDNSConflicts(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	e.addService("docker/app")
	e.ctl.plan = Plan{At: e.now, Actions: []reconcile.Action{conflictAction("A"), conflictAction("TXT"),
		{Kind: reconcile.Invalid, Key: "docker/app", Reason: "bad backend"}}}
	var got struct{ Conflicts []conflictView }
	decodeJSONT(t, c.do("GET", "/api/v1/dns/conflicts", nil), &got)
	if len(got.Conflicts) != 2 || got.Conflicts[0].ID == "" {
		t.Fatalf("conflicts: %+v", got)
	}
	idA, idTXT := got.Conflicts[0].ID, got.Conflicts[1].ID
	if idA != ConflictID(conflictAction("A")) {
		t.Fatal("id mismatch")
	}
	// Plan issues show on the service.
	var list struct{ Services []ServiceInfo }
	decodeJSONT(t, c.do("GET", "/api/v1/services", nil), &list)
	if len(list.Services[0].Issues) != 3 {
		t.Fatalf("issues: %+v", list.Services[0].Issues)
	}
	if w := c.do("POST", "/api/v1/dns/conflicts/"+idTXT+"/adopt", nil); w.Code != http.StatusConflict {
		t.Fatalf("adopt TXT: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/dns/conflicts/"+idA+"/adopt", nil); w.Code != 200 {
		t.Fatalf("adopt: %d %s", w.Code, w.Body)
	}
	rows, _ := e.st.ListAllOwnedRecords(context.Background())
	if len(rows) != 1 || rows[0].OwnerKey != "docker/app" || rows[0].Value != "192.0.2.99" || rows[0].ProviderRecordID != "rec-1" {
		t.Fatalf("owned: %+v", rows)
	}
	if w := c.do("POST", "/api/v1/dns/conflicts/"+idTXT+"/skip", nil); w.Code != 200 {
		t.Fatalf("skip: %d", w.Code)
	}
	decodeJSONT(t, c.do("GET", "/api/v1/dns/conflicts", nil), &got)
	if !got.Conflicts[1].Skipped {
		t.Fatalf("skip not shown: %+v", got.Conflicts[1])
	}
	if w := c.do("POST", "/api/v1/dns/conflicts/"+strings.Repeat("0", 32)+"/skip", nil); w.Code != http.StatusConflict {
		t.Fatalf("unknown conflict: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/dns/conflicts/..%2Fx/skip", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad id: %d", w.Code)
	}
	var plan struct{ Actions []PlanAction }
	decodeJSONT(t, c.do("GET", "/api/v1/plan", nil), &plan)
	if len(plan.Actions) != 3 {
		t.Fatalf("plan: %+v", plan)
	}
}

func TestRepairAck(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	if w := c.do("POST", "/api/v1/dns/repair/ack", map[string]string{"provider": "fk", "zone": "other.test"}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown zone: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/dns/repair/ack", map[string]string{"provider": "ref", "zone": "example.test"}); w.Code != http.StatusNotFound {
		t.Fatalf("wrong provider: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/dns/repair/ack", map[string]string{"provider": "fk", "zone": "Example.Test."}); w.Code != 200 {
		t.Fatalf("ack: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(e.activity(), "acknowledged the mass DNS repair of fk/example.test") {
		t.Fatal("no audit")
	}
}

func TestProviderTest(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	var pv struct{ Providers []providerView }
	w := c.do("GET", "/api/v1/dns/providers", nil)
	decodeJSONT(t, w, &pv)
	if len(pv.Providers) != 2 || strings.Contains(w.Body.String(), "s3cr3t") || strings.Contains(w.Body.String(), "fk-token") {
		t.Fatalf("providers: %s", w.Body)
	}
	if w := c.do("POST", "/api/v1/dns/providers/ref/test", nil); w.Code != http.StatusNotFound {
		t.Fatalf("non-record provider: %d", w.Code)
	}
	e.ctl.testErr = errors.New("auth failed for token s3cr3t-provider-token")
	w = c.do("POST", "/api/v1/dns/providers/fk/test", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "s3cr3t") || !strings.Contains(w.Body.String(), `"ok":false`) {
		t.Fatalf("test: %d %s", w.Code, w.Body)
	}
	if w := c.do("POST", "/api/v1/dns/providers/fk/test", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d", w.Code)
	}
	e.advance(providerTestEvery + time.Second)
	e.ctl.testErr = nil
	if w := c.do("POST", "/api/v1/dns/providers/fk/test", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("test ok: %d %s", w.Code, w.Body)
	}
}

func TestCertRenewAsync(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	if err := e.st.UpsertCert(context.Background(), storeCert("example.test")); err != nil {
		t.Fatal(err)
	}
	w := c.do("GET", "/api/v1/certs", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "/data/") {
		t.Fatalf("certs: %d %s", w.Code, w.Body)
	}
	e.ctl.renewWait = make(chan struct{})
	if w := c.do("POST", "/api/v1/certs/example.test/renew", nil); w.Code != http.StatusAccepted {
		t.Fatalf("renew: %d %s", w.Code, w.Body)
	}
	if w := c.do("POST", "/api/v1/certs/example.test/renew", nil); w.Code != http.StatusConflict {
		t.Fatalf("second renew: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/certs/nope.test/renew", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown cert: %d", w.Code)
	}
	close(e.ctl.renewWait)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(e.activity(), "renewal of certificate example.test: done") {
		if time.Now().After(deadline) {
			t.Fatalf("renew never finished: %s", e.activity())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := c.do("POST", "/api/v1/certs/switch-production", map[string]any{"issuer": "le"}); w.Code != http.StatusBadRequest {
		t.Fatalf("switch without confirm: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/certs/switch-production", map[string]any{"issuer": "zz", "confirm": true}); w.Code != http.StatusNotFound {
		t.Fatalf("switch unknown: %d", w.Code)
	}
	if w := c.do("POST", "/api/v1/certs/switch-production", map[string]any{"issuer": "le", "confirm": true}); w.Code != http.StatusAccepted {
		t.Fatalf("switch: %d %s", w.Code, w.Body)
	}
}

func TestReadEndpoints(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	for _, p := range []string{"/api/v1/zones", "/api/v1/activity?limit=10", "/api/v1/dns/records", "/api/v1/plan", "/metrics"} {
		if w := c.do("GET", p, nil); w.Code != 200 {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	if w := c.do("GET", "/api/v1/activity?limit=100000", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("limit: %d", w.Code)
	}
}

func TestEventsStream(t *testing.T) {
	old := sseHeartbeat
	sseHeartbeat = 50 * time.Millisecond
	t.Cleanup(func() { sseHeartbeat = old })
	e := newTestEnv(t)
	c := e.setupAdmin()
	// Production-like timeouts: the stream must outlive both.
	ts := httptest.NewUnstartedServer(e.h)
	ts.Config.ReadTimeout = 300 * time.Millisecond
	ts.Config.WriteTimeout = 300 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/events", nil)
	req.AddCookie(c.cookie)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	rd := bufio.NewReader(resp.Body)
	for e.srv.events.clientCount() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(700 * time.Millisecond)
	e.srv.Events().Publish("cycle", map[string]int{"actions": 3})
	found := false
	for i := 0; i < 500 && !found; i++ {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		found = strings.HasPrefix(line, "event: cycle")
	}
	if !found {
		t.Fatal("event not received")
	}
	// Logging out ends the stream at the next heartbeat.
	if w := c.do("POST", "/api/v1/auth/logout", nil); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	done := make(chan struct{})
	go func() {
		for {
			if _, err := rd.ReadString('\n'); err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream outlived the session")
	}
}

func storeCert(zone string) store.Cert {
	return store.Cert{ID: zone, Zone: zone, DomainsJSON: `["*.` + zone + `"]`, Issuer: "le", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Status: "valid", Path: "/data/certs/" + zone, Managed: true}
}

// Even a validator that expanded real environment values cannot echo them:
// config errors are reduced to paths and reasons.
func TestConfigPutErrorsEchoNoValues(t *testing.T) {
	const secret = "s3cr3t-env-master-key"
	e := newTestEnv(t, func(o *Options) {
		o.ValidateConfig = func(raw []byte) error {
			c, err := config.Parse(raw, func(k string) (string, bool) {
				if k == "DOORWARDEN_MASTER_KEY" {
					return secret, true
				}
				return "", false
			})
			if err != nil {
				return err
			}
			if errs := c.Validate(nil); len(errs) > 0 {
				return errs[0]
			}
			return nil
		}
	})
	c := e.setupAdmin()
	for _, doc := range []string{
		"zones:\n  - name: example.test\n    target_ip: \"${DOORWARDEN_MASTER_KEY}\"\n",
		"settings: {grace_period: \"${DOORWARDEN_MASTER_KEY}\"}\n",
	} {
		w := c.do("PUT", "/api/v1/config", map[string]string{"yaml": doc})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("accepted: %d %s", w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "s3cr3t") {
			t.Fatalf("environment value echoed: %s", w.Body)
		}
	}
	w := c.do("PUT", "/api/v1/config", map[string]string{"yaml": "providers:\n  cf: {type: cloudflare, api_token: \"${NOT_SET_VAR}\"}\n"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "NOT_SET_VAR") {
		t.Fatalf("unset variable: %d %s", w.Code, w.Body)
	}
	if strings.Contains(e.activity(), "s3cr3t") || strings.Contains(e.logBuf.String(), "s3cr3t") {
		t.Fatal("secret in activity or log")
	}
}

// A client that never reads cannot pin the stream: every write has a
// finite deadline, so once the socket buffers fill the handler gives up
// and unsubscribes.
func TestEventsStalledReader(t *testing.T) {
	old := sseWriteTimeout
	sseWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { sseWriteTimeout = old })
	e := newTestEnv(t)
	c := e.setupAdmin()
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /api/v1/events HTTP/1.1\r\nHost: dw.example.test\r\nCookie: %s=%s\r\n\r\n", c.cookie.Name, c.cookie.Value)
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.events.clientCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	big := strings.Repeat("x", 256<<10)
	for e.srv.events.clientCount() != 0 && time.Now().Before(deadline) {
		e.srv.Events().Publish("cycle", big)
		time.Sleep(5 * time.Millisecond)
	}
	if n := e.srv.events.clientCount(); n != 0 {
		t.Fatalf("stalled stream still subscribed (%d)", n)
	}
}

// One principal may hold at most maxSSEPerPrincipal streams.
func TestEventsPerPrincipalCap(t *testing.T) {
	e := newTestEnv(t)
	c := e.setupAdmin()
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)
	open := func() *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1/events", nil)
		req.AddCookie(c.cookie)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	for i := range maxSSEPerPrincipal {
		if r := open(); r.StatusCode != 200 {
			t.Fatalf("stream %d: %d", i, r.StatusCode)
		}
	}
	if r := open(); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("stream over the per-principal cap: %d", r.StatusCode)
	}
}

// A trusted-header stream is re-validated at every heartbeat: it ends once
// it has lasted sseHeaderMaxAge (forward auth gets to re-check on
// reconnect).
func TestEventsHeaderStreamExpires(t *testing.T) {
	old := sseHeartbeat
	sseHeartbeat = 20 * time.Millisecond
	t.Cleanup(func() { sseHeartbeat = old })
	e := newTestEnv(t)
	e.setupAdmin()
	r := httptest.NewRequest("GET", "http://dw.example.test/api/v1/events", nil)
	r.RemoteAddr = "192.0.2.100:1234"
	r.Header.Set("X-Auth-User", "alice")
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for e.srv.events.clientCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("header stream ended early")
	default:
	}
	e.advance(sseHeaderMaxAge + time.Second)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("header stream outlived sseHeaderMaxAge")
	}
}

// Logout and a password change end the affected session streams at once,
// not at the next heartbeat.
func TestEventsEndOnLogoutAndPasswordChange(t *testing.T) {
	e := newTestEnv(t) // default heartbeat (25s): only invalidation ends them
	c := e.setupAdmin()
	stream := func(cl *client) chan struct{} {
		r := httptest.NewRequest("GET", "http://dw.example.test/api/v1/events", nil)
		r.RemoteAddr = "198.51.100.20:5555"
		r.AddCookie(cl.cookie)
		done := make(chan struct{})
		n := e.srv.events.clientCount()
		go func() {
			defer close(done)
			e.h.ServeHTTP(httptest.NewRecorder(), r)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for e.srv.events.clientCount() == n && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		return done
	}
	ended := func(done chan struct{}) bool {
		select {
		case <-done:
			return true
		case <-time.After(2 * time.Second):
			return false
		}
	}
	other, _ := e.login("admin", testPassword)
	s1, s2 := stream(c), stream(other)
	if w := c.do("POST", "/api/v1/auth/logout", nil); w.Code != 200 {
		t.Fatalf("logout = %d", w.Code)
	}
	if !ended(s1) {
		t.Fatal("stream outlived its session's logout")
	}
	select {
	case <-s2:
		t.Fatal("logout ended another session's stream")
	default:
	}
	third, _ := e.login("admin", testPassword)
	s3 := stream(third)
	if w := third.do("POST", "/api/v1/auth/password", map[string]string{"current": testPassword, "new": "another-password-456"}); w.Code != 200 {
		t.Fatalf("password change = %d %s", w.Code, w.Body)
	}
	if !ended(s2) || !ended(s3) {
		t.Fatal("streams outlived a password change")
	}
}
