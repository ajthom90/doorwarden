package metrics

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func scrape(t *testing.T, m *Metrics) (string, *http.Response) {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return string(b), rec.Result()
}

func families(t *testing.T, m *Metrics) map[string]*dto.MetricFamily {
	t.Helper()
	fs, err := m.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, f := range fs {
		out[f.GetName()] = f
	}
	return out
}

func value(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	f := families(t, m)[name]
	if f == nil {
		t.Fatalf("no family %s", name)
	}
next:
	for _, mt := range f.Metric {
		for _, lp := range mt.Label {
			if want, ok := labels[lp.GetName()]; !ok || want != lp.GetValue() {
				continue next
			}
		}
		if len(mt.Label) != len(labels) {
			continue
		}
		switch {
		case mt.Gauge != nil:
			return mt.Gauge.GetValue()
		case mt.Counter != nil:
			return mt.Counter.GetValue()
		case mt.Histogram != nil:
			return float64(mt.Histogram.GetSampleCount())
		}
	}
	t.Fatalf("no series %s%v", name, labels)
	return 0
}

func TestHandlerExposesDocumentedMetrics(t *testing.T) {
	m := New("v1.2.3")
	m.AllowZones("example.test")
	m.AllowSources("docker")
	m.AllowProviderTypes("cloudflare")
	m.SetServices(map[string]int{"published": 3})
	m.ReconcileDone("ok", 250*time.Millisecond)
	m.ReconcileAction("DNSEnsure", 2)
	m.DNSOperation("cloudflare", "ensure", "ok")
	m.SetCertExpiry("example.test", time.Now().Add(48*time.Hour))
	m.CertRenewal("ok")
	m.SourceUp("docker", true)
	m.SourceListDuration("docker", 20*time.Millisecond)
	m.Notification("webhook", "ok")
	body, resp := scrape(t, m)
	for _, name := range []string{
		"doorwarden_services", "doorwarden_reconcile_total", "doorwarden_reconcile_duration_seconds",
		"doorwarden_reconcile_actions_total", "doorwarden_dns_operations_total", "doorwarden_cert_expiry_seconds",
		"doorwarden_cert_renewal_total", "doorwarden_source_up", "doorwarden_source_list_duration_seconds",
		"doorwarden_notifications_total", "doorwarden_build_info", "go_goroutines", "process_start_time_seconds",
	} {
		if !strings.Contains(body, "# HELP "+name+" ") || !strings.Contains(body, "# TYPE "+name+" ") {
			t.Errorf("missing HELP/TYPE for %s", name)
		}
	}
	for _, line := range []string{
		`doorwarden_services{state="published"} 3`,
		`doorwarden_services{state="error"} 0`,
		`doorwarden_reconcile_total{result="ok"} 1`,
		`doorwarden_reconcile_actions_total{kind="DNSEnsure"} 2`,
		`doorwarden_dns_operations_total{op="ensure",provider_type="cloudflare",result="ok"} 1`,
		`doorwarden_cert_renewal_total{result="ok"} 1`,
		`doorwarden_source_up{source="docker"} 1`,
		`doorwarden_notifications_total{result="ok",sender="webhook"} 1`,
		`doorwarden_build_info{version="v1.2.3"} 1`,
	} {
		if !strings.Contains(body, line) {
			t.Errorf("missing line %s", line)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type %q", ct)
	}
	if v := value(t, m, "doorwarden_cert_expiry_seconds", map[string]string{"zone": "example.test"}); v < 47*3600 || v > 48*3600+5 {
		t.Errorf("cert expiry seconds = %v", v)
	}
	if v := value(t, m, "doorwarden_reconcile_duration_seconds", map[string]string{}); v != 1 {
		t.Errorf("histogram count = %v", v)
	}
}

func TestPrivateRegistryNotGlobal(t *testing.T) {
	m := New("dev")
	m.ReconcileDone("ok", time.Second)
	// A second instance in one process must not panic on duplicate registration.
	m2 := New("dev")
	if m == m2 || m.reg == m2.reg {
		t.Fatal("instances share a registry")
	}
}

func TestSetServicesZeroFillsAndResets(t *testing.T) {
	m := New("dev")
	m.SetServices(map[string]int{"published": 2, "error": 1})
	m.SetServices(map[string]int{"published": 1})
	if v := value(t, m, "doorwarden_services", map[string]string{"state": "error"}); v != 0 {
		t.Fatalf("stale state not reset: %v", v)
	}
	m.SetServices(map[string]int{"weird-state": 4, "also-weird": 1})
	if v := value(t, m, "doorwarden_services", map[string]string{"state": "other"}); v != 5 {
		t.Fatalf("other = %v", v)
	}
}

func TestLabelWhitelistMapsUnknownToOther(t *testing.T) {
	m := New("dev")
	m.AllowZones("example.test")
	m.AllowSources("docker")
	m.ReconcileDone("host.example.test: boom", time.Second)
	m.ReconcileAction("192.0.2.1", 1)
	m.DNSOperation("secret-provider-name", "nuke", "kaboom")
	m.CertRenewal("x509: certificate has expired for app.example.test")
	m.SourceUp("my-container-name", true)
	m.SourceListDuration("other-container", time.Second)
	m.SetCertExpiry("app.internal.example.test", time.Now().Add(time.Hour))
	m.Notification("slack-webhook-url-token", "dial tcp 10.0.0.1: refused")
	body, _ := scrape(t, m)
	for _, bad := range []string{"host.example.test", "192.0.2.1", "secret-provider-name", "nuke", "kaboom", "x509:", "my-container-name", "other-container", "app.internal", "slack-webhook", "10.0.0.1"} {
		if strings.Contains(body, bad) {
			t.Errorf("arbitrary value %q reached the exposition", bad)
		}
	}
	if v := value(t, m, "doorwarden_reconcile_total", map[string]string{"result": "other"}); v != 1 {
		t.Errorf("reconcile other = %v", v)
	}
	if v := value(t, m, "doorwarden_source_up", map[string]string{"source": "other"}); v != 1 {
		t.Errorf("source other = %v", v)
	}
	if v := value(t, m, "doorwarden_dns_operations_total", map[string]string{"provider_type": "other", "op": "other", "result": "other"}); v != 1 {
		t.Errorf("dns other = %v", v)
	}
}

func TestCardinalityIsBounded(t *testing.T) {
	m := New("dev")
	m.AllowZones("example.test")
	m.AllowSources("docker")
	count := func() int {
		n := 0
		for name, f := range families(t, m) {
			if strings.HasPrefix(name, "doorwarden_") {
				n += len(f.Metric)
			}
		}
		return n
	}
	before := count()
	for i := 0; i < 5000; i++ {
		s := fmt.Sprintf("val-%d-%s", i, strings.Repeat("x", i%40))
		m.ReconcileDone(s, time.Millisecond)
		m.ReconcileAction(s, 1)
		m.DNSOperation(s, s, s)
		m.SetCertExpiry(s, time.Now())
		m.CertRenewal(s)
		m.SourceUp(s, i%2 == 0)
		m.SourceListDuration(s, time.Millisecond)
		m.Notification(s, s)
		m.SetServices(map[string]int{s: 1})
	}
	// "other" series may appear but the total stays tiny.
	if after := count(); after > before+40 {
		t.Fatalf("series grew from %d to %d", before, after)
	}
}

func TestAllowListsAreBounded(t *testing.T) {
	m := New("dev")
	for i := 0; i < 10000; i++ {
		m.AllowZones(fmt.Sprintf("z%d.example.test", i))
		m.AllowSources(fmt.Sprintf("s%d", i))
		m.AllowProviderTypes(fmt.Sprintf("p%d", i))
	}
	for i := 0; i < 10000; i++ {
		m.SetCertExpiry(fmt.Sprintf("z%d.example.test", i), time.Now())
		m.SourceUp(fmt.Sprintf("s%d", i), true)
		m.DNSOperation(fmt.Sprintf("p%d", i), "ensure", "ok")
	}
	n := 0
	for name, f := range families(t, m) {
		if strings.HasPrefix(name, "doorwarden_") {
			n += len(f.Metric)
		}
	}
	if n > 1000 {
		t.Fatalf("%d series", n)
	}
}

func TestNilReceiverIsNoop(t *testing.T) {
	var m *Metrics
	m.SetServices(map[string]int{"published": 1})
	m.ReconcileDone("ok", time.Second)
	m.ReconcileAction("DNSEnsure", 1)
	m.DNSOperation("a", "b", "c")
	m.SetCertExpiry("z", time.Now())
	m.ClearCertExpiry("z")
	m.CertRenewal("ok")
	m.SourceUp("s", true)
	m.SourceListDuration("s", time.Second)
	m.Notification("webhook", "ok")
	m.AllowZones("z")
	m.AllowSources("s")
	m.AllowProviderTypes("p")
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil)) // must not panic
	var o ReconcileObserver = m
	o.ObserveReconcile("ok", time.Second)
}

func TestConcurrentUpdatesRaceClean(t *testing.T) {
	m := New("dev")
	m.AllowZones("example.test")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				m.SetServices(map[string]int{"published": i})
				m.ReconcileDone("ok", time.Millisecond)
				m.ReconcileAction("RouteWrite", 1)
				m.SetCertExpiry("example.test", time.Now().Add(time.Hour))
				m.SourceUp("docker", i%2 == 0)
				m.AllowSources(fmt.Sprintf("s%d", g))
				m.Notification("smtp", "error")
				if i%50 == 0 {
					scrape(t, m)
				}
			}
		}(g)
	}
	wg.Wait()
	if v := value(t, m, "doorwarden_reconcile_total", map[string]string{"result": "ok"}); v != 1600 {
		t.Fatalf("lost updates: %v", v)
	}
}

func TestClearCertExpiryUnregisteredIsNoop(t *testing.T) {
	m := New("dev")
	m.SetCertExpiry("unregistered.example.test", time.Now().Add(time.Hour)) // shared "other" series
	m.ClearCertExpiry("another-unregistered.example.test")
	m.ClearCertExpiry("other")
	if body, _ := scrape(t, m); !strings.Contains(body, `doorwarden_cert_expiry_seconds{zone="other"}`) {
		t.Fatal("shared other series was cleared by an unregistered zone")
	}
}

func TestNotificationResultsClosedSet(t *testing.T) {
	m := New("dev")
	for _, r := range []string{"rate_limited", "filtered_severity", "dropped_queue_full", "suppressed_dedupe"} {
		m.Notification("dispatcher", r)
		if v := value(t, m, "doorwarden_notifications_total", map[string]string{"sender": "dispatcher", "result": r}); v != 1 {
			t.Errorf("%s = %v", r, v)
		}
	}
	m.Notification("dispatcher", "dropped") // retired value
	if v := value(t, m, "doorwarden_notifications_total", map[string]string{"sender": "dispatcher", "result": "other"}); v != 1 {
		t.Errorf("unknown result not mapped to other: %v", v)
	}
}

func TestClearCertExpiry(t *testing.T) {
	m := New("dev")
	m.AllowZones("example.test")
	m.SetCertExpiry("example.test", time.Now().Add(time.Hour))
	m.ClearCertExpiry("example.test")
	if body, _ := scrape(t, m); strings.Contains(body, `doorwarden_cert_expiry_seconds{`) {
		t.Fatal("series still exposed")
	}
}

func TestBuildInfoVersionSanitized(t *testing.T) {
	m := New("v1\n\"evil\"" + strings.Repeat("x", 500))
	body, _ := scrape(t, m)
	line := ""
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, "doorwarden_build_info{") {
			line = l
		}
	}
	if line == "" || len(line) > 200 || strings.Contains(line, "evil") {
		t.Fatalf("build_info line %q", line)
	}
}
