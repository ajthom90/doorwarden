// Package metrics exposes doorwarden's Prometheus metrics on a private
// registry. Every label value comes from a closed set (or an admin-registered
// allowlist) and anything else becomes "other", so hostnames, keys, IPs,
// container names and error text can never create series or leak.
//
// A nil *Metrics is a valid no-op sink, so packages can take an optional one.
package metrics

import (
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const other = "other"

// Closed label sets (service states match internal/model, action kinds match
// internal/reconcile.ActionKind; kept as literals to avoid import cycles).
var (
	serviceStates = []string{"discovered", "pending", "published", "conflict", "error", "stopped", "removed"}
	reconcileRes  = []string{"ok", "error", "dry_run"}
	actionKinds   = []string{"DNSEnsure", "DNSDelete", "CertEnsure", "RouteWrite", "RouteRemove", "Conflict", "Skip", "Invalid", "ScheduleRemoval", "CancelRemoval"}
	dnsOps        = []string{"ensure", "delete", "list"}
	opResults     = []string{"ok", "error"}
	renewResults  = []string{"ok", "error"}
	senderTypes   = []string{"webhook", "ntfy", "smtp"}
	notifyResults = []string{"ok", "error", "dropped"}
)

// maxAllowed caps each admin-registered allowlist.
const maxAllowed = 64

var versionRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

// ReconcileObserver is what the reconcile loop needs; *Metrics implements it.
type ReconcileObserver interface {
	ObserveReconcile(result string, d time.Duration)
	SetServices(countsByState map[string]int)
	ReconcileAction(kind string, n int)
}

type set struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func newSet(initial ...string) *set {
	s := &set{m: map[string]struct{}{}}
	for _, v := range initial {
		s.m[v] = struct{}{}
	}
	return s
}

func (s *set) add(vs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range vs {
		if len(s.m) >= maxAllowed {
			return
		}
		if v != "" && len(v) <= 253 {
			s.m[v] = struct{}{}
		}
	}
}

// norm returns v if allowed, else "other".
func (s *set) norm(v string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.m[v]; ok {
		return v
	}
	return other
}

// Metrics holds all collectors. Create with New.
type Metrics struct {
	reg *prometheus.Registry

	services       *prometheus.GaugeVec
	reconcileTotal *prometheus.CounterVec
	reconcileDur   prometheus.Histogram
	actions        *prometheus.CounterVec
	dnsOps         *prometheus.CounterVec
	certRenewal    *prometheus.CounterVec
	sourceUp       *prometheus.GaugeVec
	sourceDur      *prometheus.HistogramVec
	notifications  *prometheus.CounterVec

	states, results, kinds, ops, opRes, renew, senders, nres *set
	zones, sources, providerTypes                            *set

	certs *certCollector
}

// New builds a Metrics on a fresh private registry with the Go and process
// collectors. version is exported once as doorwarden_build_info.
func New(version string) *Metrics {
	m := &Metrics{
		reg:           prometheus.NewRegistry(),
		states:        newSet(serviceStates...),
		results:       newSet(reconcileRes...),
		kinds:         newSet(actionKinds...),
		ops:           newSet(dnsOps...),
		opRes:         newSet(opResults...),
		renew:         newSet(renewResults...),
		senders:       newSet(senderTypes...),
		nres:          newSet(notifyResults...),
		zones:         newSet(),
		sources:       newSet(),
		providerTypes: newSet(),
	}
	m.services = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "doorwarden_services", Help: "Services by lifecycle state."}, []string{"state"})
	m.reconcileTotal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "doorwarden_reconcile_total", Help: "Reconcile runs by result (ok, error, dry_run)."}, []string{"result"})
	m.reconcileDur = prometheus.NewHistogram(prometheus.HistogramOpts{Name: "doorwarden_reconcile_duration_seconds", Help: "Duration of reconcile runs.", Buckets: prometheus.DefBuckets})
	m.actions = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "doorwarden_reconcile_actions_total", Help: "Planned reconcile actions by kind."}, []string{"kind"})
	m.dnsOps = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "doorwarden_dns_operations_total", Help: "DNS provider operations by provider type, operation and result."}, []string{"provider_type", "op", "result"})
	m.certRenewal = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "doorwarden_cert_renewal_total", Help: "Certificate issuance/renewal attempts by result."}, []string{"result"})
	m.sourceUp = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "doorwarden_source_up", Help: "Whether the last listing of a source succeeded (1) or failed (0)."}, []string{"source"})
	m.sourceDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "doorwarden_source_list_duration_seconds", Help: "Duration of source listings.", Buckets: prometheus.DefBuckets}, []string{"source"})
	m.notifications = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "doorwarden_notifications_total", Help: "Notification deliveries by sender type and result (ok, error, dropped)."}, []string{"sender", "result"})
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "doorwarden_build_info", Help: "Build information; the value is always 1."}, []string{"version"})
	m.certs = &certCollector{
		now:   time.Now,
		desc:  prometheus.NewDesc("doorwarden_cert_expiry_seconds", "Seconds until the earliest certificate expiry per zone (negative when expired).", []string{"zone"}, nil),
		zones: map[string]time.Time{},
	}
	m.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.services, m.reconcileTotal, m.reconcileDur, m.actions, m.dnsOps, m.certRenewal, m.sourceUp, m.sourceDur, m.notifications, buildInfo, m.certs)

	// Pre-create closed-set series so they scrape as 0 from the start.
	for _, s := range append(serviceStates, other) {
		m.services.WithLabelValues(s)
	}
	for _, s := range append(reconcileRes, other) {
		m.reconcileTotal.WithLabelValues(s)
	}
	for _, s := range append(actionKinds, other) {
		m.actions.WithLabelValues(s)
	}
	for _, s := range append(renewResults, other) {
		m.certRenewal.WithLabelValues(s)
	}
	for _, s := range senderTypes {
		for _, r := range notifyResults {
			m.notifications.WithLabelValues(s, r)
		}
	}
	if !versionRe.MatchString(version) {
		version = "unknown"
	}
	buildInfo.WithLabelValues(version).Set(1)
	return m
}

// Handler serves the registry in Prometheus text format. On a nil *Metrics it
// answers 404.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg, MaxRequestsInFlight: 4})
}

// AllowZones registers zone names that may appear as zone labels.
func (m *Metrics) AllowZones(z ...string) {
	if m != nil {
		m.zones.add(z...)
	}
}

// AllowSources registers source names (from config) allowed as source labels.
func (m *Metrics) AllowSources(s ...string) {
	if m != nil {
		m.sources.add(s...)
	}
}

// AllowProviderTypes registers DNS provider types (not config names) allowed
// as provider_type labels.
func (m *Metrics) AllowProviderTypes(p ...string) {
	if m != nil {
		m.providerTypes.add(p...)
	}
}

// SetServices sets the per-state gauge. States absent from the map are set to
// 0; unknown states are summed into "other".
func (m *Metrics) SetServices(countsByState map[string]int) {
	if m == nil {
		return
	}
	sums := map[string]int{}
	for st, n := range countsByState {
		sums[m.states.norm(st)] += n
	}
	for _, st := range append(append([]string(nil), serviceStates...), other) {
		m.services.WithLabelValues(st).Set(float64(sums[st]))
	}
}

// ReconcileDone records one reconcile run (result: ok|error|dry_run).
func (m *Metrics) ReconcileDone(result string, d time.Duration) {
	if m == nil {
		return
	}
	m.reconcileTotal.WithLabelValues(m.results.norm(result)).Inc()
	m.reconcileDur.Observe(d.Seconds())
}

// ObserveReconcile implements ReconcileObserver.
func (m *Metrics) ObserveReconcile(result string, d time.Duration) { m.ReconcileDone(result, d) }

// ReconcileAction counts n planned actions of kind (a reconcile.ActionKind).
func (m *Metrics) ReconcileAction(kind string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.actions.WithLabelValues(m.kinds.norm(kind)).Add(float64(n))
}

// DNSOperation counts one provider call (op: ensure|delete|list; result: ok|error).
func (m *Metrics) DNSOperation(providerType, op, result string) {
	if m == nil {
		return
	}
	m.dnsOps.WithLabelValues(m.providerTypes.norm(providerType), m.ops.norm(op), m.opRes.norm(result)).Inc()
}

// SetCertExpiry records the earliest certificate expiry for a configured
// zone; the exposed value counts down at scrape time.
func (m *Metrics) SetCertExpiry(zone string, notAfter time.Time) {
	if m == nil {
		return
	}
	m.certs.set(m.zones.norm(zone), notAfter)
}

// ClearCertExpiry removes a zone's expiry series.
func (m *Metrics) ClearCertExpiry(zone string) {
	if m == nil {
		return
	}
	m.certs.clear(m.zones.norm(zone))
}

// CertRenewal counts one issuance/renewal attempt (result: ok|error).
func (m *Metrics) CertRenewal(result string) {
	if m == nil {
		return
	}
	m.certRenewal.WithLabelValues(m.renew.norm(result)).Inc()
}

// SourceUp records whether the last listing of source succeeded.
func (m *Metrics) SourceUp(source string, up bool) {
	if m == nil {
		return
	}
	v := 0.0
	if up {
		v = 1
	}
	m.sourceUp.WithLabelValues(m.sources.norm(source)).Set(v)
}

// SourceListDuration observes one source listing.
func (m *Metrics) SourceListDuration(source string, d time.Duration) {
	if m == nil {
		return
	}
	m.sourceDur.WithLabelValues(m.sources.norm(source)).Observe(d.Seconds())
}

// Notification counts one delivery; its signature matches notify.Options.Observe.
func (m *Metrics) Notification(sender, result string) {
	if m == nil {
		return
	}
	m.notifications.WithLabelValues(m.senders.norm(sender), m.nres.norm(result)).Inc()
}

// certCollector reports seconds-to-expiry computed at scrape time.
type certCollector struct {
	now   func() time.Time
	desc  *prometheus.Desc
	mu    sync.Mutex
	zones map[string]time.Time
}

func (c *certCollector) set(zone string, t time.Time) {
	c.mu.Lock()
	c.zones[zone] = t
	c.mu.Unlock()
}

func (c *certCollector) clear(zone string) {
	c.mu.Lock()
	delete(c.zones, zone)
	c.mu.Unlock()
}

func (c *certCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *certCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for z, t := range c.zones {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, t.Sub(now).Seconds(), z)
	}
}
