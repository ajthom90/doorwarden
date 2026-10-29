// Package web serves doorwarden's HTTP endpoints. This file has the health
// endpoint and the mux builder; the API, auth and UI land in later tasks.
//
// /healthz is unauthenticated (container healthchecks call it), so its body
// carries only booleans, source names and times: never an error text, a
// host name, a path or a secret.
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// DefaultProbeTimeout bounds the store probe of one /healthz request.
const DefaultProbeTimeout = 2 * time.Second

// HealthStatus is the JSON body of /healthz.
type HealthStatus struct {
	// Status is "ok" (HTTP 200) or "fail" (HTTP 503: the store is unusable).
	Status string `json:"status"`
	// Degraded is true when the service runs but not fully: a source is
	// down, or the last reconcile ended with an error. Health stays 200.
	Degraded bool `json:"degraded"`
	// Store is "ok" or "unusable".
	Store string `json:"store"`
	// DryRun is the effective global dry-run state of the last cycle.
	DryRun bool `json:"dry_run"`
	// Sources maps a source name to whether its last listing succeeded.
	Sources map[string]bool `json:"sources,omitempty"`
	// LastReconcile is when the last reconcile cycle finished.
	LastReconcile *time.Time `json:"last_reconcile,omitempty"`
	// LastResult is the last cycle's result: ok, error or dry_run.
	LastResult string `json:"last_result,omitempty"`
}

// Health is the /healthz handler. It answers 503 only when Probe fails (the
// store is unusable); a source outage or a failed cycle is 200 with
// Degraded set.
type Health struct {
	// Probe checks the store; nil counts as unusable.
	Probe func(ctx context.Context) error
	// Status returns the orchestrator's snapshot (optional).
	Status func() HealthStatus
	// Timeout bounds Probe (0 means DefaultProbeTimeout).
	Timeout time.Duration
}

// ServeHTTP implements http.Handler.
func (h Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var hs HealthStatus
	if h.Status != nil {
		hs = h.Status()
	}
	for _, up := range hs.Sources {
		if !up {
			hs.Degraded = true
		}
	}
	code := http.StatusOK
	hs.Status, hs.Store = "ok", "ok"
	if !h.probe(r.Context()) {
		code = http.StatusServiceUnavailable
		hs.Status, hs.Store = "fail", "unusable"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(hs)
}

func (h Health) probe(ctx context.Context) bool {
	if h.Probe == nil {
		return false
	}
	to := h.Timeout
	if to <= 0 {
		to = DefaultProbeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	return h.Probe(ctx) == nil
}

// MuxOptions selects the handlers NewMux mounts.
type MuxOptions struct {
	// Health is mounted at /healthz (required).
	Health http.Handler
	// Metrics, when set, is mounted at /metrics. It is unauthenticated here:
	// pass it only when the caller has put authentication (or a private
	// listener) in front of it. The orchestrator does not pass it.
	Metrics http.Handler
}

// NewMux returns a mux with the given handlers. Later tasks add the API and
// UI routes to it.
func NewMux(o MuxOptions) *http.ServeMux {
	mux := http.NewServeMux()
	if o.Health != nil {
		mux.Handle("/healthz", o.Health)
	}
	if o.Metrics != nil {
		mux.Handle("/metrics", o.Metrics)
	}
	return mux
}
