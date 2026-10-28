// Package static turns statically configured services (off-box targets, apps
// without labels) into model.Services. Hosts may be hostnames or IPs and are
// never resolved here.
//
// config.StaticService only carries name/host/upstream/port, so the richer
// per-service options live on Entry; FromConfig lifts a config entry into one.
//
// An invalid definition yields a Service with State error and an empty
// backend (Host "", Port 0; see source.Source for the consumer contract); the
// reasons are available from Warnings (reset on every List call). Duplicate
// ids/names are all returned; the reconciler resolves the conflict.
package static

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"sync"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
)

// Entry is one static service definition.
type Entry struct {
	ID, Name, Zone string
	Scheme, Host   string // Scheme defaults to http
	Port           int
	SkipVerify     bool // implies https unless Scheme says otherwise
	Websockets     bool
	Middlewares    []string
	Rename         string
	Skip           bool

	// invalid is set by FromConfig when the upstream URL cannot be parsed.
	invalid string
}

// Config configures the static source.
type Config struct {
	Services []Entry
	Name     string // source name, default "static"
}

// Source is the static source.
type Source struct {
	cfg Config

	mu       sync.Mutex
	warnings []string
}

// New builds a Source.
func New(cfg Config) *Source {
	if cfg.Name == "" {
		cfg.Name = "static"
	}
	return &Source{cfg: cfg}
}

// Name returns the source name.
func (s *Source) Name() string { return s.cfg.Name }

// Warnings returns the reasons services were put in error state by the most
// recent List call.
func (s *Source) Warnings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.warnings...)
}

// FromConfig converts a config entry. A non-empty Upstream (scheme://host[:port])
// overrides Host/Port; otherwise Host and Port are used.
func FromConfig(c config.StaticService) Entry {
	e := Entry{Name: c.Name, Host: c.Host, Port: c.Port}
	if c.Upstream == "" {
		return e
	}
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Hostname() == "" {
		e.invalid = fmt.Sprintf("invalid upstream %q", c.Upstream)
		return e
	}
	e.Scheme, e.Host = u.Scheme, u.Hostname()
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			e.invalid = fmt.Sprintf("invalid upstream port %q", p)
			return e
		}
		e.Port = n
	} else {
		e.Port = c.Port
	}
	return e
}

// List converts the entries; it never fails.
func (s *Source) List(_ context.Context) ([]model.Service, error) {
	var out []model.Service
	var warns []string
	for i, e := range s.cfg.Services {
		id := e.ID
		if id == "" {
			id = e.Name
		}
		if id == "" {
			id = fmt.Sprintf("unnamed-%d", i)
		}
		svc := model.Service{
			Key: "static:" + id, Source: "static", Name: e.Name, Zone: e.Zone,
			Options: model.Options{Skip: e.Skip, Websockets: e.Websockets,
				Middlewares: append([]string(nil), e.Middlewares...), Rename: e.Rename},
			State: model.StateDiscovered,
		}
		scheme := e.Scheme
		if scheme == "" {
			scheme = "http"
			if e.SkipVerify {
				scheme = "https"
			}
		}
		var reason string
		switch {
		case e.invalid != "":
			reason = e.invalid
		case e.Name == "":
			reason = "empty name"
		case e.Host == "":
			reason = "empty host"
		case e.Port < 1 || e.Port > 65535:
			reason = fmt.Sprintf("port %d out of range 1..65535", e.Port)
		case scheme != "http" && scheme != "https":
			reason = fmt.Sprintf("unsupported scheme %q", scheme)
		}
		if reason != "" {
			svc.State = model.StateError
			svc.Backend = model.Backend{Scheme: scheme, SkipVerify: e.SkipVerify}
			warns = append(warns, fmt.Sprintf("static %s: %s", svc.Key, reason))
		} else {
			svc.Backend = model.Backend{Scheme: scheme, Host: e.Host, Port: e.Port, SkipVerify: e.SkipVerify}
		}
		out = append(out, svc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.mu.Lock()
	s.warnings = warns
	s.mu.Unlock()
	return out, nil
}
