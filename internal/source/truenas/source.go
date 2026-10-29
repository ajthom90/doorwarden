package truenas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/secrets"
	"github.com/ajthom90/doorwarden/internal/source"
)

// PortLookup supplies published host ports for apps whose portals are empty or
// unusable (typically backed by the Docker source).
type PortLookup interface {
	PublishedPorts(ctx context.Context, appName string) ([]int, error)
}

// Config configures a TrueNAS source.
type Config struct {
	URL         string
	APIKey      secrets.Secret
	InsecureTLS bool
	TargetIP    string // host every backend uses; portal hosts are ignored; "" (no default zone) makes running apps errors
	DefaultZone string // normalized settings.default_zone ("" if none), for error messages
	Name        string // source name, default "truenas"
}

// Source discovers TrueNAS apps via app.query (read-only).
//
// Apps whose state is not RUNNING are returned as StateStopped, and apps whose
// backend cannot be determined as StateError; both carry no backend (Host ""
// and Port 0), see source.Source. The reason for an Error service is available
// from Warnings (reset on every List call).
type Source struct {
	name     string
	targetIP string
	defZone  string
	client   *Client
	ports    PortLookup

	mu       sync.Mutex
	warnings []string
}

// New validates cfg and builds a Source. ports may be nil.
func New(cfg Config, ports PortLookup) (*Source, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("truenas: URL is required")
	}
	c := NewClient(cfg.URL, cfg.APIKey, cfg.InsecureTLS)
	if c.urlErr != nil {
		return nil, fmt.Errorf("truenas: %v", c.urlErr)
	}
	name := cfg.Name
	if name == "" {
		name = "truenas"
	}
	return &Source{name: name, targetIP: cfg.TargetIP, defZone: cfg.DefaultZone, client: c, ports: ports}, nil
}

// Name returns the configured source name.
func (s *Source) Name() string { return s.name }

// Close releases the websocket connection.
func (s *Source) Close() error { return s.client.Close() }

// Warnings returns the reasons apps were put in error state by the most
// recent List call.
func (s *Source) Warnings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.warnings...)
}

type apiApp struct {
	Name            string            `json:"name"`
	State           string            `json:"state"`
	Portals         map[string]string `json:"portals"`
	ActiveWorkloads struct {
		UsedPorts []usedPort `json:"used_ports"`
	} `json:"active_workloads"`
}

// usedPort is one entry of app.query's active_workloads.used_ports. TrueNAS
// versions differ in whether ports are numbers or strings.
type usedPort struct {
	Protocol  string `json:"protocol"`
	HostPorts []struct {
		HostPort flexPort `json:"host_port"`
	} `json:"host_ports"`
}

// flexPort decodes a port given as a JSON number or string; anything else
// (or out of range) is 0.
type flexPort int

func (f *flexPort) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		*f = 0
		return nil
	}
	*f = flexPort(n)
	return nil
}

// hostPorts returns the app's published tcp host ports, or nil when
// app.query reported none (not validated then).
func (a apiApp) hostPorts() map[int]bool {
	var out map[int]bool
	for _, u := range a.ActiveWorkloads.UsedPorts {
		if p := strings.ToLower(strings.TrimSpace(u.Protocol)); p != "" && p != "tcp" {
			continue
		}
		for _, h := range u.HostPorts {
			if h.HostPort > 0 {
				if out == nil {
					out = map[int]bool{}
				}
				out[int(h.HostPort)] = true
			}
		}
	}
	// a list with only udp entries is still "reported": no tcp port allowed
	if out == nil && len(a.ActiveWorkloads.UsedPorts) > 0 {
		out = map[int]bool{}
	}
	return out
}

func unavailable(err error) error {
	return fmt.Errorf("truenas: %w: %w", source.ErrSourceUnavailable, err)
}

// List returns every app known to TrueNAS.
func (s *Source) List(ctx context.Context) ([]model.Service, error) {
	s.mu.Lock()
	s.warnings = nil
	s.mu.Unlock()

	raw, err := s.client.Call(ctx, "app.query")
	if err != nil {
		return nil, unavailable(err)
	}
	var apps []apiApp
	if err := json.Unmarshal(raw, &apps); err != nil {
		return nil, unavailable(errors.New("decode app.query result"))
	}

	var out []model.Service
	var warns []string
	for _, a := range apps {
		if a.Name == "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, unavailable(err)
		}
		svc, warn := s.convert(ctx, a)
		if warn != "" {
			warns = append(warns, warn)
		}
		out = append(out, svc)
	}
	// A cancelled ctx may have made lookups fail; do not report those as
	// per-app errors from a "successful" List.
	if err := ctx.Err(); err != nil {
		return nil, unavailable(err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.mu.Lock()
	s.warnings = warns
	s.mu.Unlock()
	return out, nil
}

// pickPortal returns the "Web UI" portal, else the first in sorted-name order.
func pickPortal(p map[string]string) (string, bool) {
	if v, ok := p["Web UI"]; ok {
		return v, true
	}
	if len(p) == 0 {
		return "", false
	}
	names := make([]string, 0, len(p))
	for n := range p {
		names = append(names, n)
	}
	sort.Strings(names)
	return p[names[0]], true
}

// parsePortal returns scheme and port; usable is false when the URL cannot be
// parsed at all (the caller falls back to the port lookup).
func parsePortal(raw string) (scheme string, port int, usable bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	scheme = strings.ToLower(u.Scheme)
	if ps := u.Port(); ps != "" {
		p, err := strconv.Atoi(ps)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, false
		}
		return scheme, p, true
	}
	switch scheme {
	case "http":
		return scheme, 80, true
	case "https":
		return scheme, 443, true
	}
	return scheme, 0, true
}

func (s *Source) convert(ctx context.Context, a apiApp) (model.Service, string) {
	svc := model.Service{Key: "truenas:" + a.Name, Source: s.name, Name: a.Name, State: model.StateDiscovered}
	svc.Backend.Scheme = "http"

	fail := func(err error) (model.Service, string) {
		svc.State = model.StateError
		svc.Backend.Host, svc.Backend.Port = "", 0
		return svc, fmt.Sprintf("app %q: %v", a.Name, err)
	}

	portals := a.Portals
	if allowed := a.hostPorts(); allowed != nil && a.State == "RUNNING" && len(portals) > 0 {
		// Final-review H2: a parsable portal is only trusted when its port is
		// one of the app's own published host ports; others are dropped.
		// Unparsable portals are not judged (nor used): with no parsable
		// portal the published-ports lookup applies. The message names
		// portals and port numbers only, never their URLs (userinfo and
		// query tokens would reach the logs and the activity).
		portals = map[string]string{}
		var bad []string
		for n, v := range a.Portals {
			_, p, usable := parsePortal(v)
			switch {
			case !usable:
			case allowed[p]:
				portals[n] = v
			default:
				bad = append(bad, fmt.Sprintf("%q (port %d)", n, p))
			}
		}
		if len(portals) == 0 && len(bad) > 0 {
			sort.Strings(bad)
			return fail(fmt.Errorf("no portal port is one of the app's published ports: %s", strings.Join(bad, ", ")))
		}
	}
	port := 0
	if portal, ok := pickPortal(portals); ok {
		if sc, p, usable := parsePortal(portal); usable {
			if sc != "http" && sc != "https" {
				if a.State == "RUNNING" {
					return fail(fmt.Errorf("unexpected portal scheme %q (want http or https)", sc))
				}
			} else {
				svc.Backend.Scheme, port = sc, p
			}
		}
	}

	if a.State == "RUNNING" && strings.TrimSpace(s.targetIP) == "" {
		// No default zone with a target_ip: apps cannot name a zone, so
		// none has a backend host.
		if s.defZone != "" {
			return fail(fmt.Errorf("zone %s (the default zone) has no target_ip: set its target_ip", s.defZone))
		}
		return fail(errors.New("no zone: set settings.default_zone"))
	}
	if a.State != "RUNNING" {
		// Backend is unknown while not running: only Scheme is set.
		svc.State = model.StateStopped
		svc.Backend.Host, svc.Backend.Port = "", 0
		return svc, ""
	}

	if port == 0 {
		svc.Backend.Scheme = "http"
		if s.ports == nil {
			return fail(errors.New("no usable portal and no port lookup configured"))
		}
		ps, err := s.ports.PublishedPorts(ctx, a.Name)
		if err != nil {
			return fail(fmt.Errorf("no usable portal; port lookup failed: %v", err))
		}
		for _, p := range ps {
			if p > 0 && p <= 65535 && (port == 0 || p < port) {
				port = p
			}
		}
		if port == 0 {
			return fail(errors.New("no usable portal and no published port found"))
		}
	}
	svc.Backend.Host, svc.Backend.Port = s.targetIP, port
	return svc, ""
}

var _ source.Source = (*Source)(nil)
