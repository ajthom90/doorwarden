// Package docker discovers services from Docker container labels using the
// Docker Engine HTTP API (read-only GET /containers/json), so it works through
// a read-only socket proxy with CONTAINERS=1.
//
// Labels (opt-in; containers without doorwarden.enable=true are ignored):
//
//	doorwarden.enable       must be exactly "true"
//	doorwarden.name         service name (default: container name)
//	doorwarden.port         container (private) port
//	doorwarden.scheme       http|https (default http)
//	doorwarden.zone         DNS zone
//	doorwarden.skip-verify  bool, skip upstream TLS verification
//	doorwarden.websockets   bool
//	doorwarden.middlewares  comma-separated list
//
// Containers that are not running are still returned, with State stopped, so
// a stop or restart never removes anything downstream. Because Docker reports
// no ports for a stopped container, its backend port is only known when the
// doorwarden.port label is set.
//
// Invalid labels or an unresolvable backend yield a Service with State error;
// the reason is available from Warnings (reset on every List call).
//
// Two containers may legitimately claim the same doorwarden.name; both are
// returned and the reconciler resolves the conflict.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/source"
)

// Config configures a Docker source.
type Config struct {
	Endpoint string // unix:///var/run/docker.sock or tcp://host:2375
	TargetIP string // host used with published ports
	Network  string // optional shared network; use the container IP on it
	Name     string // source name, default "docker"
}

// Source is the Docker discovery source.
type Source struct {
	cfg    Config
	base   string
	sock   string
	client *http.Client

	mu       sync.Mutex
	warnings []string
}

// New validates the endpoint and builds a Source.
func New(cfg Config) (*Source, error) {
	if cfg.Name == "" {
		cfg.Name = "docker"
	}
	s := &Source{cfg: cfg}
	tr := &http.Transport{}
	switch {
	case strings.HasPrefix(cfg.Endpoint, "unix://"):
		s.sock = strings.TrimPrefix(cfg.Endpoint, "unix://")
		if s.sock == "" {
			return nil, fmt.Errorf("docker: empty unix socket path")
		}
		s.base = "http://docker"
		sock := s.sock
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
	case strings.HasPrefix(cfg.Endpoint, "tcp://"):
		host := strings.TrimPrefix(cfg.Endpoint, "tcp://")
		if host == "" {
			return nil, fmt.Errorf("docker: empty tcp endpoint")
		}
		s.base = "http://" + host
	default:
		return nil, fmt.Errorf("docker: unsupported endpoint %q (want unix:// or tcp://)", cfg.Endpoint)
	}
	s.client = &http.Client{Timeout: 10 * time.Second, Transport: tr}
	return s, nil
}

// Name returns the configured source name.
func (s *Source) Name() string { return s.cfg.Name }

// Warnings returns the reasons containers were put in error state by the most
// recent List call.
func (s *Source) Warnings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.warnings...)
}

type apiPort struct {
	PrivatePort int
	PublicPort  int
	Type        string
}

type apiContainer struct {
	Names           []string
	State           string
	Labels          map[string]string
	Ports           []apiPort
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func unavailable(err error) error {
	return fmt.Errorf("docker: %w: %v", source.ErrSourceUnavailable, err)
}

// List returns all opted-in containers.
func (s *Source) List(ctx context.Context) ([]model.Service, error) {
	s.mu.Lock()
	s.warnings = nil
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+"/containers/json?all=1", nil)
	if err != nil {
		return nil, unavailable(err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, unavailable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, unavailable(fmt.Errorf("unexpected status %s", resp.Status))
	}
	var cs []apiContainer
	if err := json.NewDecoder(resp.Body).Decode(&cs); err != nil {
		return nil, unavailable(fmt.Errorf("decode response: %v", err))
	}

	var out []model.Service
	var warns []string
	for _, c := range cs {
		if c.Labels["doorwarden.enable"] != "true" || len(c.Names) == 0 {
			continue
		}
		svc, warn := s.convert(c)
		if warn != "" {
			warns = append(warns, warn)
		}
		out = append(out, svc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.mu.Lock()
	s.warnings = warns
	s.mu.Unlock()
	return out, nil
}

func parseBool(labels map[string]string, key string) (bool, error) {
	v, ok := labels[key]
	if !ok {
		return false, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("invalid %s %q", key, v)
	}
	return b, nil
}

func (s *Source) convert(c apiContainer) (model.Service, string) {
	cname := strings.TrimPrefix(c.Names[0], "/")
	l := c.Labels
	svc := model.Service{Key: "docker:" + cname, Source: s.cfg.Name, Name: cname,
		Zone: l["doorwarden.zone"], State: model.StateDiscovered}
	if n := l["doorwarden.name"]; n != "" {
		svc.Name = n
	}
	svc.Backend.Scheme = "http"

	fail := func(err error) (model.Service, string) {
		svc.State = model.StateError
		return svc, fmt.Sprintf("container %q: %v", cname, err)
	}

	switch sc := l["doorwarden.scheme"]; sc {
	case "", "http", "https":
		if sc != "" {
			svc.Backend.Scheme = sc
		}
	default:
		return fail(fmt.Errorf("invalid doorwarden.scheme %q (want http or https)", sc))
	}
	var err error
	if svc.Backend.SkipVerify, err = parseBool(l, "doorwarden.skip-verify"); err != nil {
		return fail(err)
	}
	if svc.Options.Websockets, err = parseBool(l, "doorwarden.websockets"); err != nil {
		return fail(err)
	}
	for _, m := range strings.Split(l["doorwarden.middlewares"], ",") {
		if m = strings.TrimSpace(m); m != "" {
			svc.Options.Middlewares = append(svc.Options.Middlewares, m)
		}
	}

	// Private tcp ports, deduplicated (IPv4/IPv6 entries repeat).
	published := map[int]int{}
	var private []int
	for _, p := range c.Ports {
		if p.Type != "" && p.Type != "tcp" {
			continue
		}
		if _, seen := published[p.PrivatePort]; !seen {
			private = append(private, p.PrivatePort)
			published[p.PrivatePort] = 0
		}
		if p.PublicPort > 0 {
			published[p.PrivatePort] = p.PublicPort
		}
	}

	port := 0
	if v, ok := l["doorwarden.port"]; ok {
		port, err = strconv.Atoi(strings.TrimSpace(v))
		if err != nil || port < 1 || port > 65535 {
			return fail(fmt.Errorf("invalid doorwarden.port %q", v))
		}
	}

	stopped := c.State != "running"
	if port == 0 {
		switch {
		case len(private) == 1:
			port = private[0]
		case len(private) == 0 && stopped:
			// Ports are unknown while stopped; keep the service listed.
		case len(private) == 0:
			return fail(fmt.Errorf("no exposed port; set doorwarden.port"))
		default:
			return fail(fmt.Errorf("multiple exposed ports %v; set doorwarden.port", private))
		}
	}
	svc.Backend.Port = port

	if stopped {
		svc.State = model.StateStopped
		svc.Backend.Host = s.cfg.TargetIP
		return svc, ""
	}
	if n, ok := c.NetworkSettings.Networks[s.cfg.Network]; s.cfg.Network != "" && ok && n.IPAddress != "" {
		svc.Backend.Host = n.IPAddress
		return svc, ""
	}
	if pub := published[port]; pub > 0 && s.cfg.TargetIP != "" {
		svc.Backend.Host = s.cfg.TargetIP
		svc.Backend.Port = pub
		return svc, ""
	}
	return fail(fmt.Errorf("no published host port for %d and no IP on the configured network", port))
}

var _ source.Source = (*Source)(nil)
