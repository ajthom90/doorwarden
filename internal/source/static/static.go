// Package static turns statically configured services (off-box targets, apps
// without labels) into model.Services. Hosts may be hostnames or IPs and are
// never resolved here.
//
// Key is "static:<id>" when the entry has an id, else "static:<slug of name>";
// renaming an entry that has no id therefore changes its key. Entries with
// neither (an invalid definition) share the key "static:unnamed".
//
// Validation uses config.StaticService.Problems. An invalid definition yields a
// Service with State error and an empty backend (Host "", Port 0; see
// source.Source for the consumer contract); the reasons are available from
// Warnings . Duplicate keys are all returned; the
// reconciler resolves the conflict.
package static

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/model"
)

// Config configures the static source.
type Config struct {
	Services []config.StaticService
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

// List converts the entries; it never fails.
func (s *Source) List(_ context.Context) ([]model.Service, error) {
	var out []model.Service
	var warns []string
	for _, e := range s.cfg.Services {
		key := e.Key()
		if key == "" {
			key = "static:unnamed"
		}
		svc := model.Service{
			Key: key, Source: "static", Name: e.Name, Zone: e.Zone,
			Options: model.Options{Skip: e.Skip, Websockets: e.Websockets,
				Middlewares: append([]string(nil), e.Middlewares...), Rename: e.Rename},
			State: model.StateDiscovered,
		}
		if probs := e.Problems(); len(probs) > 0 {
			svc.State = model.StateError
			warns = append(warns, fmt.Sprintf("static %s: %s", key, strings.Join(probs, "; ")))
		} else {
			scheme, host, port := e.Target()
			svc.Backend = model.Backend{Scheme: scheme, Host: host, Port: port, SkipVerify: e.SkipVerify}
		}
		out = append(out, svc)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	s.mu.Lock()
	s.warnings = warns
	s.mu.Unlock()
	return out, nil
}
