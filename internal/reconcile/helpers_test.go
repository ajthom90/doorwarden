package reconcile

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajthom90/doorwarden/internal/config"
	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/model"
	"github.com/ajthom90/doorwarden/internal/store"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const target = "192.0.2.10"

// zone builds a zone config using provider "dnsp" and issuer "le".
func zone(name, mode, strategy string) config.Zone {
	return config.Zone{
		Name:        name,
		TargetIP:    target,
		Records:     config.Records{Provider: "dnsp", Mode: mode},
		Certificate: config.Certificate{Issuer: "le", Strategy: strategy, Challenge: "dns-01"},
	}
}

func cfgOf(zs ...config.Zone) *config.Config {
	return &config.Config{Zones: zs, Settings: config.Settings{GracePeriod: 24 * time.Hour}}
}

func sourceOf(key string) string {
	if i := strings.IndexByte(key, ':'); i > 0 {
		return key[:i]
	}
	return "unknown"
}

// svc builds a service; Source derives from the key prefix.
func svc(key, name, zone, state, host string, port int) model.Service {
	return model.Service{Key: key, Source: sourceOf(key), Name: name, Zone: zone, State: state,
		Backend: model.Backend{Scheme: "http", Host: host, Port: port}}
}

func pub(key, name, zone string, port int) model.Service {
	return svc(key, name, zone, model.StatePublished, "198.51.100.5", port)
}

func known(key, zone, host string, removedAfter *time.Time) KnownService {
	return KnownService{Key: key, Source: sourceOf(key), Zone: zone, Hostname: host, RemovedAfter: removedAfter}
}

func knownMap(ks ...KnownService) map[string]KnownService {
	m := map[string]KnownService{}
	for _, k := range ks {
		m[k.Key] = k
	}
	return m
}

func owned(zone, name, typ, value, owner string) store.DNSRecord {
	return store.DNSRecord{Provider: "dnsp", Zone: zone, Name: name, Type: typ, Value: value,
		ProviderRecordID: "id-" + name, OwnerKey: owner, CreatedAt: t0.Add(-time.Hour)}
}

// listed returns Foreign listings that are known and empty for each zone of
// provider "dnsp".
func listed(zones ...string) map[string][]dns.Record {
	m := map[string][]dns.Record{}
	for _, z := range zones {
		m["dnsp/"+z] = []dns.Record{}
	}
	return m
}

func tp(t time.Time) *time.Time { return &t }

// sum renders an action compactly for comparisons.
func sum(a Action) string {
	s := fmt.Sprintf("%s %s %s %s", a.Kind, a.Zone, a.Host, a.Key)
	if a.Record != nil {
		s += fmt.Sprintf(" [%s %s %s]", a.Record.Name, a.Record.Type, a.Record.Value)
	}
	if len(a.Names) > 0 {
		s += " " + strings.Join(a.Names, ",")
	}
	if a.Backend != nil {
		s += fmt.Sprintf(" ->%s:%d", a.Backend.Host, a.Backend.Port)
	}
	if a.Repair {
		s += " repair"
	}
	return strings.TrimSpace(strings.Join(strings.Fields(s), " "))
}

func sums(as []Action) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, sum(a))
	}
	return out
}

func ofKind(as []Action, k ActionKind) []Action {
	var out []Action
	for _, a := range as {
		if a.Kind == k {
			out = append(out, a)
		}
	}
	return out
}

func forKey(as []Action, key string) []Action {
	var out []Action
	for _, a := range as {
		if a.Key == key {
			out = append(out, a)
		}
	}
	return out
}

func assertSums(t *testing.T, got []Action, want ...string) {
	t.Helper()
	g := sums(got)
	if strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Fatalf("actions mismatch\n got:\n  %s\nwant:\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

func assertNone(t *testing.T, got []Action, kinds ...ActionKind) {
	t.Helper()
	for _, k := range kinds {
		if f := ofKind(got, k); len(f) > 0 {
			t.Fatalf("unexpected %s actions: %v", k, sums(f))
		}
	}
}

func sortedCopy(s []string) []string {
	c := append([]string{}, s...)
	sort.Strings(c)
	return c
}
