// Package fake is an in-memory, goroutine-safe DNS provider for tests.
package fake

import (
	"context"
	"fmt"
	"sync"

	"github.com/ajthom90/doorwarden/internal/dns"
	"github.com/ajthom90/doorwarden/internal/dns/httpx"
)

// Type is the registry name of the fake provider.
const Type = "fake"

func init() {
	dns.Register(Type, func(cfg map[string]any, _ dns.SecretResolver) (dns.Provider, error) {
		wildcard := true
		if _, ok := cfg["wildcard"]; ok {
			b, err := httpx.BoolOption(cfg, "wildcard")
			if err != nil {
				return nil, fmt.Errorf("fake: %w", err)
			}
			wildcard = b
		}
		return New(wildcard), nil
	}, dns.ConfigSchema{Fields: []dns.Field{
		{Name: "wildcard", Help: "support wildcard A records (default true)"},
	}}, dns.Capabilities{WildcardA: true, MultiZone: true, Update: true, TTL: true})
}

// Call is one recorded provider invocation.
type Call struct {
	Op     string // method name, e.g. "CreateRecord"
	Zone   string
	Record dns.Record
}

// Fake implements dns.Provider in memory.
type Fake struct {
	wildcard bool

	mu      sync.Mutex
	nextID  int
	zones   map[string][]dns.Record
	calls   []Call
	failing map[string][]error
}

// New returns a fake with the given wildcard capability. wildcard=false is an
// intentional fixture: the instance reports narrower capabilities than the
// static ones registered for CapsFor (WildcardA true).
func New(wildcard bool) *Fake {
	return &Fake{wildcard: wildcard, zones: map[string][]dns.Record{}, failing: map[string][]error{}}
}

// FailNext makes the next call to op (a method name such as "Test" or
// "CreateRecord") return err. Multiple calls queue in order.
func (f *Fake) FailNext(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing[op] = append(f.failing[op], err)
}

// Calls returns a copy of the call log, including calls that failed.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

func (f *Fake) Type() string { return Type }

func (f *Fake) Capabilities() dns.Capabilities {
	return dns.Capabilities{WildcardA: f.wildcard, MultiZone: true, Update: true, TTL: true}
}

// begin records the call and pops any injected failure. Caller holds f.mu.
func (f *Fake) begin(op, zone string, r dns.Record) error {
	f.calls = append(f.calls, Call{Op: op, Zone: zone, Record: r})
	if q := f.failing[op]; len(q) > 0 {
		f.failing[op] = q[1:]
		return q[0]
	}
	return nil
}

func (f *Fake) Test(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.begin("Test", "", dns.Record{})
}

func (f *Fake) ListRecords(_ context.Context, zone string) ([]dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ListRecords", zone, dns.Record{}); err != nil {
		return nil, err
	}
	return append([]dns.Record(nil), f.zones[zone]...), nil
}

func (f *Fake) find(zone string, r dns.Record) int {
	for i, e := range f.zones[zone] {
		if e.Name == r.Name && e.Type == r.Type {
			return i
		}
	}
	return -1
}

func (f *Fake) findID(zone, id string) int {
	for i, e := range f.zones[zone] {
		if e.ID == id {
			return i
		}
	}
	return -1
}

func (f *Fake) CreateRecord(_ context.Context, zone string, r dns.Record) (dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("CreateRecord", zone, r); err != nil {
		return dns.Record{}, err
	}
	if i := f.find(zone, r); i >= 0 {
		if f.zones[zone][i].Value == r.Value {
			return f.zones[zone][i], nil
		}
		return dns.Record{}, dns.ErrRecordExists
	}
	f.nextID++
	r.ID = fmt.Sprintf("fake-%d", f.nextID)
	f.zones[zone] = append(f.zones[zone], r)
	return r, nil
}

func (f *Fake) UpdateRecord(_ context.Context, zone string, r dns.Record) (dns.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("UpdateRecord", zone, r); err != nil {
		return dns.Record{}, err
	}
	var i int
	if r.ID != "" {
		i = f.findID(zone, r.ID)
	} else {
		i = f.find(zone, r)
	}
	if i < 0 {
		return dns.Record{}, dns.ErrNotFound
	}
	if cur := f.zones[zone][i]; cur.Name != r.Name || cur.Type != r.Type {
		return dns.Record{}, fmt.Errorf("fake: update of record %q: name/type mismatch (%s %s vs stored %s %s): %w",
			r.ID, r.Name, r.Type, cur.Name, cur.Type, dns.ErrNotFound)
	}
	r.ID = f.zones[zone][i].ID
	f.zones[zone][i] = r
	return r, nil
}

func (f *Fake) DeleteRecord(_ context.Context, zone string, r dns.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("DeleteRecord", zone, r); err != nil {
		return err
	}
	i := -1
	if r.ID != "" {
		i = f.findID(zone, r.ID)
	} else if j := f.find(zone, r); j >= 0 && f.zones[zone][j].Value == r.Value {
		i = j
	}
	if i >= 0 {
		f.zones[zone] = append(f.zones[zone][:i], f.zones[zone][i+1:]...)
	}
	return nil
}
