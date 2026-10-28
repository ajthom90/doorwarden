// Package dns defines the DNS provider interface and registry. Real providers
// live under providers/ and register themselves from init(); providers/all.go
// blank-imports them so one import wires everything up.
package dns

import (
	"context"
	"errors"

	"github.com/ajthom90/doorwarden/internal/secrets"
)

// Sentinel errors providers return so callers can branch with errors.Is.
var (
	// ErrNotFound is returned when updating a record that does not exist.
	ErrNotFound = errors.New("dns: record not found")
	// ErrRecordExists is returned when creating a record whose (name, type)
	// already exists with a different value.
	ErrRecordExists = errors.New("dns: record already exists with a different value")
)

// Record is a single DNS record.
//
// Name conventions: records passed to and returned from providers use
// fully-qualified names without a trailing dot, lowercased, for example
// "app.example.test". A wildcard A record has Name "*.zone" (for example
// "*.example.test"). Zone arguments use the same form ("example.test").
// ID is provider-assigned and may be empty on input to CreateRecord.
type Record struct {
	ID    string
	Name  string
	Type  string
	Value string
	TTL   int
}

// Capabilities describes what a provider type supports. They are static per
// type, declared at Register time. A provider whose real capabilities depend
// on runtime probing must document that and declare the conservative value.
type Capabilities struct {
	WildcardA bool // can create "*.zone" A records
	MultiZone bool // one credential can manage several zones
	Update    bool // supports in-place UpdateRecord
	TTL       bool // honours Record.TTL
}

// Provider manages records at one DNS provider.
type Provider interface {
	Type() string
	Capabilities() Capabilities
	// Test verifies credentials and connectivity.
	Test(ctx context.Context) error
	ListRecords(ctx context.Context, zone string) ([]Record, error)
	// CreateRecord is idempotent for an identical existing record.
	CreateRecord(ctx context.Context, zone string, r Record) (Record, error)
	// UpdateRecord returns ErrNotFound if the record does not exist.
	UpdateRecord(ctx context.Context, zone string, r Record) (Record, error)
	// DeleteRecord of a missing record returns nil.
	DeleteRecord(ctx context.Context, zone string, r Record) error
}

// SecretResolver resolves secret references found in provider config.
type SecretResolver interface {
	Resolve(ref string) (secrets.Secret, error)
}
