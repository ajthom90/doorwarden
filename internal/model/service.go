// Package model defines the service domain types and pure helpers for naming
// and override merging.
package model

// Service lifecycle states.
const (
	StateDiscovered = "discovered"
	StatePending    = "pending"
	StatePublished  = "published"
	StateConflict   = "conflict"
	StateError      = "error"
	StateStopped    = "stopped"
	StateRemoved    = "removed"
)

// Service is a discovered workload that may be published.
type Service struct {
	Key, Source, Name, Zone string
	Backend                 Backend
	Options                 Options
	State                   string
}

// Backend is the upstream a service is proxied to.
type Backend struct {
	Scheme, Host string
	Port         int
	SkipVerify   bool
}

// Options are per-service publishing options.
type Options struct {
	Skip, Websockets bool
	Middlewares      []string
	Rename           string
	// Apex publishes the service at the zone name itself (the zone apex,
	// e.g. "example.test") instead of "<slug(name)>.<zone>". Static entries
	// only; mutually exclusive with Rename.
	Apex bool
}
