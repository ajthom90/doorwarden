package acme

import (
	"context"
	"time"
)

// EventKind names a certificate notification.
type EventKind string

const (
	// EventFailure: an issuance or renewal attempt failed (the previous
	// certificate, if any, keeps serving).
	EventFailure EventKind = "cert.failure"
	// EventExpiring: a certificate crossed an expiry threshold (sent once
	// per certificate, threshold and expiry date).
	EventExpiring EventKind = "cert.expiring"
)

// ExpiryThresholds are the remaining-lifetime thresholds that trigger an
// EventExpiring, largest first.
var ExpiryThresholds = []time.Duration{14 * 24 * time.Hour, 7 * 24 * time.Hour, 24 * time.Hour}

// Event is one notification. It never carries key material.
type Event struct {
	Kind     EventKind
	CertID   string
	Zone     string
	Names    []string
	NotAfter time.Time
	// Threshold is set for EventExpiring.
	Threshold time.Duration
	// Message is a human-readable summary (for EventFailure the error).
	Message string
	// NextAttempt is set for EventFailure.
	NextAttempt time.Time
}

// Notifier receives certificate events. Implementations (webhook, ntfy,
// SMTP) live elsewhere; Notify must not block for long and handles its own
// delivery errors.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// NotifierFunc adapts a function to Notifier.
type NotifierFunc func(ctx context.Context, e Event)

// Notify calls f.
func (f NotifierFunc) Notify(ctx context.Context, e Event) { f(ctx, e) }
