// Package source defines the discovery-source contract shared by the Docker
// and TrueNAS sources.
package source

import (
	"context"
	"errors"

	"github.com/ajthom90/doorwarden/internal/model"
)

// ErrSourceUnavailable means the source could not be queried (daemon down,
// non-200 response, ...). The reconciler must treat this as "unknown state",
// never as "all services are gone".
var ErrSourceUnavailable = errors.New("source unavailable")

// Source discovers services from a workload platform.
//
// Backend contract: a service whose State is Stopped or Error carries no
// authoritative backend (Host empty and/or Port 0 means unknown). Consumers
// must not overwrite a stored last-known backend from it, and must not remove
// or stop rendering routes, DNS or certs because of it. Only Discovered
// services may update a stored backend; a new host port after a restart
// arrives as Discovered.
//
// Implementations that expose Warnings() []string report it only for the most
// recent List; a failed List leaves it empty. Callers must not call List
// concurrently on one source (or must hold a mutex across List+Warnings).
type Source interface {
	Name() string
	List(ctx context.Context) ([]model.Service, error)
}
