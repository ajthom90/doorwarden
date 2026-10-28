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
type Source interface {
	Name() string
	List(ctx context.Context) ([]model.Service, error)
}
