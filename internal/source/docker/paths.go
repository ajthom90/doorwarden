package docker

// ContainersListPath is the only Docker Engine API path this source calls
// (GET, with the query all=1). deploy/compose.truenas.yml allowlists exactly
// this path in the socket proxy; a test keeps the two in sync. Any new
// endpoint must be added to that allowlist explicitly.
const ContainersListPath = "/containers/json"
