# Deploying Doorwarden on TrueNAS

TrueNAS app names, menu paths and ports vary by version; the values below are
examples. Use TrueNAS "Custom App" YAML (docker compose) installs.

## Layout

Create a dataset, e.g. `/mnt/<pool>/apps/doorwarden/`, containing:

```
config/doorwarden.yaml     Doorwarden config (read-only mount)
data/                      SQLite state and data/certs/ (owned by uid 65532)
traefik-dynamic/           written by Doorwarden, read by Traefik
traefik/traefik.yml        copy of deploy/traefik/traefik.yml
```

The image runs as the non-root user `65532`; give it ownership of `data/`
and `traefik-dynamic/`.

## Deploy

1. Copy `deploy/compose.truenas.yml` and `deploy/traefik/traefik.yml` onto the
   dataset (adjust the relative volume paths to your dataset paths).
2. Copy `deploy/.env.example` to `.env` (or enter them as app environment
   variables) and fill in the values. Never commit real values.
3. Paste the compose YAML into a new Custom App and deploy.

Services: `doorwarden` (control plane), `traefik` (published 80/443; routing
from the file provider only, no ACME, no dashboard, no docker provider) and
`docker-socket-proxy` (an allowlisting proxy, see below; internal network
only, no host ports). Point the docker source at
`tcp://docker-socket-proxy:2375`. Set `DOCKER_GID` to the group that owns
`/var/run/docker.sock` on the host.

## Docker API access

Doorwarden's Docker source calls exactly one Docker Engine endpoint:
`GET /containers/json?all=1` (container list). The proxy
(`wollomatic/socket-proxy`) allows only `GET` on the path
`^/containers/json$` (matched against the path, not the query), only from the
`doorwarden` service, and answers 403/405 for everything else. This matters
because container inspect would expose other containers' environment
variables (secrets), `/archive` reads files out of containers, and logs and
attach are readable too. A read-only (`:ro`) bind mount of the socket does
not limit any of that; the allowlist does. The socket stays root-equivalent
for anything that can reach an allowed endpoint, so only `doorwarden` shares
the proxy's isolated `socket` network.

If a future Doorwarden version needs another endpoint (for example container
inspect), that must be added explicitly to the proxy flags (a new exact
pattern, never `.*`), and the deploy tests in `internal/deploycheck` updated
deliberately. Symptom of a missing allowlist entry: Docker discovery logs
HTTP 403 from the proxy; check the proxy's logs, which print each denied
request.

## Environment

| Variable | Purpose |
| --- | --- |
| `DOORWARDEN_TAG` | image tag |
| `DOORWARDEN_MASTER_KEY` | encrypts secrets at rest (required) |
| `TRAEFIK_HTTP_PORT`, `TRAEFIK_HTTPS_PORT` | published ports (use 8080/8443 for a trial) |
| `TRUENAS_API_KEY`, `DNS_API_TOKEN` | referenced from the config as `${NAME}` |

## First run

- The default issuer directory is **staging** (untrusted certificates); switch
  to production only after verification.
- Start with `settings.dry_run: true`: Doorwarden reports what it would do
  and changes nothing.
- Confirm health: the `doorwarden` container's healthcheck runs
  `/doorwarden healthcheck`, which GETs `http://127.0.0.1:8080/healthz`
  (override with `DOORWARDEN_HEALTH_URL`; the endpoint is served by the
  control plane). Traefik's healthcheck uses its internal `ping` entry point
  on `:8082`, which is not published.
- Verify published hosts with `scripts/verify.sh`.

See [migration.md](migration.md) when replacing Nginx Proxy Manager.
