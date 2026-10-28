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
`docker-socket-proxy` (read-only, `CONTAINERS=1`, `POST=0`, internal network
only, no host ports). Point the docker source at
`tcp://docker-socket-proxy:2375`.

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
