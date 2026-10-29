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

Both `doorwarden` and `traefik` run as UID/GID `65532`, so Doorwarden's
`0600` key files remain readable by Traefik without loosening permissions.
One-time init (the paths are bind mounts you must own). Do it in this
order, before the first start: `./certs` is mounted at `/data/certs`, nested
inside `./data`, and if `./certs` does not exist Docker creates a root-owned
empty stub for the mount, which Doorwarden (65532) then cannot write.

```
mkdir -p data certs traefik-dynamic
chown -R 65532:65532 ./data ./traefik-dynamic ./certs
```

All three containers run with `read_only: true`, `cap_drop: [ALL]` and
`no-new-privileges`; only `traefik` publishes host ports (80/443), and
`doorwarden` publishes none. The image pre-creates `/data` and `/config`
owned by 65532 but declares no `VOLUME`.

**Binding :80/:443 as non-root.** Docker sets
`net.ipv4.ip_unprivileged_port_start=0` inside containers, so Traefik (65532)
can normally bind them. If Traefik logs `permission denied` binding `:80`,
check the value the container sees:
`docker run --rm alpine cat /proc/sys/net/ipv4/ip_unprivileged_port_start`
(or `sysctl net.ipv4.ip_unprivileged_port_start` on a host-network setup).
If it is not 0, uncomment `cap_add: [NET_BIND_SERVICE]` on the `traefik`
service (it is the only capability to add back).

## Certificates in Traefik

Doorwarden writes certificates to `./certs` (its `acme.certs_dir`, mounted at
`/data/certs`) and lists them in `doorwarden-tls.yml` with Traefik's view of
the same directory (`traefik.cert_path_prefix`, default `/certs`, mounted
read-only). Each issuance uses a new `certs/<id>/v<N>/` directory, so the
dynamic file changes and Traefik reloads. Traefik picks the certificate by
SNI; its single default certificate (clients without SNI or with an unknown
name) is the wildcard certificate of `settings.default_zone`, or of the only
zone; with several zones and no `default_zone` Traefik's self-signed default
is used. Settings under `traefik:`:

- `tls_min_version`: `VersionTLS12` (default) or `VersionTLS13`
  (`tls.options.default.minVersion`).
- `sni_strict` (default false): reject handshakes without SNI or with a name
  no certificate matches. Leave it off unless every client sends SNI.
- `serve_expired` (default false): keep serving an expired certificate when
  nothing valid covers its names (clients then see an expiry error for the
  right host instead of the default certificate).

Do not define `tls.options.default` or `tls.stores.default` in another file of
Traefik's dynamic directory: Traefik keeps only one of them.

## Discovery sources and approval

Each source has an `approval` mode: `auto` (publish what is discovered),
`approve` (each new service waits for an operator's approval) or `off`
(publish nothing from the source; its existing routes are removed after
the grace period). Defaults:

| source  | unset `approval` means | why |
|---------|------------------------|-----|
| truenas | `approve`              | TrueNAS apps have no opt-in of their own: every installed app would otherwise be published |
| docker  | `auto`                 | containers opt in with `doorwarden.*` labels |
| static  | `auto`                 | written by the operator in the config |

```yaml
sources:
  truenas:
    url: https://nas.example.test
    api_key: secret:truenas-api-key
    # approval: approve   # the default; set auto only if every app may be public
  docker:
    host: tcp://docker-socket-proxy:2375
```

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

The socket proxy runs as `user: 65534:${DOCKER_GID}`. That has only been
verified to start under Docker Desktop, not against a real Linux/TrueNAS
socket group id. After the first start confirm the proxy can reach the socket
and that Doorwarden's one allowed call works, from a container on the
`socket` network (the proxy only answers the `doorwarden` hostname, so run it
in that container's network namespace) or simply read the proxy logs for
`permission denied` on the socket:

```
docker logs <project>-docker-socket-proxy-1 2>&1 | grep -i "socket not available"
docker exec <project>-doorwarden-1 /doorwarden healthcheck   # control plane health
```

If the first command prints a permission error, fix `DOCKER_GID`
(`stat -c %g /var/run/docker.sock`) and redeploy. A direct end-to-end check
of the allowlist from the Docker host, using a throwaway client container on
the same network under the allowed name, is:

```
docker run --rm --network <project>_socket --name doorwarden curlimages/curl:8.10.1 \
    -s -o /dev/null -w '%{http_code}\n' 'http://docker-socket-proxy:2375/containers/json?all=1'
```

Expect `200` (and `403` for any other path). Stop the real `doorwarden`
container first, since two containers cannot share the name.

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
| `DOORWARDEN_TAG` | image tag (required; a release version such as `1.0.0`; `latest` only tracks stable releases) |
| `DOORWARDEN_MASTER_KEY` | encrypts secrets at rest (required, no default; generate with `openssl rand -base64 32`) |
| `DOCKER_GID` | group owning `/var/run/docker.sock` (`stat -c %g /var/run/docker.sock`) |
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

## Web UI and API access

Everything on the control plane's HTTP port requires authentication except
`/healthz`, `/api/v1/auth/status`, the first-run setup and the login
endpoints. That includes `/metrics` (scrape it with a session or through a
trusted-header proxy) and the event stream `/api/v1/events`.

- **First-run setup.** While no administrator exists, Doorwarden logs a
  one-time setup token at start-up (`WARN no administrator yet: first-run
  setup token ...`; read it with `docker logs doorwarden`). Setup
  (`POST /api/v1/auth/setup` with user name, password of at least 12
  characters and the token) creates the only administrator; it is refused
  once one exists, and two concurrent attempts cannot both succeed. The token
  changes on every restart until setup is done. A token was chosen over a
  localhost-only setup because the UI is normally reached through Traefik.
- **Sessions.** Passwords are hashed with argon2id. A session cookie
  (`__Host-doorwarden_session`: HttpOnly, Secure, SameSite=Strict) expires
  after `web.session_idle` (8h) without use and `web.session_max` (7d) in
  all. Logout and a password change end sessions server side. Login is
  throttled per client address and per user name: after 5 failures the key
  is locked for 30s, doubling up to 15 minutes. Set `web.cookie_insecure:
  true` only when the UI is served over plain HTTP on a trusted LAN.
- **CSRF.** Every state-changing request needs the `X-Doorwarden-CSRF`
  header (the token returned by login, setup and `GET /api/v1/auth/me`), a
  JSON body, and an `Origin` that matches the request host or one of
  `web.allowed_origins` (`scheme://host[:port]`).
- **Trusted header (optional).** With `web.trusted_header.proxies` set to
  CIDRs, a request whose TCP peer is in those ranges is authenticated by
  `web.trusted_header.user_header` (default `Remote-User`) with
  `web.trusted_header.role` (`viewer` by default, or `admin`). The peer
  address is the connection's, never `X-Forwarded-For`; from any other peer
  the header is stripped. An empty list turns it off. Only list the proxy
  that sets the header (e.g. Traefik with forward auth) and make sure it
  overwrites any client-sent copy.

### Editing the config from the UI

`GET /api/v1/config` returns the config file with every secret replaced by
`<masked>` (`secret:` references and plain `${VAR}` placeholders are shown,
since they are not secrets). `PUT /api/v1/config` takes the edited document;
a `<masked>` value keeps the current one. The document is validated like at
start-up and written atomically (mode 0600), so the config file must be
writable by the container (it cannot be a read-only mount for this). Changes
take effect at the next restart: the running reconciler, DNS providers and
ACME manager are not rebuilt mid-cycle or mid-order.

### Per-service overrides

Publish/unpublish, rename, port and skip-verify set in the UI are stored in
the database and applied every cycle before the approval gate. In approve
mode a rename or skip-verify change requires approving the service again.
Unpublishing removes the service like a disappearance: its route and DNS
records are scheduled for removal after `settings.grace_period` (24h by
default); publishing again within the grace cancels the removal.
