# Deploying Doorwarden on TrueNAS

TrueNAS app names, menu paths and ports vary by version; the values below are
examples. Use TrueNAS "Custom App" YAML (docker compose) installs.

## Layout

Create a dataset, e.g. `/mnt/<pool>/apps/doorwarden/`, containing:

```
config/doorwarden.yaml     Doorwarden config (read-only mount)
data/                      SQLite state (owned by uid 65532)
certs/                     certificates: /data/certs in Doorwarden (rw), /certs in Traefik (ro)
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

**TrueNAS's own web interface uses 80/443 by default.** Before Traefik can
publish 80/443 on the TrueNAS host, move the TrueNAS web interface to other
ports (in the system's general/GUI settings; the menu path depends on the
TrueNAS version), and reach it at the new port from then on. During the
alternate-port trial ([migration.md](migration.md)) this is not needed yet.

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
- `file_mode` (default `0600`; `0640` also allowed): permissions of the
  generated dynamic files. They can contain middleware secrets (basic-auth
  hashes, forward-auth settings). With `0600` Traefik must run as Doorwarden's
  UID (65532 in the compose file); `0640` only if Traefik reads them through a
  shared group. Files with a wrong mode are rewritten on the next write.
  `traefik.dynamic_dir` must already exist; Doorwarden does not create it.

Do not define `tls.options.default` or `tls.stores.default` in another file of
Traefik's dynamic directory: Traefik keeps only one of them.

## HTTP-01 challenge route

Zones with `certificate.challenge: http-01` are validated by the CA over
plain HTTP on port 80 at `http://<host>/.well-known/acme-challenge/<token>`.
Doorwarden's challenge server listens on `acme.http01_listen` inside its
container; Traefik must forward those requests to it. When `http01_listen` is
set and at least one zone uses `http-01`, Doorwarden writes
`doorwarden-acme-http01.yml` into the dynamic directory with one router:

```yaml
http:
  routers:
    doorwarden-acme-http01:
      entryPoints: [web]                 # traefik.http_entry_point
      rule: (Host(`example.test`) || Host(`www.example.test`)) && PathPrefix(`/.well-known/acme-challenge/`)
      priority: 1073741824
      service: doorwarden-acme-http01
  services:
    doorwarden-acme-http01:
      loadBalancer:
        servers: [{url: "http://doorwarden:8089"}]   # acme.http01_backend
        passHostHeader: true
```

- It matches only the exact host names of http-01 zones that are routes
  (the names Doorwarden orders and renews, the zone apex included), never a
  wildcard or catch-all, and only the challenge path. Before a cycle orders a
  name that is not in the file yet, the file is rewritten with it and
  Doorwarden waits a few seconds for Traefik to load it.
- It has no TLS and no middleware, and lives only on the plain-HTTP entry
  point, so it never shadows the HTTPS routers.
- The Host header is passed through: the challenge server answers only for
  the name being validated.
- When no zone uses `http-01` (or no host needs a certificate) the file is
  removed. With HTTP-01 off nothing changes.

**The `web` redirection.** The shipped `traefik/traefik.yml` redirects all of
`:80` to HTTPS at the entry point. Traefik implements this as a router with
priority MaxInt-1 attached to every request on the entry point, above the
highest priority any provider's router may use, so it would answer the CA's
request with a redirect to HTTPS (where no certificate exists yet). The
shipped file therefore sets the redirection's priority to 1:

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          permanent: true
          priority: 1
```

Every other request on `:80` is still redirected. If you keep an older copy
of `traefik.yml`, add `priority: 1` and restart Traefik (static
configuration is not reloaded). This was checked by hand with Traefik v3.5:
with `priority: 1` the challenge path of a listed host reaches Doorwarden
and every other request is redirected; without it the challenge request is
redirected too. (Doorwarden's automated tests check the rendered file, not a
running Traefik.) If Traefik runs
outside this compose project, set `acme.http01_backend` to the URL Traefik
uses to reach Doorwarden's challenge port, and publish that port only to
Traefik.

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
    api_key: ${TRUENAS_API_KEY}
    # approval: approve   # the default; set auto only if every app may be public
  docker:
    host: tcp://docker-socket-proxy:2375
```

`${TRUENAS_API_KEY}` reads the key from the container's environment. To keep
it in Doorwarden's database instead (encrypted with `DOORWARDEN_MASTER_KEY`),
store it once and reference it as `secret:<name>`:

```
printf %s "$TOKEN" | docker exec -i <project>-doorwarden-1 /doorwarden admin secret set truenas-api-key
# or, on a terminal, prompt twice without echo:
#   docker exec -it <project>-doorwarden-1 /doorwarden admin secret set truenas-api-key
```

The value never goes on the command line. `docker exec` inherits
`DOORWARDEN_MASTER_KEY` from the container's `environment:`; do not add
`-e DOORWARDEN_MASTER_KEY`, which would replace it with your shell's value
(possibly empty). Restart Doorwarden afterwards.

```yaml
sources:
  truenas:
    url: https://nas.example.test
    api_key: secret:truenas-api-key
```

See [configuration.md](configuration.md#secrets-and-the-master-key) for the
`admin secret` commands.

## Deploy

1. Copy `deploy/compose.truenas.yml` and `deploy/traefik/traefik.yml` onto the
   dataset (adjust the relative volume paths to your dataset paths).
2. Copy `deploy/.env.example` to `.env` (or enter them as app environment
   variables) and fill in the values. Never commit real values.
3. Paste the compose YAML into a new Custom App and deploy.

A TrueNAS Custom App has no `.env` file next to the YAML. The compose file
uses `${DOORWARDEN_TAG:?...}` and `${DOORWARDEN_MASTER_KEY:?...}`, which make
the deployment fail when the variable is unset: replace them in the pasted
YAML with literal values (for example `image: ghcr.io/ajthom90/doorwarden:1.0.0`),
and set the same for `${DOCKER_GID:-999}` and the port variables if the
defaults do not fit. Treat the pasted YAML as a secret once it holds the master
key or API keys.

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
in that container's network namespace) or simply read the proxy logs: a
wrong group shows up at start-up as `msg="socket not available"
error="dial unix /var/run/docker.sock: connect: permission denied"`:

```
docker logs <project>-docker-socket-proxy-1 2>&1 | grep -i "socket not available"
docker exec <project>-doorwarden-1 /doorwarden healthcheck   # control plane health
```

The image is distroless: there is no shell in it, and the binary is
`/doorwarden`, not on `PATH`. Always call it with the absolute path through
`docker exec <container> /doorwarden ...`. With the provided compose file
(project `name: doorwarden`, no `container_name`) the containers are
`<project>-doorwarden-1`, `<project>-traefik-1` and
`<project>-docker-socket-proxy-1`; `docker ps` shows the real names.

The socket proxy has no healthcheck in the compose file (its image has
none); a broken proxy shows up as the docker source being down
(`doorwarden_source_up{source="docker"} 0`, `degraded: true` on `/healthz`,
and an error on the Services page).

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
  and changes nothing. Dry run still lists sources and providers, plans every
  cycle and logs the plan; actions that would change something from the UI
  (Renew now, Switch to production, Adopt a DNS conflict) are refused with
  `409 Conflict` while it is on. Turn dry run off for them.
- **Stop timeout.** Shutdown can take up to about 40 seconds (HTTP, then
  certificate orders in progress); the compose file sets
  `stop_grace_period: 45s`. Keep it when you adapt the file. Stopping deletes
  nothing ([operations.md](operations.md#stopping)).
- **Several zones.** With more than one zone and Docker or TrueNAS discovery,
  set `settings.default_zone`. Without it Doorwarden still starts (and logs a
  warning), but every TrueNAS app and every container without
  `doorwarden.zone` is an error (`no zone`).
- **Reaching the UI.** Doorwarden publishes no host port, and nothing routes
  to its port 8080 until you add a route. Add a static entry for the UI to the
  config (static entries need no approval, so it is published in the first
  cycle that is not dry):

  ```yaml
  static:
    - name: doorwarden          # https://doorwarden.example.test
      host: doorwarden          # compose service name, reachable from Traefik
      port: 8080
  ```

  In dry run Doorwarden writes no Traefik file, so this route only appears once
  dry run is off. To use the UI before that (first-run setup, reviewing the
  dry-run plan, approving TrueNAS apps), publish the port on the host's
  loopback only, for a trial:

  ```yaml
  services:
    doorwarden:
      ports:
        - "127.0.0.1:8090:8080"   # trial only; remove once the route works
  ```

  and open it through an SSH tunnel: `ssh -L 8090:127.0.0.1:8090 <truenas-host>`,
  then `http://localhost:8090/`. Browsers keep the `Secure` session cookie on
  `http://localhost`; if yours does not, set `web.cookie_insecure: true` for
  the trial only. Never publish port 8080 on all interfaces.
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
  setup token ...`; read it with `docker logs <project>-doorwarden-1`). Setup
  (`POST /api/v1/auth/setup` with user name, password of at least 12
  characters and the token) creates the only administrator; it is refused
  once one exists, and two concurrent attempts cannot both succeed. The token
  changes on every restart until setup is done. A token was chosen over a
  localhost-only setup because the UI is normally reached through Traefik.
- **Sessions.** Passwords are hashed with argon2id. A session cookie
  (`__Host-doorwarden_session`: HttpOnly, Secure, SameSite=Strict) expires
  after `web.session_idle` (8h) without use and `web.session_max` (7d) in
  all. Logout and a password change end sessions server side. Login is
  throttled per (user name, client address): after 5 failures that pair
  waits 30s, doubling up to 15 minutes; one address failing for 20 user
  names is backed off the same way (IPv6 addresses count per /64).
  Every attempt counts against one budget per user name of about 30 a
  minute (at most ~1830 guesses in any hour, however many addresses are
  used). Addresses with recent failures cannot use the last 5 of it,
  which stay reserved for addresses without failures: at worst such a
  login waits up to 5 seconds or is asked to retry a few seconds later, so
  failures from elsewhere can never lock the administrator out. A login
  the client abandons (disconnect, timeout) counts as a failure. Setup is
  limited per address only (the setup token is 192-bit random).
  Set `web.cookie_insecure: true` only when the UI is served over plain
  HTTP on a trusted LAN.
- **Behind Traefik: set `web.trusted_proxies`.** Login throttling, audit and
  log lines use the client address. Without `web.trusted_proxies` that is
  the TCP peer, so behind Traefik every client looks like Traefik and one
  client's failed logins slow down everyone's. Set it to the proxy's network
  (for the compose file, the subnet of the `default` network Traefik shares
  with Doorwarden: `docker network inspect <project>_default --format
  '{{(index .IPAM.Config 0).Subnet}}'`, then for example
  `trusted_proxies: ["198.51.100.0/24"]` with your subnet). When the peer is in that list
  the client is the rightmost `X-Forwarded-For` address that is not itself a
  trusted proxy; anything further left was written by the client and is
  ignored. Doorwarden warns in its log when it runs in a container with the
  setting empty, when `X-Forwarded-For` arrives while it is empty, and when
  the first requests all come from one address. This setting only affects
  the client address; it never authenticates anyone (that is
  `web.trusted_header`).
- **Locked out / lost password.** With shell access to the host:
  `docker exec <project>-doorwarden-1 /doorwarden admin unlock` ends every
  session and clears all login limits; `docker exec <project>-doorwarden-1
  /doorwarden admin reset-password` also sets a new random password, printed once on the
  terminal (never logged), and creates the administrator (`-user`, default
  `admin`) if none exists. Both work on the database (`-db`, default
  `$DOORWARDEN_DB`) while the server runs. They refuse to run as a user
  other than the database file's owner (e.g. `docker exec -u 0`), since
  SQLite's `-wal`/`-shm` files would then belong to that user and lock the
  server out; `-allow-owner-mismatch` overrides.
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
a `<masked>` value keeps the current one, but only for the same entry
(list entries are matched by `name`/`id`/`url`/`host`-style identity fields,
not position) and only while its destination (`url`, `host`, `server`,
`endpoint`, `type`, `port`, ...) is unchanged; otherwise the PUT is refused
and the secret must be re-entered. Comments are stripped from the returned
document. `${VAR}` references are accepted only in secret fields (an
unchanged existing one elsewhere is kept), and only like a masked secret:
a new or changed reference only in an entry that already exists in the
file and whose destination is unchanged, and an existing reference is
refused when its entry's destination changes. `DOORWARDEN_*` variables
(such as `DOORWARDEN_MASTER_KEY`) can never be referenced from the editor.
To add a new entry that takes its secret from the environment, or to move
one to another destination, edit the config file itself. YAML anchors,
aliases and merge keys (`<<`) are refused everywhere, in the editor and in a
config file written by hand (the error names the line; see
[configuration.md](configuration.md) for the other limits). The document is validated like at
start-up and written atomically (mode 0600), so the config file must be
writable by the container (it cannot be a read-only mount for this). Changes
take effect at the next restart: the running reconciler, DNS providers and
ACME manager are not rebuilt mid-cycle or mid-order.

### Per-service overrides

Publish/unpublish, rename, port and skip-verify set in the UI are stored in
the database and applied every cycle before the approval gate. In approve
mode a UI override carries the service's approval over to the changed
content, while a change from the source (labels, the TrueNAS app) to an
approved service quarantines it until it is approved again
([labels.md](labels.md#approval)).
Unpublishing removes the service like a disappearance: its route and DNS
records are scheduled for removal after `settings.grace_period` (24h by
default); publishing again within the grace cancels the removal.
