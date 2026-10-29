# Configuration reference

Doorwarden reads one YAML file at start-up: `-config` flag, else
`$DOORWARDEN_CONFIG`, else `/config/doorwarden.yaml`. The file is read once;
changes (including those saved from the UI's config editor) take effect at the
next restart.

The decoder is strict: an unknown key anywhere is an error. Every problem
found by validation is reported at once at start-up, and Doorwarden does not
start until the file is valid. Errors name the key path and line (for example
`static[0].port (line 4): invalid value: a string where an integer is
expected`) and never repeat the value: values from the environment, and quoted
values derived from them, appear as `[redacted]` or `(value elided)`. At most
20 problems are described (then `and N more problems`), and the message is
cut at 8 KiB.

The file must be plain YAML. The same check applies at start-up and in the
UI's config editor:

- YAML anchors (`&name`), aliases (`*name`) and merge keys (`<<`) are refused;
  write each value out in full.
- Mapping keys must be plain scalars (no list or mapping used as a key).
- A mapping may have at most 4096 keys, and the document may be nested at
  most 64 levels deep.

These limits are far above what a real config needs.

All names in the examples are placeholders (`example.test`, `192.0.2.x`).

- [Command-line flags and environment](#command-line-flags-and-environment)
- [Environment variable substitution](#environment-variable-substitution)
- [Secrets and the master key](#secrets-and-the-master-key)
- [A complete example](#a-complete-example)
- [zones](#zones)
- [providers](#providers)
- [issuers](#issuers)
- [sources](#sources)
- [static](#static)
- [settings](#settings)
- [middlewares](#middlewares)
- [traefik](#traefik)
- [acme](#acme)
- [notifications](#notifications)
- [web](#web)

## Command-line flags and environment

`doorwarden` with no subcommand runs the control plane.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-config` | `DOORWARDEN_CONFIG` | `/config/doorwarden.yaml` | config file |
| `-db` | `DOORWARDEN_DB` | `/data/doorwarden.db` | SQLite state database (its directory is created `0700`) |
| `-listen` | `DOORWARDEN_LISTEN` | `:8080` | web UI, API, `/healthz` and `/metrics`; an empty value disables the HTTP server |

Other environment variables:

| Variable | Meaning |
|---|---|
| `DOORWARDEN_MASTER_KEY` | encrypts ACME account keys (and `secret:` values) at rest; see [below](#secrets-and-the-master-key) |
| `DOORWARDEN_HEALTH_URL` | target of `doorwarden healthcheck` (default `http://127.0.0.1:8080/healthz`) |

Subcommands: `doorwarden --version`, `doorwarden healthcheck [-url URL]
[-timeout 3s]`, `doorwarden admin reset-password|unlock` (see
[security.md](security.md#recovering-access)), `doorwarden admin secret
set|list|delete` ([below](#secrets-and-the-master-key)),
`doorwarden import-npm` and `doorwarden certs import-npm` (see
[migration.md](migration.md)). In the container call the binary as
`/doorwarden` (`docker exec <container> /doorwarden ...`); the image has no
shell.

## Environment variable substitution

String values may contain `${VAR}` or `${VAR:-default}`:

- `${VAR}` with `VAR` unset is an error that names every missing variable.
- `${VAR:-default}` uses `default` when `VAR` is unset **or empty**.
- Substitution happens only inside string values, never in keys or comments,
  and the result is never parsed as YAML again (a value cannot inject
  structure).
- Under `providers`, `middlewares` and `notifications` the result is always a
  string, exactly as the variable holds it (`0123`, `true`, `1e3` stay
  strings). Write numbers and booleans in those sections literally (DNS
  provider boolean options also accept the strings `"true"` and `"false"`).
- Elsewhere, an unquoted value that is exactly one placeholder takes the type
  of its text when that is a boolean or a number (`dry_run: ${DRY_RUN}` with
  `DRY_RUN=true` is a boolean). Quoted values, or text mixed with a
  placeholder, stay strings.
- In YAML flow style (`{...}`, `[...]`) quote the placeholder:
  `records: {provider: "${PROVIDER}"}`. Unquoted, `{` and `}` in `${...}`
  would be read as YAML syntax.

## Secrets and the master key

`DOORWARDEN_MASTER_KEY` (at least 16 bytes; generate one with
`openssl rand -base64 32`) derives the AES-256-GCM key that encrypts ACME
account keys in the database. It is **required** when any zone has a
`certificate.issuer`, or when the config uses a `secret:` value. Keep a copy
outside the server: without it the stored ACME accounts cannot be read (see
[operations.md](operations.md#backups)).

Put credentials in the environment and reference them with `${VAR}`; keep the
real values in an `.env` file or the app's environment settings, never in a
committed file.

Alternatively, store a credential in Doorwarden's database, sealed with the
master key, and reference it as `secret:<name>`. Names are 1-128 characters of `[A-Za-z0-9._-]`. `secret:` references
work in DNS provider settings, ACME challenge provider settings and
`sources.truenas.api_key`.

```
printf %s "$TOKEN" | docker exec -i <container> /doorwarden admin secret set <name>
docker exec -it <container> /doorwarden admin secret set <name>   # on a terminal: prompts twice, no echo
docker exec <container> /doorwarden admin secret list             # names only, never values
docker exec <container> /doorwarden admin secret delete <name>
```

- The value comes from standard input (one trailing newline is dropped) or
  the prompt, never from the command line or the environment. Empty values
  and values over 64 KiB are refused. `set` replaces an existing secret only
  with `-force`.
- All three take `-db` (default `$DOORWARDEN_DB`, then `/data/doorwarden.db`)
  and, like `admin unlock`, refuse to run as a user other than the database
  file's owner unless `-allow-owner-mismatch` is given (`docker exec` runs as
  the container's user, which is the owner).
- The master key comes from `DOORWARDEN_MASTER_KEY`, which `docker exec`
  inherits from the container's `environment:`. Do **not** add
  `-e DOORWARDEN_MASTER_KEY`: without a value it copies your shell's variable,
  possibly empty, over the container's key. `set` refuses a master key that
  cannot decrypt the secrets already stored.
- Restart Doorwarden afterwards; the config references the secret as
  `secret:<name>`.

TLS private keys of issued certificates are files on disk (mode `0600`), not
encrypted with the master key, because Traefik must read them.

## A complete example

```yaml
zones:
  - name: example.test
    target_ip: 192.0.2.10          # where Traefik listens
    records:
      provider: cloudflare
      mode: wildcard                # one *.example.test A record
    certificate:
      issuer: letsencrypt
      strategy: wildcard
      dns_provider: cloudflare      # DNS-01 through the same Cloudflare entry

providers:
  cloudflare:
    type: cloudflare
    api_token: ${DNS_API_TOKEN}

issuers:
  letsencrypt:
    directory: staging              # the default; switch to production later
    email: admin@example.test

sources:
  docker:
    host: tcp://docker-socket-proxy:2375
  truenas:
    url: https://nas.example.test
    api_key: ${TRUENAS_API_KEY}
    # approval: approve             # the default for TrueNAS

static:
  - name: doorwarden                # the Doorwarden UI itself
    host: doorwarden                # compose service name, reachable from Traefik
    port: 8080
  - name: printer
    upstream: https://192.0.2.30
    skip_verify: true

settings:
  dry_run: true                     # report only; set false when the plan looks right

web:
  trusted_proxies: ["198.51.100.0/24"]   # the network Traefik reaches Doorwarden from
```

## zones

A list. Every service is published as `<name>.<zone>` in exactly one zone
(a static entry with `apex: true` as the zone name itself, see
[static](#static)).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | DNS zone, e.g. `example.test` |
| `target_ip` | IP | required | address DNS records point at (where Traefik listens). It is also the backend host for Docker and TrueNAS services (their published ports are on that host) |
| `records.mode` | `wildcard` \| `per-host` \| `off` | unset (same as `off`) | `wildcard`: one `*.<zone>` A record (plus an A record at the zone name for an `apex` entry, which the wildcard does not cover); `per-host`: one A record per published host; `off`: Doorwarden manages no records in this zone |
| `records.provider` | provider name | required unless mode is `off` | entry under `providers`. `wildcard` needs a provider that supports wildcard A records |
| `certificate.issuer` | issuer name | unset | entry under `issuers`. Unset: Doorwarden issues no certificates for the zone |
| `certificate.strategy` | `wildcard` \| `per-host` \| `san` | `wildcard` | `wildcard`: `<zone>` + `*.<zone>`; `per-host`: one certificate per host; `san`: one certificate listing every host |
| `certificate.challenge` | `dns-01` \| `http-01` | `dns-01` | `wildcard` requires `dns-01`; `http-01` requires `acme.http01_listen` |
| `certificate.dns_provider` | provider name | required for `dns-01` | entry under `providers` whose `type` is an ACME DNS provider (a lego provider code, see [providers.md](providers.md#acme-dns-01-challenge-providers)). `unifi`, `pihole` and `adguard` cannot solve challenges |

A service names its zone with the `doorwarden.zone` label or the static
`zone` key (TrueNAS apps cannot name one). A service without one uses
`settings.default_zone`, or the only zone when exactly one is configured;
otherwise it is an error (`no zone: set doorwarden.zone or
settings.default_zone`), reported and not published. Set `default_zone`
whenever you configure several zones and use Docker or TrueNAS discovery.

## providers

A map of name to provider settings. `type` selects the implementation; every
other key is a setting of that type.

```yaml
providers:
  home-dns:
    type: technitium
    url: https://dns.example.test
    token: ${TECHNITIUM_TOKEN}
```

DNS record providers (`records.provider`) accept only their own keys (an
unknown key is an error when the provider is built). ACME challenge providers
(`certificate.dns_provider`) map keys to lego's environment variable names and
ignore unknown keys. Both are described in [providers.md](providers.md).

## issuers

A map of name to ACME issuer.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `directory` | `staging` \| `production` \| URL | `staging` | Let's Encrypt staging (untrusted test certificates), Let's Encrypt production, or another ACME directory URL (`https://`; plain `http://` only to a loopback address). `letsencrypt` alone is refused as ambiguous |
| `email` | string | required for Let's Encrypt | account contact address |
| `eab_kid`, `eab_hmac` | string | unset | external account binding for CAs that require it; set both or neither |

New installations get staging certificates until you switch; see
[cert-troubleshooting.md](cert-troubleshooting.md#from-staging-to-production).

## sources

Discovery sources. Static services are always on.

```yaml
sources:
  docker:
    host: unix:///var/run/docker.sock   # or tcp://docker-socket-proxy:2375
    approval: auto
  truenas:
    url: https://nas.example.test
    api_key: ${TRUENAS_API_KEY}
    approval: approve
```

| Key | Type | Default | Meaning |
|---|---|---|---|
| `docker.host` | `unix://path` \| `tcp://host:port` | required | Docker Engine API. Doorwarden only calls `GET /containers/json?all=1`; put an allowlisting socket proxy in front (see [deploy.md](deploy.md#docker-api-access)) |
| `docker.approval` | `auto` \| `approve` \| `off` | `auto` | containers opt in with labels ([labels.md](labels.md)) |
| `truenas.url` | `https://`, `wss://`, `http://` or `ws://` URL | required | TrueNAS SCALE host; Doorwarden uses its JSON-RPC websocket API (`/api/current`, method `app.query` only) |
| `truenas.api_key` | string | required | TrueNAS API key (use `${VAR}`) |
| `truenas.approval` | `auto` \| `approve` \| `off` | `approve` | TrueNAS apps have no opt-in of their own, so every new app waits for approval unless you choose `auto` |

Approval modes: `auto` publishes what is discovered; `approve` holds each new
service until an administrator approves it in the UI (or
`POST /api/v1/services/{key}/approve`); `off` publishes nothing from the
source and removes its existing routes after the grace period.

The backend host of a Docker or TrueNAS service is the `target_ip` of its
zone: the zone named by its `doorwarden.zone` label, else the default zone
(`settings.default_zone`, or the only zone). Details in
[labels.md](labels.md). The backend host is always that `target_ip`: there is
no option to reach Docker containers on a Docker network instead.

Switching a source from `auto` to `approve` does not take down what is already
served: see [labels.md](labels.md#approval) (services served with unchanged
content are approved automatically, "grandfathered on mode switch").

## static

A list of services you define by hand. Static entries always use approval
`auto`. When services from different sources claim the same host name, the
higher-ranked source wins: static, then TrueNAS, then Docker (see
[labels.md](labels.md#host-name-conflicts)). Add an entry for Doorwarden's own
UI (`host: doorwarden`, `port: 8080`, as in the example above): nothing else
routes to it ([deploy.md](deploy.md#first-run)).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | required | service name; the host name is `<slug(name)>.<zone>` (the zone name with `apex: true`) |
| `id` | `[A-Za-z0-9._-]+` | slug of `name` | stable key (`static:<id>`); set it to rename without losing state |
| `host` | host name or IP | one of `host`/`upstream` | backend host (no scheme, path or port) |
| `upstream` | `scheme://host[:port]` | one of `host`/`upstream` | backend as a URL; no path, query, user info or fragment. Overrides `host`, and its scheme and port must agree with `scheme`/`port` when those are set |
| `port` | 1-65535 | 80, or 443 for https | backend port |
| `scheme` | `http` \| `https` | `http` (`https` with `skip_verify`) | backend scheme |
| `zone` | zone name | default zone | |
| `skip_verify` | bool | false | do not verify the backend's TLS certificate (requires https) |
| `websockets` | bool | false | informational; Traefik proxies websockets without extra configuration |
| `middlewares` | list of references | none | see [labels.md](labels.md#middlewares) |
| `rename` | DNS label | unset | publish under this name instead of `name` |
| `apex` | bool | false | publish at the zone name itself (`example.test`) instead of `<slug(name)>.<zone>`; see below |
| `skip` | bool | false | do not publish this entry |

### Apex entries

`apex: true` publishes the entry at the zone apex: the host name is the
zone's name (`example.test`), not `<slug(name)>.<zone>`. `name` is still
required (it is the entry's id and display name). Limits:

- static entries only (there is no Docker label or TrueNAS equivalent);
- at most one apex entry per zone, and `apex` cannot be combined with
  `rename` (the UI refuses to rename an apex service as well);
- the zone name must be a valid host name with at least two labels
  (lowercase letters, digits and hyphens; an IDN zone in its `xn--` form);
- `www` is an ordinary entry (`name: www`);
- a zone nested in another (`home.example.test` next to `example.test`) has
  its own apex: an apex entry in the nested zone publishes
  `home.example.test`, never the parent's apex.

DNS: with `records.mode: per-host` the A record is created at the zone name.
Records Doorwarden does not own at the apex (NS, SOA, MX, TXT and others)
are never changed; a foreign A or CNAME record at the apex is reported as a
conflict, not overwritten. With `records.mode: wildcard` the `*.<zone>`
record does not cover the zone name, so the apex entry gets its own A
record. Certificates: the `wildcard` strategy already covers the zone name;
`per-host` and `san` add it like any other host; `http-01` can issue it.

#### Example: a domain whose DNS is hosted elsewhere

The zone's DNS stays at its current host (records are added there by hand,
pointing the apex and `www` at your public address); Doorwarden routes both
and issues their certificates by HTTP-01:

```yaml
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {mode: "off"}          # DNS is managed elsewhere
    certificate:
      issuer: letsencrypt
      strategy: per-host
      challenge: http-01
issuers:
  letsencrypt: {directory: production, email: admin@example.test}
acme:
  http01_listen: ":8089"            # Traefik reaches it as http://doorwarden:8089
static:
  - name: site
    apex: true                      # https://example.test
    zone: example.test
    host: 192.0.2.20
    port: 8080
  - name: www                       # https://www.example.test
    zone: example.test
    host: 192.0.2.20
    port: 8080
```

Port 80 must reach Traefik from the internet, and Traefik's `web` entry
point redirection needs `priority: 1` (see
[deploy.md](deploy.md#http-01-challenge-route)). Doorwarden then renders the
challenge route for `example.test` and `www.example.test`.

## settings

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dry_run` | bool | `false` | plan and report only: no DNS write, no certificate order, no Traefik file write. Recommended for the first start. The UI/API also has a persisted dry-run toggle; the run is dry when either is on |
| `grace_period` | duration | `24h` | how long a service that disappeared from its source, or was unpublished, keeps its route and DNS records before they are removed (a stopped container or app is not removed) |
| `poll_interval` | duration | `30s` | how often sources are listed and the plan is reconciled |
| `renew_before` | duration | `720h` (30 days) | renew a certificate this long before it expires |
| `default_zone` | zone name | the only zone | zone for services that name none. Optional; with two or more zones and no `default_zone`, Docker containers without `doorwarden.zone` and every TrueNAS app are per-service errors (`no zone: ...`), and Doorwarden logs a warning at start-up |

Durations use Go syntax (`90s`, `15m`, `24h`).

## middlewares

A map of name to one Traefik middleware definition, passed to Traefik as-is
(see Traefik's middleware documentation for the options of each type):

```yaml
middlewares:
  lan-only:
    ipAllowList:
      sourceRange: ["192.0.2.0/24"]
  auth:
    basicAuth:
      users: ["admin:$apr1$..."]
  secured:
    chain:
      middlewares: [lan-only, auth]
```

An `ipAllowList` only works if Traefik sees real client addresses. Behind
Docker's userland `docker-proxy` (TrueNAS SCALE publishes ports that way) it
sees only the bridge gateway and rejects every client; see
[deploy.md](deploy.md#web-ui-and-authentication).

Rules: a name matches `[A-Za-z0-9_.-]+`; each definition has exactly one type
key; no string may contain `{{` or `}}` (Traefik templating); a `chain` must
list at least one member, every member must be valid, and chains must not
form a cycle. Services reference middlewares by name (see
[labels.md](labels.md#middlewares)). Middlewares fail closed: a service that
references a missing or invalid middleware is reported as invalid and gets no
new route; a route it already had keeps the middlewares it was last written
with, so a typo never removes authentication that was in place.

## traefik

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dynamic_dir` | absolute path | `/etc/traefik/dynamic` | directory Doorwarden writes Traefik's file-provider files into; it must exist at start-up |
| `entry_point` | `[A-Za-z0-9_-]+` | `websecure` | Traefik entry point of every router |
| `http_entry_point` | `[A-Za-z0-9_-]+` | `web` | Traefik's plain-HTTP entry point, used only by the HTTP-01 challenge router (see `acme.http01_listen`); must differ from `entry_point` |
| `cert_path_prefix` | absolute path | `/certs` | where Traefik sees `acme.certs_dir` (the same directory mounted into the Traefik container) |
| `external_middlewares` | list of `name@provider` | none | middlewares defined outside Doorwarden (e.g. in another Traefik provider) that services may reference |
| `tls_min_version` | `VersionTLS12` \| `VersionTLS13` | `VersionTLS12` | rendered as `tls.options.default.minVersion` |
| `sni_strict` | bool | false | reject TLS handshakes without SNI or with an unknown name |
| `serve_expired` | bool | false | keep serving an expired certificate when nothing valid covers its names |
| `file_mode` | `0600` \| `0640` | `0600` | permissions of the generated dynamic files, which can contain middleware secrets. With `0600` Traefik must run as the same UID as Doorwarden; `0640` lets it read them through a shared group. Files with another mode are rewritten with the right one on the next write |

Do not define `tls.options.default` or `tls.stores.default` in another file of
the dynamic directory; see [deploy.md](deploy.md#certificates-in-traefik).

## acme

| Key | Type | Default | Meaning |
|---|---|---|---|
| `certs_dir` | absolute path | `/data/certs` | certificate files: `<certs_dir>/<id>/v<N>/fullchain.pem` and `privkey.pem` |
| `http01_listen` | `host:port` | unset (HTTP-01 off) | address of the HTTP-01 challenge server. When a zone uses `certificate.challenge: http-01`, Doorwarden renders a Traefik router on `traefik.http_entry_point` for `/.well-known/acme-challenge/` of exactly the hosts that need an http-01 certificate, forwarding to `http01_backend` (see [deploy.md](deploy.md#http-01-challenge-route)) |
| `http01_backend` | `http(s)://host[:port]` | `http://doorwarden:<port of http01_listen>` | URL at which Traefik reaches the challenge server; no user info, path, query or fragment. Requires `http01_listen` |
| `dns_propagation_timeout` | duration | the provider's own | how long to wait for a DNS-01 TXT record to propagate |
| `resolvers` | list of `host[:port]` | system resolvers | resolvers used for the propagation check |
| `issue_timeout` | duration | `5m` | upper bound of one issuance as seen by the reconcile loop |

## notifications

Alerts can be sent to webhooks, ntfy and e-mail. Event kinds:
`cert.failure`, `cert.renewal_failed`, `cert.expiring`,
`cert.adoption_blocked`, `dns.conflict`, `dns.alert`, `source.unavailable`,
`reconcile.error`, `service.invalid` (a published service whose labels became
invalid; it keeps its last route) and `service.quarantined` (an approved
service whose content changed; see [labels.md](labels.md#approval)). A
quarantined service raises `service.quarantined` again every cycle; the
`dedupe_window` keeps that to one notification per service and backend per
window, and a notification dropped because the queue was full is retried at
the next cycle.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `dedupe_window` | duration | `1h` | identical alerts within this window are sent once; negative disables |
| `timeout` | duration | `10s` | per delivery |
| `queue_size` | int | 64 | pending deliveries |
| `webhooks`, `ntfy`, `smtp` | lists | none | senders |

Every sender has `name` (default `webhook-N`, `ntfy-N`, `smtp-N`; unique),
`min_severity` (`info` default, `warning`, `critical`) and `rate_per_minute`
(default 10).

| Sender | Keys |
|---|---|
| `webhooks` | `url` (required), `secret`, `headers` (map), `allow_insecure_http` |
| `ntfy` | `server` (URL, required), `topic` (required, `[A-Za-z0-9_-]{1,64}`), `token` **or** `username` + `password`, `allow_insecure_http` |
| `smtp` | `host` (required), `port` (587 for `starttls`, 465 for `tls`, 25 for `none`), `tls` (`starttls` default, `tls`, `none`), `username` + `password`, `from` (required), `to` (at least one), `insecure_skip_verify` |

Plain `http://` webhook and ntfy URLs are accepted only for private or
loopback hosts unless `allow_insecure_http: true`. SMTP refuses to send
credentials without TLS to a non-loopback host.

```yaml
notifications:
  ntfy:
    - server: https://ntfy.example.test
      topic: doorwarden-alerts
      token: ${NTFY_TOKEN}
      min_severity: warning
```

## web

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cookie_insecure` | bool | false | drop the `Secure` cookie attribute; only for plain HTTP on a trusted LAN |
| `session_idle` | duration | `8h` | session expires after this long without use |
| `session_max` | duration | `168h` | absolute session lifetime |
| `allowed_origins` | list of `scheme://host[:port]` | none | extra origins accepted for state-changing requests (the request's own host is always accepted) |
| `trusted_proxies` | list of CIDRs | none | peers whose `X-Forwarded-For` is used to find the client address |
| `trusted_header.proxies` | list of CIDRs | none (off) | peers allowed to authenticate users with a header |
| `trusted_header.user_header` | header name | `Remote-User` | header holding the user name |
| `trusted_header.role` | `viewer` \| `admin` | `viewer` | role of header-authenticated users |

Guidance for `trusted_proxies` and `trusted_header` is in
[security.md](security.md#reverse-proxy-settings).
