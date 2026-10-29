# Doorwarden

Doorwarden publishes your self-hosted services through
[Traefik](https://traefik.io/) with valid HTTPS certificates and DNS records,
from what is already running: Docker containers that opt in with a label,
TrueNAS SCALE apps you approve, and static entries for everything else.

It replaces the manual work of a reverse proxy UI such as Nginx Proxy Manager,
where every new service means a proxy host, a certificate and a DNS record
entered by hand. Doorwarden discovers the service, picks the host name
(`<name>.<zone>`), creates the DNS record, obtains the certificate and writes
the Traefik route, and removes them again (after a grace period) when the
service goes away.

## Features

- **Discovery** from Docker (`doorwarden.enable=true` label), TrueNAS SCALE
  apps (read-only API, approval required by default) and static config
  entries.
- **DNS records** in Cloudflare, Route 53, RFC 2136 servers (BIND, Knot,
  PowerDNS), Technitium, AdGuard Home, UniFi Network and Pi-hole: one wildcard
  or one record per host.
- **Certificates** from Let's Encrypt (or another ACME CA): wildcard, per-host
  or SAN, DNS-01 through any of lego's ~190 DNS providers, or HTTP-01. Staging
  by default; production after an explicit switch.
- **Safety first**: dry run, ownership tracking for every DNS record, grace
  periods, a mass-repair breaker, rate limits below Let's Encrypt's, and auth
  middlewares that fail closed.
- **Web UI and API**: services, approvals and overrides, DNS conflicts,
  certificates, activity log, a config editor that masks secrets; one
  administrator with argon2id passwords, optional single sign-on through a
  forward-auth proxy.
- **Operations**: `/healthz`, Prometheus `/metrics`, notifications (ntfy,
  webhook, SMTP), a migration importer for Nginx Proxy Manager.

## How it works

```
  Docker (via socket proxy) ─┐
  TrueNAS SCALE API ─────────┼──> Doorwarden ──> DNS provider API  (A/AAAA records)
  static: entries ───────────┘     │   │
                                   │   └──────> ACME CA            (certificates via lego)
                                   │
                                   └─ writes ─> doorwarden-routes.yml / doorwarden-tls.yml
                                                + certificate files
                                                      │
                                                      v
  browser ──── https://app.example.test ──────> Traefik :443 ──> service backend
```

Every poll interval (30s by default) Doorwarden lists its sources, decides what
should be published, compares that with what it owns (stored in SQLite), and
applies the difference: DNS records, certificates, and Traefik's file-provider
configuration. Traefik does only routing and TLS; it has no ACME, no Docker
provider and no dashboard in this setup.

## Quickstart

Doorwarden runs as three containers: `doorwarden`, `traefik` and an
allowlisting Docker socket proxy. The compose file works with `docker compose`
on any Linux host and as a TrueNAS Custom App. All values below are
placeholders.

1. Get the deploy files and prepare the directories (relative to
   `deploy/compose.truenas.yml`):

   ```
   git clone https://github.com/ajthom90/doorwarden.git
   cd doorwarden/deploy
   mkdir -p config data certs traefik-dynamic
   sudo chown -R 65532:65532 data certs traefik-dynamic
   cp .env.example .env
   ```

2. Fill in `.env`: `DOORWARDEN_TAG` (a release version),
   `DOORWARDEN_MASTER_KEY` (`openssl rand -base64 32`, and keep a copy
   off the server), `DNS_API_TOKEN`, and `DOCKER_GID`
   (`stat -c %g /var/run/docker.sock`).

3. Write `config/doorwarden.yaml`:

   ```yaml
   zones:
     - name: example.test
       target_ip: 192.0.2.10              # this host, where Traefik listens
       records: {provider: cloudflare, mode: wildcard}
       certificate: {issuer: letsencrypt, dns_provider: cloudflare}

   providers:
     cloudflare:
       type: cloudflare
       api_token: ${DNS_API_TOKEN}

   issuers:
     letsencrypt:
       email: admin@example.test          # staging directory by default

   sources:
     docker:
       host: tcp://docker-socket-proxy:2375

   static:
     - name: doorwarden                   # the UI: https://doorwarden.example.test
       host: doorwarden
       port: 8080

   settings:
     dry_run: true                        # look at the plan first
   ```

4. While dry run is on nothing routes to the UI yet, so add a loopback-only
   port for the first steps, in `local.yml` next to the compose file:

   ```yaml
   services:
     doorwarden:
       ports: ["127.0.0.1:8090:8080"]
   ```

   and start: `docker compose -f compose.truenas.yml -f local.yml up -d`.

5. **First login.** Read the one-time setup token from the log
   (`docker compose -f compose.truenas.yml logs doorwarden`, the line
   `no administrator yet: first-run setup token`), open
   `http://localhost:8090/` (through `ssh -L 8090:127.0.0.1:8090 <host>` from
   another machine) and create the administrator with it (password of at
   least 12 characters). The token changes on every restart until setup is
   done.

6. Review the plan on the Services page. Add `doorwarden.enable: "true"` labels
   to the containers you want published ([docs/labels.md](docs/labels.md)).
   Then remove `dry_run: true`, restart, and check that
   `https://doorwarden.example.test` serves a (staging) certificate. Switch to
   production on the Certificates page when every host works
   ([docs/cert-troubleshooting.md](docs/cert-troubleshooting.md#from-staging-to-production)),
   and drop `local.yml`.

Set `web.trusted_proxies` once Traefik is in front
([docs/security.md](docs/security.md#webtrusted_proxies)).

### On TrueNAS SCALE

Follow [docs/deploy.md](docs/deploy.md): create a dataset with the same
layout, paste `deploy/compose.truenas.yml` into a Custom App with literal
values in place of the `${...}` variables, move the TrueNAS web interface off
80/443 before Traefik takes them, and add a `sources.truenas` entry with an
API key. TrueNAS apps wait for approval on the Services page. Replacing Nginx
Proxy Manager is a staged cutover on alternate ports with an instant rollback:
[docs/migration.md](docs/migration.md), [docs/rollback.md](docs/rollback.md).

## Safety model

- **Nothing is published by accident.** Docker containers must opt in; TrueNAS
  apps wait for approval; static entries are written by you. Dry run shows the
  plan before anything changes.
- **Doorwarden only touches DNS records it created** (or that you adopt).
  Existing records are reported as conflicts. Removal waits for
  `settings.grace_period` (24h); a source outage never counts as removal; the
  wildcard record is never removed automatically; when most records of a zone
  look missing, the mass-repair breaker stops and asks
  ([docs/providers.md](docs/providers.md#how-doorwarden-owns-records)).
- **Certificates start on staging**, and Doorwarden keeps below Let's Encrypt's
  rate limits, so a mistake cannot lock you out of the CA.
- **Auth middlewares fail closed**: a typo never publishes a service without
  its authentication.
- **Least privilege**: the Docker API is reached only through a proxy that
  allows one read-only call; every container runs read-only without
  capabilities; Doorwarden publishes no port of its own.

Details: [docs/security.md](docs/security.md).

## DNS providers

| Provider | `type` | Wildcard record | ACME DNS-01 |
|---|---|---|---|
| Cloudflare | `cloudflare` | yes | yes (same entry) |
| Amazon Route 53 | `route53` | yes | yes (separate entry) |
| RFC 2136 (BIND, Knot, PowerDNS, ...) | `rfc2136` | yes | yes (separate entry) |
| Technitium DNS Server | `technitium` | yes | yes (separate entry) |
| AdGuard Home | `adguard` | yes | no (record only) |
| UniFi Network | `unifi` | opt-in (`wildcard: true`) | no (record only) |
| Pi-hole v6 | `pihole` | no | no (record only) |

Certificates can use any other [lego DNS provider](https://go-acme.github.io/lego/dns/)
for challenges, independent of the record provider. See
[docs/providers.md](docs/providers.md).

## Status and maturity

Doorwarden is **beta**. The design is complete and the test suite is large,
but it has had little use on real installations yet. Back up, start in dry run
with the staging issuer, and keep your old setup for rollback.

What has only been verified against fakes (in-process servers that follow the
documented APIs), not against the real product:

- every DNS record provider: Cloudflare, Route 53, RFC 2136, Technitium,
  AdGuard Home, Pi-hole and especially UniFi (record writes, wildcard records
  and IPv6 policies have not been tried on a real controller);
- the TrueNAS SCALE API (`app.query`) and its portal data;
- certificate issuance, tested end to end only against Pebble (Let's
  Encrypt's test CA) with a mock DNS server; none of lego's DNS challenge
  providers is exercised against a real DNS API by the tests;
- the socket proxy's group setup on a real TrueNAS or Linux Docker socket
  (verified only under Docker Desktop).

The binary is about 66 MiB (linux/amd64, stripped) because it includes lego's
full DNS provider catalog; a smaller `acme_minimal` build is deferred
([docs/operations.md](docs/operations.md#resource-notes)).

The `fake` DNS provider type is compiled in for tests and the UI demo; it keeps
records in memory only and is not for real zones. Reports from real setups,
working or not, are very welcome: open an issue.

## Documentation

- [docs/deploy.md](docs/deploy.md): deploying on TrueNAS or Docker, UI access,
  the socket proxy
- [docs/configuration.md](docs/configuration.md): every config key, flag and
  environment variable
- [docs/labels.md](docs/labels.md): Docker labels, TrueNAS apps, static
  routes, overrides, middlewares
- [docs/providers.md](docs/providers.md): DNS record and challenge providers,
  record ownership
- [docs/cert-troubleshooting.md](docs/cert-troubleshooting.md): certificates,
  staging to production, rate limits, errors
- [docs/operations.md](docs/operations.md): health, metrics, backups,
  upgrades, dry run, the mass-repair breaker
- [docs/security.md](docs/security.md): threat model and hardening
- [docs/migration.md](docs/migration.md) and [docs/rollback.md](docs/rollback.md):
  moving from Nginx Proxy Manager and back

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Third-party licenses of the modules compiled
into the binary are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), also
shipped in the image under `/usr/share/doc/doorwarden/`.
