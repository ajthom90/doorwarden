# doorwarden — design (draft for review)

Status: DRAFT, awaiting approval. No product code exists yet.

## 1. Intent
Self-hosted control plane that publishes Docker containers and TrueNAS SCALE apps at
`https://<app>.<zone>` with Let's Encrypt certs (wildcards included) and managed DNS.
Traefik v3 is the data plane (file provider only). doorwarden owns discovery, DNS, certs, and
all Traefik config. Traefik's own ACME is never used.

Goals: "install an app, nothing else"; safe by default (staging CA, dry-run, ownership-tracked
DNS); usable by strangers (open source) with zero environment-specific hard-coding.
Non-goals: being a general reverse proxy UI, L4/stream proxying, multi-node clustering, HA.
Anti-goals: deleting a DNS record or cert it did not create; losing service on container
restart; secrets in logs/git; requiring re-issuance to cut over from NPM.

## 2. Recon facts that shape the design (from the author's box; not committed to the repo)
- TrueNAS 27.0.0-RC.1: REST is gone; use JSON-RPC 2.0 over WebSocket (`/api/current`),
  API-key auth. Version is detected at startup and the client is a thin adapter so older
  versions (`/api/v25.04.x`, `/api/v2.0` legacy) can be added.
- `app.query` portals report host `0.0.0.0`; ~1/3 of apps have empty portals. Therefore:
  host = configured `target_ip`; port fallback = Docker published-port lookup via the
  `ix-<app>-` container prefix; manual override always available.
- NPM data: 38 hosts, no streams/access lists/redirects, 1 custom nginx config; certs issued by
  Cloudflare DNS-01; upstreams include off-box IPs and a hostname that resolves to the NAS.
- Port 80/443 held by NPM (compose app `ix-npm-app-1`).

## 3. Architecture
```
 TrueNAS API ─┐                       ┌─> DNS providers (records, ownership in SQLite)
 Docker (RO   ├─> Sources ─> Reconciler ─┼─> ACME manager (lego) ─> certs on disk (0600)
 socket proxy)│   (normalize)  (plan)  └─> Traefik writer ─> /dynamic/*.yml  ──> Traefik
 Static cfg  ─┘                              ▲                                   :80 → :443
                                  Web UI/API ─┘  (approve, rename, renew, dry-run)
```
Single Go binary + embedded SPA (static assets via `embed`), SQLite (pure-Go `modernc.org/sqlite`
so images are multi-arch with CGO off). Packages:

- `internal/source`: `Source` interface `List(ctx) ([]Service, error)`; impls `truenas`, `docker`,
  `static`. Output is normalized `Service{Key, Source, Name, Zone, Backend{Scheme,Host,Port,
  SkipVerify}, Options, State}`. Key is stable (`truenas:<app>`, `docker:<container name>`,
  `static:<id>`) so renames/restarts don't change identity.
- `internal/merge`: precedence label < config override < UI override; pure function, unit tested.
- `internal/reconcile`: pure `Plan(desired, observed, policy) []Action`; executor applies actions
  (or logs them in dry-run). Actions: `DNSEnsure/DNSDelete`, `CertEnsure`, `RouteWrite`.
- `internal/dns`: provider interface + registry (below). `internal/acme`: lego wrapper.
- `internal/traefik`: renders `routers/services/middlewares` and `tls.yml`, atomic write
  (temp + rename); Traefik file provider hot-reloads, so no downtime.
- `internal/store`: SQLite, migrations via embedded SQL.
- `internal/web`: REST+SSE JSON API, auth, UI. `internal/notify`: webhook/ntfy/SMTP.
- `internal/importer/npm`: optional, reads NPM SQLite (read-only copy) → mapping table.
- `internal/secrets`: AES-256-GCM envelope with master key from env (`DOORWARDEN_MASTER_KEY`),
  per-secret nonce; secrets are a distinct Go type whose `String()/MarshalJSON` redact.

Loop: sources polled every 30s (TrueNAS) / Docker events + resync; any change enqueues a
reconcile (debounced). Reconcile is idempotent and level-triggered.

Approval modes (per source): `auto` → new services publish; `approve` → state `pending` until
clicked; `off` → ignored. Service states: discovered, pending, published, conflict, error,
removed (grace).

## 4. DNS provider interface
```go
type Record struct{ ID, Name, Type, Value string; TTL int } // Name: fully-qualified, lowercase, no trailing dot; one managed record per (name,type); Update/Delete target Record.ID when set, else (name,type) / exact (name,type,value), and a non-matching Delete is a no-op
type Capabilities struct{ WildcardA, MultiZone, Update, TTL bool }
type Provider interface {
    Type() string
    Capabilities() Capabilities
    Test(ctx) error                                 // credential check
    ListRecords(ctx, zone string) ([]Record, error)
    CreateRecord(ctx, zone string, r Record) (Record, error)
    UpdateRecord(ctx, zone string, r Record) (Record, error)
    DeleteRecord(ctx, zone string, r Record) error
}
type Factory func(cfg map[string]any, secrets SecretResolver) (Provider, error)
func Register(typ string, f Factory, schema ConfigSchema) // called from init()
```
A new provider = one file in `internal/dns/providers/` with `init(){ Register(...) }` plus a
blank import in `providers/all.go`. `ConfigSchema` drives the UI form (field name, secret?,
required). Where a `libdns` package exists (cloudflare, route53, rfc2136) the file is a thin
adapter; unifi/pihole/adguard-home/technitium are hand-written HTTP clients.
Capability checks at config time: mode `wildcard` requires `WildcardA`; fails validation with
a clear message otherwise.

Ownership table `dns_records(provider, zone, name, type, value, provider_record_id, owner_key,
created_at, removed_after)`. Rule: update/delete only rows present here. A matching foreign
record yields a `conflict` (UI: adopt → insert ownership row; skip → remember choice).
Service deletion sets `removed_after = now + grace` (default 24h); a service merely
unreachable/stopped never schedules removal.

Record modes per zone: `wildcard` (one `*.zone` A), `per-host`, `off`.

## 5. Certificates
Issuer config: `letsencrypt` (prod/staging, default staging) or custom `directory` URL + EAB.
Challenge: `dns-01` via a *challenge provider* chosen from lego's provider list by name with its
env vars (separate from the record provider; secrets injected into lego's env per-run under a
mutex since lego reads process env — or use the provider-config constructors where available).
`http-01` optional (non-wildcard only). Validation rules: wildcard ⇒ dns-01; `unifi` is not a
challenge provider; zone's challenge provider must be defined.
Strategies per zone: `wildcard` (default: `*.zone` + `zone`), `per-host`, `san` (grouped).
Renewal at ≤30 days, exponential backoff with jitter, LE rate-limit awareness (track failures
per set and new-orders per week; refuse to loop), configurable propagation timeout/resolvers.
Storage: `certs/<id>/{fullchain,privkey}.pem` mode 0600, dir 0700; metadata (domains, issuer,
not_after, last_result, staging flag) in SQLite. `tls.yml` lists certs and per-zone default
cert (`tls.stores.default` is single-valued in Traefik; per-zone defaults are done with
`tls.certificates` + SNI matching, and a documented limitation for the global default store,
decided during implementation spike).
Import: PEM files or NPM's `/etc/letsencrypt/live/npm-N` dirs → stored as `imported` certs,
renewed through doorwarden only once an issuer is set for the zone (renewal switches them to
managed, never silently).
"Switch staging → production" re-issues all certs for that issuer after confirmation.
Notifications: renewal failure, expiry <14d, conflicts: webhook, ntfy, SMTP.

## 6. Config and secrets
YAML (`config.yaml`) with `${ENV}` substitution; UI edits write back a managed overlay in
SQLite (`config.yaml` stays authoritative for keys it defines; UI shows them read-only).
Same schema as the example in the request (zones/providers/issuers/sources/static services).
First-run wizard for people who don't want YAML. Secrets: master key from env, encrypted in
SQLite; never logged (redacting type + log filter test).

## 7. Web UI
Embedded SPA (Preact + Vite, no heavy runtime), responsive, dark mode via CSS variables.
Pages: Services, DNS providers (test credentials, owned vs foreign records), Certificates,
Zones, Activity log, Settings (global dry-run). Auth: local admin (argon2id) plus optional
trusted-header / forward-auth (configurable header names + trusted proxy CIDRs).
Endpoints: `/healthz`, `/metrics` (Prometheus), `/api/v1/...`, SSE `/api/v1/events`.

## 8. Deployment
Compose for TrueNAS Custom Apps: `doorwarden`, `traefik:v3` (80/443, file provider on shared
volume), `tecnativa/docker-socket-proxy` (CONTAINERS=1, read-only). Image: multi-arch
(amd64/arm64) to GHCR via GitHub Actions (build, test, Pebble integration job, release).
Traefik's own dashboard off; doorwarden's UI is itself published as a route.

## 9. Migration from NPM (optional tool + docs)
1. Read-only import of proxy hosts/certs → mapping table classifying each: `auto` (TrueNAS
   app match by port), `label` (Docker container match), `static` (anything else); flags for
   custom nginx config, access lists, streams, non-wildcard certs, off-box upstreams.
2. Import wildcard certs.
3. Cutover script: show commands → stop NPM app → start Traefik on 80/443 → verify.
4. `verify.sh`: curl each hostname with `--resolve`, check status, issuer, SANs, expiry.
5. Rollback: stop Traefik, start NPM (left stopped, intact ≥ 1 week). Every TrueNAS
   state-changing command is shown to the user before it runs.

## 10. Testing
Unit: discovery naming, merge precedence, reconcile plan (table-driven), provider capability
checks, secret redaction, config validation. Integration: Pebble + fake DNS provider
(challtestsrv for DNS-01) covering issue, renew, wildcard, backoff. Provider adapters tested
against recorded HTTP fixtures (`httptest`). No real hostnames/IPs/emails in fixtures.

## 11. Build order (for the plan)
1. Skeleton, config, store, secrets. 2. Sources + merge + reconcile (dry-run end to end).
3. Traefik writer. 4. ACME + Pebble tests. 5. DNS interface + cloudflare + fake. 6. Remaining
providers. 7. API + UI. 8. Notifications, metrics. 9. NPM importer + cutover scripts.
10. CI/image/README.

## 12. Open decisions
- License (proposal: Apache-2.0). Repo/GHCR owner and name.
- Per-zone default cert strategy given Traefik's single default store (spike).
- UI stack (proposal: Preact + Vite, embedded).
- Whether the UniFi record provider targets 11.0.97's DNS-policies endpoint only
  (proposal: yes, document minimum version).
