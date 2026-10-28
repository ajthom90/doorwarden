# doorwarden Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build doorwarden, a self-hosted control plane that discovers Docker/TrueNAS services and publishes them through Traefik with managed DNS records and ACME certificates.

**Architecture:** One Go binary (pure-Go SQLite, embedded Preact SPA). Sources emit normalized `Service`s; a pure `Plan` function diffs desired vs. observed state into actions; executors apply DNS changes (ownership-tracked), issue/renew certs via lego, and atomically write Traefik file-provider YAML.

**Tech Stack:** Go 1.23+, `modernc.org/sqlite`, `go-acme/lego/v4`, `libdns/*`, `gopkg.in/yaml.v3`, `gorilla/websocket`, `prometheus/client_golang`, Preact+Vite, Pebble for integration tests, GitHub Actions + GHCR.

**Spec:** `docs/superpowers/specs/2026-10-28-doorwarden-design.md`

## Global Constraints

- Module path `github.com/ajthom90/doorwarden`; license Apache-2.0; images `ghcr.io/ajthom90/doorwarden`, multi-arch amd64+arm64, CGO off.
- Nothing environment-specific in the repo: tests/fixtures/docs use `example.test`, `*.example.test` and RFC 5737 addresses (192.0.2.0/24, 198.51.100.0/24); never the author's domains, IPs or email.
- Default ACME issuer is Let's Encrypt **staging**; global dry-run is available and defaults off but is honored by every executor.
- Renew when ≤30 days remain; DNS grace period before record deletion defaults to 24h; TrueNAS poll interval 30s.
- doorwarden only modifies/deletes DNS records recorded in its `dns_records` ownership table.
- Container stop/restart never removes DNS records, routes or certs.
- Cert/key files mode 0600 (dirs 0700); secrets AES-256-GCM at rest with master key from `DOORWARDEN_MASTER_KEY`; secrets never logged.
- Config validation: wildcard cert ⇒ DNS-01; `unifi` cannot be a challenge provider; `wildcard` record mode requires provider capability `WildcardA`.
- Traefik v3, file provider only; Traefik ACME never used.
- TrueNAS API: JSON-RPC 2.0 over WebSocket at `/api/current` with API-key auth; REST not used.
- UniFi: Integration API, header `X-API-KEY`, `GET /proxy/network/integration/v1/sites` then `/sites/{siteId}/dns/policies` (type `A_RECORD`, fields `domain`, `ipv4Address`, `ttlSeconds`); requires UniFi Network ≥ 10.x with DNS policies (verified on 11.0.97).
- Every task ends in a commit; use `go test ./... -race`.

## Review Focus

- Service names with uppercase, underscores, dots, or leading digits (e.g. `My_App.v2`): must produce a valid DNS label or a clear error, never an invalid host rule.
- Two sources claiming the same hostname: deterministic winner by precedence, loser shown as `conflict`, never two routers with one rule.
- TrueNAS portals with host `0.0.0.0`, empty portals, or multiple portals: host rewritten to `target_ip`, empty falls back to Docker published port, else state `error: no port`.
- Source outage (Docker socket or TrueNAS API unreachable): reconciler must treat the source as *unknown*, not as "all services deleted" — no DNS deletion scheduled.
- Config/secret edge cases: `${UNSET_VAR}` in YAML must fail validation naming the variable; wrong/missing master key must not corrupt stored secrets.
- ACME rate limits and failures: repeated failure backs off and stops hammering; a failed renewal keeps serving the existing cert.
- Existing foreign DNS record with same name: conflict, not overwrite; adopt must be explicit.
- Concurrent reconciles (poll + UI click): serialized, idempotent.

---

### Task 1: Skeleton, license, CI test job

**Files:** Create `go.mod`, `LICENSE`, `cmd/doorwarden/main.go`, `.github/workflows/ci.yml`, `.gitignore`, `Makefile`.

**Interfaces:** Produces `main()` calling `app.Run(ctx, args []string) error` (stub until Task 9).

- [ ] **Step 1:** `go mod init github.com/ajthom90/doorwarden`; add Apache-2.0 `LICENSE`; `.gitignore` excludes `data/`, `*.key`, `.env`.
- [ ] **Step 2:** Test `TestMainVersionFlag` in `cmd/doorwarden/main_test.go` runs `run([]string{"--version"})` and asserts output contains `doorwarden`. Run: FAIL (undefined).
- [ ] **Step 3:** Implement `run(args []string, out io.Writer) int`. CI workflow runs `go vet ./... && go test ./... -race` on push/PR.
- [ ] **Step 4:** `go test ./...` PASS. Commit `chore: project skeleton`.

### Task 2: Config loading, env substitution, validation

**Files:** Create `internal/config/config.go`, `env.go`, `validate.go`; tests alongside.

**Interfaces:** Produces:
```go
type Config struct { Zones []Zone; Providers map[string]ProviderCfg; Issuers map[string]Issuer
  Sources Sources; Static []StaticService; Settings Settings }
func Load(path string, env func(string) (string, bool)) (*Config, error)
func (c *Config) Validate(caps func(providerType string) (dns.Capabilities, bool)) []error
```
(`Zone` = `{Name, TargetIP, Records{Provider, Mode}, Certificate{Issuer, Strategy, Challenge, DNSProvider}}`; `Mode` ∈ wildcard|per-host|off; `Strategy` ∈ wildcard|per-host|san.)

- [ ] **Step 1:** Tests: `TestEnvSubstitution` (`${A}` replaced, `${B:-x}` default), `TestUnsetVarFails` (error names `UNSET_VAR`), `TestWildcardRequiresDNS01`, `TestUnifiNotChallengeProvider`, `TestWildcardModeNeedsCapability`, `TestDefaultsStagingIssuer`, `TestUnknownProviderRef`. Use the example shape from the request with `example.test`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with `yaml.v3`, substitution before unmarshal, strict unknown-field decoding. **Step 4:** PASS. **Step 5:** Commit.

### Task 3: Secrets package

**Files:** Create `internal/secrets/secrets.go`, test.

**Interfaces:** Produces `type Secret string` (`String()`/`MarshalJSON`/`LogValue` return `"[redacted]"`), `func (s Secret) Reveal() string`, `func NewBox(masterKey string) (*Box, error)`, `(*Box).Seal(plain []byte) ([]byte, error)`, `(*Box).Open(sealed []byte) ([]byte, error)`.

- [ ] **Step 1:** Tests: roundtrip; two seals of same plaintext differ (random nonce); wrong key → `ErrDecrypt`, no panic; `fmt.Sprintf("%v", s)` and slog output contain no plaintext; empty master key rejected.
- [ ] **Steps 2–5:** Implement AES-256-GCM, key derived via HKDF-SHA256 from master key; commit.

### Task 4: SQLite store and migrations

**Files:** Create `internal/store/store.go`, `migrations/0001_init.sql`, `services.go`, `dnsrecords.go`, `certs.go`, `activity.go`, `settings.go`.

**Interfaces:** Produces `Open(path string) (*Store, error)`, tables `services(key PK, source, state, overrides_json, first_seen, last_seen, removed_after)`, `dns_records(provider, zone, name, type, value, provider_record_id, owner_key, created_at, removed_after)`, `certs(id, zone, domains_json, issuer, staging, not_after, status, last_result, last_error, path, managed)`, `activity(ts, level, kind, message)`, `kv(key, value)`; methods used by later tasks: `UpsertService`, `ListServices`, `AddOwnedRecord`, `ListOwnedRecords(provider, zone)`, `DeleteOwnedRecord`, `UpsertCert`, `ListCerts`, `AppendActivity`, `GetSetting/SetSetting`.

- [ ] Tests: migrations idempotent on reopen; ownership roundtrip; `ListOwnedRecords` scoped to provider+zone. Implement with `modernc.org/sqlite`, WAL, embedded SQL. Commit.

### Task 5: Service model, naming, override merge

**Files:** Create `internal/model/service.go`, `name.go`, `merge.go`, tests.

**Interfaces:** Produces:
```go
type Service struct { Key, Source, Name, Zone string; Backend Backend; Options Options; State string }
type Backend struct { Scheme, Host string; Port int; SkipVerify bool }
type Options struct { Skip, Websockets bool; Middlewares []string; Rename string }
func Slug(s string) (string, error)                       // DNS-label safe
func Merge(label, cfg, ui Overrides) Overrides            // ui > cfg > label
func Hostname(svc Service, zones []string, defaultZone string) (string, error)
```

- [ ] Tests (table-driven): `Slug("My_App.v2")=="my-app-v2"`; empty/all-invalid → error; 64+ chars truncated to 63; leading digit allowed, leading/trailing hyphen trimmed; merge precedence per field including explicit `false`/zero overriding a label; unknown zone errors. Implement. Commit.

### Task 6: Docker source

**Files:** Create `internal/source/source.go` (interface), `internal/source/docker/docker.go`, test with fake Docker HTTP server.

**Interfaces:** Produces `type Source interface{ Name() string; List(ctx) ([]model.Service, error) }`; docker impl reads labels `doorwarden.enable|name|port|scheme|zone|skip-verify|websockets|middlewares`, connects to `tcp://socket-proxy:2375` or unix path (configurable). Backend host = container name on shared network if configured, else `target_ip` + published port. Returns `ErrSourceUnavailable` (typed) when the daemon is unreachable.

- [ ] Tests: opt-in only when `doorwarden.enable=true`; defaults (name = container name slug, port = single exposed port, error if ambiguous); stopped container remains listed with state `stopped` (never dropped); daemon down → `ErrSourceUnavailable`. Implement; commit.

### Task 7: TrueNAS source

**Files:** Create `internal/source/truenas/client.go`, `source.go`, tests with a fake WebSocket JSON-RPC server.

**Interfaces:** Produces `NewClient(url string, apiKey secrets.Secret, insecureTLS bool)`; `Call(ctx, method string, params ...any) (json.RawMessage, error)`; source `List` calls `app.query`, maps `name,state,portals` → Services with `Backend.Host=target_ip`, port parsed from portal URL (host `0.0.0.0` ignored); empty portals fall back to a `PortLookup` interface (Docker published ports by `ix-<app>-` prefix); `state != RUNNING` → `stopped`.

- [ ] **Step 1 (spike, first):** against a real TrueNAS box (URL and API-key file path supplied by the operator at run time, never committed; TLS verify off, read-only `core.ping`, `system.version`, `app.query`) record the auth handshake (`auth.login_with_api_key`) and one sanitized `app.query` response into `testdata/app_query.json` (replace names/ports with `example` values before commit).
- [ ] Tests: portal `http://0.0.0.0:30088/` → port 30088 host target_ip; `https` portals set scheme; two portals → first "Web UI" wins; empty portals + lookup hit/miss (`error: no port`); API down → `ErrSourceUnavailable`. Implement; commit.

### Task 8: Static source and approval gate

**Files:** Create `internal/source/static/static.go`, `internal/approval/approval.go`, tests.

**Interfaces:** Produces static source from `config.Static`; `Gate(mode string, existing store state, svc) State` where mode ∈ auto|approve|off yields `published|pending|ignored`.

- [ ] Tests: auto publishes; approve yields `pending` until `Approve(key)`; off ignored; approval persists across restart; `Skip` option wins over auto. Implement; commit.

### Task 9: Reconcile plan (pure) and executor shell

**Files:** Create `internal/reconcile/plan.go`, `executor.go`, tests.

**Interfaces:** Produces:
```go
type Action struct { Kind string; Zone, Host string; Svc *model.Service } // DNSEnsure|DNSDelete|CertEnsure|RouteWrite|RouteRemove|Conflict
type Observed struct { Owned []store.DNSRecord; Foreign map[string][]dns.Record; Certs []store.Cert; Unavailable map[string]bool }
func Plan(desired []model.Service, obs Observed, cfg *config.Config, now time.Time) []Action
type Executor interface{ Apply(ctx, []Action, dryRun bool) error }
```

- [ ] Tests (table-driven): new service → DNSEnsure+CertEnsure+RouteWrite; wildcard mode → one `*.zone` DNSEnsure total; mode off → no DNS actions; **unavailable source → no deletes**; service gone → schedules deletion only after `removed_after`; stopped → nothing removed; foreign record same name → `Conflict`; duplicate hostname across sources → one winner + `Conflict`; dry-run records activity but calls no provider. Implement; commit.

### Task 10: Traefik writer

**Files:** Create `internal/traefik/writer.go`, `render.go`, golden tests.

**Interfaces:** Produces `Write(dir string, routes []Route, certs []TLSCert) error` writing `routers-services.yml` and `tls.yml` atomically (temp file + `os.Rename`, same dir); Route supports scheme, `serversTransport` with `insecureSkipVerify`, middlewares, websockets (no special config needed; keep note), HTTP→HTTPS redirect handled by Traefik static config.

- [ ] Tests: golden YAML for http backend, https+skip-verify, middleware list; rewrite with identical content does not change mtime; partial-write simulation never leaves a truncated file; stale routes removed. Implement; commit.

### Task 11: DNS provider interface, registry, fake provider

**Files:** Create `internal/dns/provider.go`, `registry.go`, `providers/all.go`, `providers/fake/fake.go`, tests.

**Interfaces:** Exactly the `Provider`, `Record`, `Capabilities`, `Factory`, `Register` from the spec §4, plus `ConfigSchema{Fields []Field{Name string; Secret, Required bool; Help string}}` and `New(typ string, cfg map[string]any, sr SecretResolver) (Provider, error)`, `Types() []string`, `CapsFor(typ string)`.

- [ ] Tests: duplicate `Register` panics; unknown type error; fake provider conformance suite `dnstest.Run(t, factory)` (create/list/update/delete, idempotent create, delete missing is ok) — reused by every provider in Tasks 12–13. Implement; commit.

### Task 12: Cloudflare, Route 53, RFC 2136 providers (libdns adapters)

**Files:** `internal/dns/providers/{cloudflare,route53,rfc2136}/*.go`, tests.

- [ ] Each: `init(){ dns.Register(...) }`, schema fields (cloudflare `api_token`; route53 `access_key_id|secret_access_key|region` with IAM-role fallback when keys empty, hosted-zone auto-discovery by longest suffix match; rfc2136 `server|key_name|key_secret|algorithm`), `Capabilities{WildcardA:true}`. Tests via `dnstest.Run` against `httptest`/fake libdns; route53 zone autodiscovery picks `example.test` over `test`. Commit per provider.

### Task 13: UniFi, Pi-hole, AdGuard Home, Technitium providers

**Files:** `internal/dns/providers/{unifi,pihole,adguard,technitium}/*.go`, `testdata/`, tests.

- [ ] UniFi: `url`, `api_key`, optional `site_id`; auto-discover siteId via `/sites`, `insecure_skip_verify` option; records map to `A_RECORD` policies; `WildcardA` true only if a probe/policy create of `*.example` is accepted (document; default false, config override `wildcard: true`). Ownership still enforced by store. Update uses PUT on policy id.
- [ ] Pi-hole (v6 API `/api/config/dns/hosts`, session auth), AdGuard (`/control/rewrite/*`, basic auth), Technitium (`/api/zones/records/*`, token): each with HTTP fixtures; all run `dnstest.Run`; wildcard supported for AdGuard/Technitium only. Commit per provider.

### Task 14: Ownership-aware DNS executor

**Files:** `internal/reconcile/dnsexec.go`, test.

- [ ] Tests with fake provider: creates record and stores ownership; foreign same-name record → no write, `Conflict` activity; `Adopt(key)` then updates it; update only when value differs; delete only owned rows and only past grace; provider error leaves ownership row consistent (create succeeded but DB write failed is retried without duplicating). Implement; commit.

### Task 15: ACME manager (lego) + challenge provider catalog

**Files:** `internal/acme/manager.go`, `catalog.go`, `store.go`, tests.

**Interfaces:** `Issue(ctx, req IssueRequest) (*Bundle, error)`; `Catalog() []ChallengeProvider{Name string; EnvVars []string}` generated from lego's providers; `Renew` selects certs with `NotAfter-now ≤ 30d`; certs written 0600 under `certs/<id>/`.

- [ ] Tests: `TestWildcardRequiresDNS01Validation`; file modes 0600/0700; backoff schedule (1m,2m,4m…cap 6h) with injected clock; failure keeps previous cert; rate-limit error (`urn:ietf:params:acme:error:rateLimited`) parks the order until the retry-after; EAB passed to custom directory; env isolation (provider env set under mutex, restored). Implement; commit.

### Task 16: Pebble integration tests

**Files:** `test/integration/acme_test.go`, `docker-compose.pebble.yml`, CI job.

- [ ] Using Pebble + `pebble-challtestsrv` as DNS responder with a mock lego DNS provider calling challtestsrv's HTTP API: issue wildcard+apex cert, renew (clock forced), HTTP-01 non-wildcard issue. Build-tag `integration`; CI job starts the compose stack. Commit.

### Task 17: Cert import and Traefik TLS wiring

**Files:** `internal/acme/import.go`, `internal/traefik/tls.go`, tests.

- [ ] Tests: import PEM pair → parsed domains/expiry stored with `managed=false`; mismatched key rejected; NPM live dir import (`fullchain.pem`/`privkey.pem`); imported cert not auto-renewed until issuer assigned; default cert per zone chosen by longest domain match, stored as SNI-matched `tls.certificates`; spike result on `tls.stores.default` documented in the file. Commit.

### Task 18: Notifications and metrics

**Files:** `internal/notify/{webhook,ntfy,smtp}.go`, `internal/metrics/metrics.go`, tests.

- [ ] Tests with `httptest`/fake SMTP: payload shape, retry once, no secrets in payload, expiry-warning dedupe (one per cert per threshold). Metrics: `doorwarden_services{state}`, `doorwarden_cert_expiry_seconds{zone}`, `doorwarden_reconcile_total{result}`, `doorwarden_dns_ops_total{provider,op}`. Commit.

### Task 19: Orchestrator (`app.Run`), health, dry-run

**Files:** `internal/app/app.go`, `loop.go`, `internal/web/health.go`, tests.

- [ ] Tests: reconcile loop serialized via mutex; poll + manual trigger coalesced; `/healthz` fails when store unusable, ok when a source is down (degraded flag in body); global dry-run toggle persisted; graceful shutdown. Wire everything built so far. Commit.

### Task 20: HTTP API and auth

**Files:** `internal/web/{api,auth,sse}.go`, tests.

**Interfaces:** `/api/v1/services` (GET, POST `…/{key}/publish|unpublish|approve|rename|port`), `/dns/providers` (+`/test`), `/dns/records`, `/dns/conflicts/{id}/adopt|skip`, `/certs` (+`/renew`, `/switch-production`), `/zones`, `/activity`, `/settings/dry-run`, `/config` (GET/PUT with secrets masked), SSE `/events`; auth = argon2id local admin + session cookie (SameSite=Strict, CSRF header), optional trusted-header only from configured CIDRs.

- [ ] Tests: unauthenticated 401; header auth ignored from untrusted source IP; secrets masked in `/config`; PUT config validates and rejects invalid; first-run creates admin only when none exists. Commit.

### Task 21: Web UI

**Files:** `web/` (Preact+Vite), `internal/web/ui.go` (`embed`), Playwright smoke test.

- [ ] Pages: Services, DNS providers (test button, owned/foreign badge), Certificates (renew now, staging→production with confirm), Zones, Activity, Settings (dry-run), first-run wizard. Responsive + `prefers-color-scheme` dark mode. Smoke test: login, see service list, mobile viewport has no horizontal scroll. Commit.

### Task 22: NPM importer and verify script

**Files:** `internal/importer/npm/npm.go`, `cmd/doorwarden/import_npm.go`, `scripts/verify.sh`, tests with a synthetic NPM sqlite.

- [ ] Tests: classifies auto/label/static by matching host:port against discovered services; flags custom nginx config, access lists, streams, non-wildcard certs, off-box upstreams; hostname-based upstreams resolved/flagged; never writes to the NPM DB (opened `mode=ro` on a copy). `verify.sh <hostlist>` curls each host with `--resolve`, prints status, issuer, SANs, days-to-expiry; exits non-zero on any failure. Commit.

### Task 23: Deployment, docs, release

**Files:** `Dockerfile`, `deploy/compose.truenas.yml`, `deploy/traefik/traefik.yml`, `docs/{README,labels,providers,cert-troubleshooting,migration,rollback}.md`, `.github/workflows/release.yml`.

- [ ] Compose: doorwarden + `traefik:v3` (80→443 redirect, file provider on shared volume, no ACME) + docker-socket-proxy (read-only). Docs: "install it, nothing else", label reference, "add a DNS provider" (one file + `all.go` import + conformance test), staging→production flow, rollback (stop Traefik, start NPM; keep NPM ≥ 1 week). Release workflow: buildx amd64+arm64 to GHCR on tag. Test: `docker build` succeeds and container passes `/healthz`. Commit.

### Task 24: Live cutover on the author's NAS (manual, gated)

- [ ] Not automated. With the author's explicit go-ahead: deploy on alternate ports first, run importer + `verify.sh` against Traefik via `--resolve`, show each state-changing command (stop NPM app, start Traefik on 80/443) before running, verify all hostnames, leave NPM stopped but intact.

---

## Self-review notes
- Spec coverage: sources (6–8), DNS (11–14), certs (15–17), config/secrets (2–3), UI/API (20–21), migration (22, 24), engineering/CI/docs (1, 16, 18, 23). Per-zone default cert spike is in Task 17.
- Type names (`model.Service`, `dns.Provider`, `store.DNSRecord`, `reconcile.Action`) are used consistently across tasks.
