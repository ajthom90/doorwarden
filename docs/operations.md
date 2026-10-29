# Operations

## Health

`GET /healthz` needs no authentication and answers:

- `200 {"status":"ok","degraded":false}` when the control plane runs;
  `degraded` is `true` when a source's last listing failed or the last
  reconcile ended with an error (health stays 200, so a TrueNAS outage does not
  restart Doorwarden);
- `503` with `"status":"fail"` only when the database is unusable.

With a session the answer also has `store`, `dry_run`, `sources` (source name
to last listing succeeded), `last_reconcile` and `last_result` (`ok`, `error`
or `dry_run`).

The container healthcheck runs `/doorwarden healthcheck`, which GETs
`$DOORWARDEN_HEALTH_URL` (default `http://127.0.0.1:8080/healthz`) with a 3
second timeout (`-url`, `-timeout`).

## Metrics

`GET /metrics` serves Prometheus metrics and, like the rest of the API,
requires authentication: a session, or a header-authenticated scraper through
`web.trusted_header` (see [security.md](security.md#webtrusted_header) for the
rules; a `viewer` role is enough).

| Metric | Type | Labels |
|---|---|---|
| `doorwarden_services` | gauge | `state`: services per lifecycle state |
| `doorwarden_reconcile_total` | counter | `result`: `ok`, `error`, `dry_run` |
| `doorwarden_reconcile_duration_seconds` | histogram | |
| `doorwarden_reconcile_actions_total` | counter | `kind`: planned action kind |
| `doorwarden_dns_operations_total` | counter | `provider_type`, `op` (`ensure`, `update`, `delete`, `list`), `result`: every call to a DNS record provider |
| `doorwarden_cert_renewal_total` | counter | `result`: `ok`, `error`: every issuance attempt (hourly renewals, new certificates, Renew now, the production switch); deferred or skipped certificates are not counted |
| `doorwarden_cert_expiry_seconds` | gauge | `zone`: seconds until the earliest certificate expiry (negative when expired), updated every cycle, dry run included |
| `doorwarden_source_up` | gauge | `source`: 1 when the last listing succeeded |
| `doorwarden_source_list_duration_seconds` | histogram | `source` |
| `doorwarden_notifications_total` | counter | `sender`, `result` (`ok`, `error`, `dropped`) |
| `doorwarden_build_info` | gauge | `version` (always 1) |

The standard Go runtime (`go_*`) and process (`process_*`) metrics are
included. Useful alerts: `doorwarden_cert_expiry_seconds < 7*86400`,
`doorwarden_source_up == 0` for 15 minutes, and a rising
`doorwarden_reconcile_total{result="error"}`.

## Logs and activity

Doorwarden logs to standard error (`docker logs <container>`) as text lines
with a level (`INFO`, `WARN`, `ERROR`). Credentials are never logged. Worth
knowing:

- `INFO doorwarden started ... dry_run=...` at start-up, and in a dry run also
  `WARN DRY RUN: no DNS record, certificate, Traefik file or route is changed ...`
  with the reason (config, the UI switch, or an unreadable switch);
- `WARN no administrator yet: first-run setup token ...` until setup is done;
- `WARN ... zones and no settings.default_zone ...` when several zones and
  discovery are configured without a default zone
  ([configuration.md](configuration.md#settings));
- `INFO dry run: would ...` for every planned change during a dry run;
- `WARN running in a container with web.trusted_proxies unset` (see
  [security.md](security.md#webtrusted_proxies)).

The **Activity** page (`GET /api/v1/activity`) keeps a log of changes: what
was applied, invalid services and conflicts (when their outcome changes, not
every cycle), and every administrator action (approvals, renames, adopted
records, dry-run toggles). Alerts go to the configured
[notifications](configuration.md#notifications).

## The dry-run workflow

1. Start with `settings.dry_run: true` (or the dry-run switch on the
   **Settings** page). Doorwarden lists sources and DNS providers (read-only)
   and logs and shows what it would do, but writes no DNS record, places no
   certificate order, writes no Traefik file and sends no notification.
2. Read the plan on the **Services** page ("Planned ... in dry run") and the
   `dry run: would ...` log lines. Check host names, backends, DNS conflicts
   and invalid services.
3. Turn dry run off. If `settings.dry_run` is `true` in the config, the UI
   switch cannot turn it off: remove it from the config and restart.
4. Keep the staging issuer until every host serves a certificate, then
   [switch to production](cert-troubleshooting.md#from-staging-to-production).

The run is dry when the config setting or the persisted UI switch is on. A
failure to read the switch from the database also makes a cycle dry.

While dry run is on, the actions that would change real state now (Renew now,
Switch to production, Adopt a DNS conflict) are refused with `409 Conflict`
(`dry run is on: ... turn dry run off first`). Ignoring a conflict, approvals,
renames and other overrides are accepted and show up in the next plan. Remember that
in dry run Doorwarden writes no Traefik file, so the static route to its own
UI does not exist yet ([deploy.md](deploy.md#first-run)).

## Mass-repair breaker

When more than 3 of the owned DNS records in a zone are missing and they are
more than half of them, Doorwarden does not re-create them: a listing that
suddenly looks empty usually means a wrong provider or zone configuration (a
wiped Pi-hole, a Route 53 provider pinned to the wrong hosted zone), not that
the records are really gone. It reports `most owned records missing at
<provider>/<zone> (N of M); refusing mass repair` on the DNS page and alerts.

1. Check the provider and zone configuration first. When most records are
   listed again, the breaker clears by itself.
2. If the records really are gone (a reinstalled DNS server, records deleted
   by hand), press **Acknowledge and allow repair** on the DNS page, or call
   `POST /api/v1/dns/repair/ack` with `{"provider": "<name>", "zone": "<zone>"}`.
   For 24 hours, repairs then proceed at up to 5 records per zone and cycle.
   The acknowledgement is dropped once the zone has recovered, so a later mass
   loss trips the breaker again.

## Backups

Back up all of these together:

| What | Default location | Why |
|---|---|---|
| database | `/data/doorwarden.db` (with `-wal`/`-shm` files) | ownership of DNS records, approvals, overrides, routes, certificate state, ACME accounts, users |
| certificates | `/data/certs/` | issued certificates and keys (can be re-issued, within rate limits) |
| config | `/config/doorwarden.yaml` | |
| **master key** | `DOORWARDEN_MASTER_KEY`, outside the server | without it the ACME account keys in a restored database cannot be decrypted |

The ownership rows matter most: without them Doorwarden treats the records it
created as foreign (it reports conflicts, which you can adopt) and can no
longer clean them up after the grace period.

Take the copy while Doorwarden is stopped, or from a filesystem snapshot (a
ZFS snapshot of the dataset on TrueNAS is crash-consistent, which SQLite's
write-ahead log tolerates). Do not copy only `doorwarden.db` while it runs
without its `-wal` file.

## Upgrading

1. Read the release notes.
2. Back up (above).
3. Set `DOORWARDEN_TAG` to the new version and redeploy. Database migrations
   run automatically at start.
4. Check `/healthz`, the log and the plan. Consider turning dry run on for the
   first start after a major upgrade.

Migrations only go forward. To go back to an older version, restore the backup
taken before the upgrade. Do not just start an older binary on a newer
database: it ignores columns it does not know. For example, a version without
migration `0005` ignores the quarantine mark on routes
([labels.md](labels.md#approval)) and would serve quarantined services again.

Notes for upgrading to the version with quarantine and `traefik.file_mode`:

- Existing approvals are migrated to the new format once, automatically,
  only for services whose current content is exactly what their route serves
  (`migrated approval v1->v2` in the activity log); no mass re-approval is
  needed. Any other service is quarantined (or Pending, if it has no route)
  and needs one re-approval ([labels.md](labels.md#approval)). Nothing is
  migrated in dry run, and dry run does not show which approvals would be
  written.
- Configs that use YAML anchors or aliases no longer load; write the values
  out in full ([configuration.md](configuration.md)).
- Generated Traefik files with another mode than `traefik.file_mode` (default
  `0600`) are rewritten once, which makes Traefik reload once.
- With several zones, set `settings.default_zone` if you use Docker or
  TrueNAS discovery; otherwise zone-less services become errors.

## Stopping

Stopping Doorwarden deletes nothing: no route, DNS record, certificate or
file. On `SIGTERM` it stops the loop between actions, closes the UI's event
streams, finishes HTTP requests (up to 10 seconds; background API actions such as
Renew now are refused with `503` once shutdown has begun), and waits up to 30 seconds for certificate orders in
progress. Give the container a stop timeout of at least 45 seconds (the
provided compose file sets `stop_grace_period: 45s`; Docker's default is 10).

## Files Doorwarden writes for Traefik

In `traefik.dynamic_dir`: `doorwarden-routes.yml` (routers, services,
middlewares) and `doorwarden-tls.yml` (certificates, TLS options, default
store). Both start with `# doorwarden-managed: generated by doorwarden, do not
edit`, are written atomically, and are regenerated every cycle; Doorwarden
only removes stale files that carry this header and the `doorwarden-` prefix.
Put your own Traefik configuration in other files.

## Troubleshooting

- **A stopped TrueNAS app and a Docker container with the same host name.**
  The TrueNAS app outranks the container, so while the app is stopped the
  container stays a conflict and Traefik keeps serving the TrueNAS app's route
  (its backend is down). The routes table can show a leftover row for the
  container; it is harmless and is not served. Rename one of the two to let
  both be published.
- **A service is stuck as Pending.** Its source is in `approve` mode (the
  default for TrueNAS) and it has not been approved yet
  ([labels.md](labels.md#approval)).
- **`backend changed; re-approve to resume`.** The service is quarantined: its
  source changed approved content (port, scheme, middlewares, name). It is not
  served until you review and approve it again
  ([labels.md](labels.md#approval)).
- **A renamed or recreated service is a conflict with itself.** Its key
  changed, and the old key keeps the host name until its grace period ends
  ([labels.md](labels.md#host-name-conflicts)).
- **`degraded: true` on `/healthz`.** A source failed its last listing or the
  last reconcile had an error; the Services page and the log say which.

## Resource notes

The binary includes the whole lego catalog of DNS challenge providers, so it is
large: about 66 MiB for linux/amd64 (stripped), and the image about 90 MB. An
`acme_minimal` build tag that would leave out unused challenge providers is
planned but deferred; it does not exist in this release.
