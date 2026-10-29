# Migrating from Nginx Proxy Manager to Doorwarden

This is a staged cutover. NPM keeps serving ports 80/443 until the very last
step, and is stopped (never deleted) so you can roll back instantly
(see [rollback.md](rollback.md)).

All names below are placeholders: `<truenas-host>`, `example.test`,
`192.0.2.x`. TrueNAS app names, menu paths and ports differ between TrueNAS
versions; treat the ones here as examples.

> **Safety rule for every TrueNAS state-changing command** (stopping or
> starting an app, editing an app's ports, creating datasets): show the exact
> command or UI action to the operator, and run it only after they confirm.
> Nothing in this guide should be pasted blindly.

## 0. Prerequisites

- DNS for your zone is managed by a provider Doorwarden supports, and you have
  an API token with DNS edit rights for that zone only.
- Certificates: Doorwarden obtains its own via ACME, or imports NPM's
  ([below](#import-npms-certificates)). Importing copies them; NPM's own files
  stay untouched (they remain the rollback path).
- A dataset for Doorwarden (config, data, traefik-dynamic), e.g.
  `/mnt/<pool>/apps/doorwarden/`.
- Copy `database.sqlite` access: you only need read access to NPM's data
  volume.

## 1. Deploy Doorwarden + Traefik on alternate ports

NPM keeps 80/443. Set in `deploy/.env`:

```
TRAEFIK_HTTP_PORT=8080
TRAEFIK_HTTPS_PORT=8443
```

Deploy `deploy/compose.truenas.yml` as described in [deploy.md](deploy.md).
Keep `settings.dry_run: true` and the staging issuer (the default) for now.
Add the static route for Doorwarden's own UI, and use the loopback port for the
UI while dry run is on ([deploy.md](deploy.md#first-run)).

## 2. Run the importer

The importer never reads NPM's database in place: by default it takes a
snapshot copy (database plus any `-wal`/`-shm` files) into a private `0700`
temp directory named `doorwarden-npm-*`, reads the copy, and removes it on
exit or on SIGINT/SIGTERM. The original directory is not touched, so a
read-only mount is fine. The copy contains NPM's data, including credentials:
if the process is killed with `-9` the directory can be left behind in the
temp directory (`/tmp`); delete any `doorwarden-npm-*` directory you find.
`--no-copy` exists but is unsafe (SQLite may create sidecar files next to
NPM's database); it is refused when `-wal`/`-shm` files exist or the
directory is not writable.

The importer is advisory and read-only: it never changes NPM or Doorwarden.
Against a live NPM the copy is verified (source size/mtime compared before and
after, then `PRAGMA quick_check`) and retried up to 3 times; the safest run is
with NPM briefly stopped or quiesced, and a rerun is cheap. If it reports that
the database kept changing or is corrupt, stop NPM briefly or copy its data
directory while it is stopped and point `--db` at that copy.

The image is distroless (no shell), so run the subcommand directly, mounting
NPM's data volume read-only. `--config` reads the Doorwarden config to know
your zones, and the config's `${VAR}` placeholders must resolve: pass the same
variables with `-env-file` (lines of `KEY=VALUE`, such as `deploy/.env`; lands
with the final-fix wave):

```
docker run --rm \
    -v <npm-data>:/npm:ro \
    -v <dataset>/config:/config:ro \
    -v <dataset>/.env:/run/doorwarden.env:ro \
    ghcr.io/ajthom90/doorwarden:<tag> \
    import-npm --db /npm/database.sqlite \
    --config /config/doorwarden.yaml -env-file /run/doorwarden.env \
    --discovered /config/discovered.json
```

`<npm-data>` is the host directory of NPM's `/data` volume (the one holding
`database.sqlite`), `<dataset>` the directory with Doorwarden's `config/`.
Without `--discovered`, leave that flag out.

Add `--yaml` for the paste-ready entries. Hosts with an access list, hosts
disabled in NPM and hosts with custom nginx config are never emitted as live
YAML; they appear as `# SKIPPED <domain>: <reason>` comments.

`discovered.json` (optional; live discovery wiring is part of the control
plane itself) is a JSON array of what Doorwarden already discovers:

```json
[
  {"key": "truenas:myapp", "name": "myapp", "host": "192.0.2.10", "port": 30001},
  {"key": "docker:web",    "name": "web",   "host": "192.0.2.10", "port": 8081}
]
```

A `truenas:` key classifies a matching NPM host as `auto`, a `docker:` key as
`label`; anything else is `static`. Nothing is applied automatically.

## 3. Review the mappings table

Columns: Domain | Class | Target | Flags. Go through every flag:

| Flag | What to do |
| --- | --- |
| custom nginx config present | Not translated. Read it in NPM and decide: drop it, or express it as a Traefik middleware in the Doorwarden config. |
| access list attached | Re-create as a middleware (e.g. basic auth / IP allowlist) and attach by name. |
| hostname upstream: verify | The forward host is a name, not an IP. Confirm it resolves from Doorwarden's network. |
| off-box upstream IP | Upstream is not the zone's target IP; confirm it is reachable from the Traefik container. |
| https upstream | NPM does not verify upstream certificates; the suggested entry sets `skip_verify: true`. |
| per-host certificate / outside configured zones | Doorwarden issues certificates for its configured zones only. |
| ssl_forced off | NPM also served plain HTTP; Doorwarden redirects HTTP to HTTPS. |
| domain outside configured zones - no zone | Add the zone or leave that host in NPM. |

Streams (raw TCP/UDP), redirection hosts and 404 hosts are counted but not
imported; handle them separately.

Use `--yaml` to get paste-ready `static:` entries for the `static` class, and
add them to the config.

### Import NPM's certificates

NPM keeps its Let's Encrypt certificates (including wildcard ones) under
`live/npm-<N>/` of its `letsencrypt` volume. Importing them lets Doorwarden
serve valid production certificates from the cutover on, without new orders;
it renews them itself when they come due. Run it with Doorwarden stopped, as
the Doorwarden user, with its data and certificate directories mounted (lands
with the final-fix wave):

```
docker run --rm --user 65532:65532 \
    -v <npm-letsencrypt>:/npm-le:ro \
    -v <dataset>/config:/config:ro \
    -v <dataset>/data:/data \
    -v <dataset>/certs:/data/certs \
    ghcr.io/ajthom90/doorwarden:<tag> \
    certs import-npm -npm-dir /npm-le/live -dry-run
```

Mount the whole `letsencrypt` volume, not only `live/`: the files in `live/`
are links into `archive/`. `-npm-dir` is either that `live/` directory (every
`npm-*` directory in it is imported) or one `npm-<N>` directory. Each
certificate is assigned to the configured zone that contains all its names.
`-dry-run` lists what would be imported; run it again without `-dry-run` to
import. `-db` (default `$DOORWARDEN_DB`, then `/data/doorwarden.db`) and
`-certs-dir` (default `/data/certs`) select where it writes. NPM's files are
only read. A staging issuer never replaces an imported production
certificate.

## 4. Dry run, staging issuer, verify on the alternate port

With dry run on, review the plan on the Services page and in the activity log;
dry run plans and logs every cycle but changes nothing, and the UI refuses
Renew now, Switch to production and Adopt with `409 Conflict` until it is off.
Then turn dry run off (remove `settings.dry_run: true` from the config and
restart, or use the switch on the Settings page if the config does not set
it), keeping the **staging** issuer. Staging certificates are not
trusted by browsers, so verify with `--insecure` (chain checks are skipped;
SAN and expiry are still checked):

```
scripts/verify.sh hosts.txt --resolve 192.0.2.10 --port 8443 --insecure
```

`hosts.txt` is one hostname per line (`#` comments allowed). Expect the
summary to flag `STAGING` issuers. Note that Traefik's HTTP-to-HTTPS redirect
targets the `websecure` entry point (port 443), not the trial's published
8443: during the trial a redirect from :8080 points at :443, which is still
NPM. Test the trial with `https://` and `--port 8443` directly, as above, not
by following redirects. Fix every FAIL before continuing.

When satisfied, switch to production **from the UI**: on the Certificates
page choose **Switch to production...** and confirm (or
`POST /api/v1/certs/switch-production` with
`{"issuer": "<issuer>", "confirm": true}`, which needs an administrator session
and the CSRF header). This re-issues every staging certificate from the
production CA. Only editing `directory: production` in the config and
restarting does **not** re-issue existing staging certificates, so the
cutover would still serve staging certificates. After the switch, set
`directory: production` in the config too
([cert-troubleshooting.md](cert-troubleshooting.md#from-staging-to-production)).
Wait until the certificates are issued, then re-run `verify.sh` without
`--insecure`: the issuer should no longer be STAGING and every host must
pass.

## 5. Cutover

Each step below changes TrueNAS state. Show the command/action to the
operator and wait for confirmation before running it.

1. Announce a short window. Confirm Doorwarden's plan is clean. Make sure
   the TrueNAS web interface no longer uses 80/443 (it does by default; see
   [deploy.md](deploy.md#layout)), and that you know the port it moved to.
2. **Stop the NPM app** (do not delete it; keep its dataset and config).
3. Change Traefik's published ports from 8080/8443 to 80/443 (edit
   `TRAEFIK_HTTP_PORT` / `TRAEFIK_HTTPS_PORT` in the app's environment) and
   redeploy the Doorwarden app.
4. Run `scripts/verify.sh hosts.txt --resolve 192.0.2.10` (port 443). All
   hosts must pass.
5. Spot-check a few services in a browser, including websockets and any
   authenticated services.

If anything is wrong, follow [rollback.md](rollback.md) immediately.

## 6. After cutover

Keep NPM **stopped but intact for at least a week**. Stopping NPM touches no
DNS record or certificate, so rollback stays a short operation
([rollback.md](rollback.md)). Only after that period, and a clean renewal observation if
possible, consider archiving NPM.
