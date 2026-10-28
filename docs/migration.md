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
- Certificates: Doorwarden obtains its own via ACME. Keep NPM's certificates
  untouched (they remain the rollback path).
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

## 2. Run the importer

The importer opens NPM's database read-only. Use `--copy` while NPM is
running (it works on a temporary copy and removes it afterwards):

```
doorwarden import-npm --db /path/to/npm-data/database.sqlite --copy \
    --config /config/doorwarden.yaml --discovered discovered.json
```

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

Wildcard certificates in NPM live under `letsencrypt/live/npm-<N>/` inside
NPM's data volume; the importer lists them. A `doorwarden certs import-npm
DIR` command to import them is planned by the ACME work (TODO: not yet
available); until then Doorwarden issues its own.

## 4. Dry run, staging issuer, verify on the alternate port

With `dry_run: true` review the plan Doorwarden reports. Then set
`dry_run: false` with the **staging** issuer. Staging certificates are not
trusted by browsers, so verify with `--insecure` (chain checks are skipped;
SAN and expiry are still checked):

```
scripts/verify.sh hosts.txt --resolve 192.0.2.10 --port 8443 --insecure
```

`hosts.txt` is one hostname per line (`#` comments allowed). Expect the
summary to flag `STAGING` issuers. Fix every FAIL before continuing.

When satisfied, switch the issuer to production, let certificates issue, and
re-run `verify.sh` without `--insecure`: the issuer should no longer be
STAGING and every host must pass.

## 5. Cutover

Each step below changes TrueNAS state. Show the command/action to the
operator and wait for confirmation before running it.

1. Announce a short window. Confirm Doorwarden's plan is clean.
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

Keep NPM **stopped but intact for at least a week**. DNS records and
certificates are untouched by stopping NPM, so rollback stays a two-step
operation. Only after that period, and a clean renewal observation if
possible, consider archiving NPM.
