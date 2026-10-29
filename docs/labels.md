# Discovery: labels, TrueNAS apps and static routes

Doorwarden publishes a service as `https://<name>.<zone>` through Traefik. A
service comes from one of three sources:

| Source | Key | Opt-in | Default approval |
|---|---|---|---|
| Docker containers | `docker:<container name>` | `doorwarden.enable=true` label | `auto` |
| TrueNAS SCALE apps | `truenas:<app name>` | none (every app is discovered) | `approve` |
| Static entries in the config | `static:<id or slug of name>` | written by you | always `auto` |

The host name is `<slug>.<zone>`, where the slug is the name (or its rename)
lowercased, with every run of characters other than `a-z0-9` replaced by one
`-`, trimmed of `-` and cut to 63 characters. `My App_2` becomes `my-app-2`.

The one exception is a static entry with `apex: true`: its host name is the
zone name itself (`example.test`), it cannot be renamed, and each zone has at
most one (see [configuration.md](configuration.md#apex-entries)). There is no
Docker label or TrueNAS equivalent; a container or app is always published
below the zone. An apex entry outranks a Docker or TrueNAS service claiming
the same name like any static entry.

When two services claim the same host name, see
[Host name conflicts](#host-name-conflicts).

## Host name conflicts

- **Different sources:** the higher-ranked source wins (static, then TrueNAS,
  then Docker), even against a service that already holds the name. The other
  service is reported as a conflict and gets no route.
- **Same source:** the service that already holds the host name (the
  incumbent) keeps it, whatever its state: running, stopped, pending
  approval, quarantined, invalid but still holding its route, or gone but
  still within its grace period. A newcomer from the same source that claims
  the name (for example a second container with the same `doorwarden.name`)
  is reported as a conflict instead of taking over the route and DNS record.
  Only when there is no incumbent do two newcomers tie, and then the one with
  the lower key wins.

Because the incumbent is identified by its key, a change of key looks like a
new service: a container recreated under a new container name, or a static
entry renamed without an `id`. The new key is a conflict until the old one's
route is removed after `settings.grace_period` (24h by default). To avoid the
wait, keep keys stable (give static entries an `id`, give containers a fixed
`container_name`), or rename or unpublish one of the two in the UI.

Resolve a conflict by renaming one of the services (label, static `rename`,
or Rename in the UI).

## Docker labels

Doorwarden lists containers with the Docker Engine API
(`GET /containers/json?all=1`, nothing else) and reads these labels. There are
no other `doorwarden.*` labels.

| Label | Value | Default | Meaning |
|---|---|---|---|
| `doorwarden.enable` | `true` | (required) | opt in. Any other boolean value (`false`, `0`) leaves the container out; a value that is not a boolean is logged as a warning and left out |
| `doorwarden.name` | text | container name | service name, slugged into the host name |
| `doorwarden.port` | 1-65535 | the only exposed TCP port | container (private) port to route to. Required when the container exposes several TCP ports or none |
| `doorwarden.scheme` | `http` \| `https` | `http` | backend scheme |
| `doorwarden.zone` | zone name | `settings.default_zone`, or the only zone | |
| `doorwarden.skip-verify` | boolean | `false` | do not verify the backend's TLS certificate |
| `doorwarden.websockets` | boolean | `false` | informational only; Traefik proxies websockets without extra configuration |
| `doorwarden.middlewares` | comma-separated references | none | see [Middlewares](#middlewares) |

Booleans are parsed like Go's `strconv.ParseBool` (`true`, `false`, `1`,
`0`, `t`, `f`, ...). An invalid label puts the service in the error state
with the reason in the UI; nothing is published for it.

### How the backend is found

The container's port must be **published on the host**. Traefik reaches the
service at `<target_ip of its zone>:<published host port>`, not on a Docker
network. Its zone is the one named by `doorwarden.zone`, else the default
zone. For example:

```yaml
services:
  whoami:
    image: traefik/whoami
    ports:
      - "8081:80"            # published: Traefik connects to 192.0.2.10:8081
    labels:
      doorwarden.enable: "true"
      doorwarden.name: whoami   # https://whoami.example.test
```

A running container whose chosen port is not published is in the error state
(`no published host port`). If the zone has no `target_ip`, the error names it
(`zone example.test (the default zone) has no target_ip: set its target_ip ...`;
for a `doorwarden.zone` label, `zone X has no target_ip (nor does the default
zone) ...`). A stopped container stays listed as stopped: its route and
records are kept, so a restart never causes churn.

There is no Docker network mode: the backend is always `target_ip` plus the
published host port.

**Pin the host port in `approve` mode.** The published host port is part of
what is approved. A port published without a fixed host port (`ports:
["80"]`, or `-P`) gets a new random host port when the container is
recreated, which changes the backend and quarantines the service until it is
approved again ([Approval](#approval)). Publish a fixed host port
(`"8081:80"`, as above), or use `approval: auto` for the docker source.

Two containers with the same `doorwarden.name` are a
[host name conflict](#host-name-conflicts): the one that holds the name keeps
it.

## TrueNAS apps

With `sources.truenas` set, Doorwarden calls the TrueNAS JSON-RPC API
(`app.query`, read-only) every poll interval. Each installed app becomes a
service named after the app:

- The backend is `<target_ip of the app's zone>:<portal port>` (TrueNAS apps
  have no zone label, so that is the default zone). The portal
  named `Web UI` is used when present, otherwise the first portal in name
  order. The portal's host is ignored, its scheme (`http`/`https`) and port
  are used.
- An app that is not `RUNNING` is listed as stopped; its route and records are
  kept.
- Portal ports are checked against the host ports the app actually publishes
  (when TrueNAS reports them): portals on other ports are ignored, and if none
  is left the app is in the error state (`no portal port is one of the app's
  published ports: "Web UI" (port 30001)`; portals are named by name and port
  only, never by URL).
- A running app without a usable portal is in the error state (`no usable
  portal ...`). Set a port for it on the Services page (Port): it then uses
  the default zone's `target_ip` with that port, and still needs approval. Or
  publish it with a static entry.
- With two or more zones and no `settings.default_zone`, every running app is
  in the error state (`no zone: set settings.default_zone`), because apps
  cannot name a zone.
- New apps wait for approval (`approval: approve`, the default). Approve them
  on the Services page ("Review and approve").

The TrueNAS API connection verifies TLS certificates; there is no option to
skip verification. Use a URL whose certificate is trusted by the container
(for example once Doorwarden itself publishes the TrueNAS UI with a valid
certificate), or a plain `http://`/`ws://` URL only on a network you trust,
since the API key is then sent unencrypted.

## Static routes

For anything else (devices, VMs, services on other hosts, Doorwarden's own
UI), add entries under `static:` (reference in
[configuration.md](configuration.md#static)):

```yaml
static:
  - name: doorwarden
    host: doorwarden          # reachable from the Traefik container
    port: 8080
  - name: router
    upstream: https://192.0.2.1
    skip_verify: true
  - name: media
    id: media                 # keeps the key stable if you change name
    host: 192.0.2.40
    port: 8096
    middlewares: [lan-only]
```

Static entries are never approved by hand; removing one from the config
removes its route after the grace period.

## Per-service overrides

| Setting | Docker label | Static key | UI / API |
|---|---|---|---|
| publish / unpublish | (`doorwarden.enable`) | `skip` | Unpublish / publish (`POST /api/v1/services/{key}/unpublish`, `.../publish`) |
| name | `doorwarden.name` | `name`, `rename` | Rename (`POST .../rename`), a lowercase DNS label |
| port | `doorwarden.port` | `port` | Port (`POST .../port`) |
| skip TLS verification | `doorwarden.skip-verify` | `skip_verify` | TLS check (`POST .../skip-verify`) |
| zone | `doorwarden.zone` | `zone` | not available |
| scheme | `doorwarden.scheme` | `scheme` | not available |
| middlewares | `doorwarden.middlewares` | `middlewares` | not available |

UI overrides are stored in the database and win over the config, which wins
over labels. Unpublishing in the UI removes the service like a disappearance:
route and records go after `settings.grace_period`, and publishing again
within the grace cancels the removal.

## Approval

In `approve` mode (the default for TrueNAS) a new service is Pending until an
administrator approves it ("Review and approve" on the Services page). The
approval is bound to what was approved: the host name (name, rename, zone),
the backend (scheme, host and port), skip-verify, websockets and the
middleware list in order.

- **UI overrides keep the approval.** Changing the port, skip-verify or the
  name of an approved service in the UI carries its approval over to the new
  content; the activity log records it (kind `approval`). Nothing that was not
  approved before becomes approved.
- **Changes from the source quarantine the service.** When the source changes
  approved content (a new published host port, a different TrueNAS portal
  port, a label that drops an auth middleware), the service is *quarantined*:
  - its route stops being served at once, while its host name, DNS record and
    certificate are kept, and a same-source newcomer cannot take the name;
  - the Services page shows `backend changed; re-approve to resume: ...` and
    a `service.quarantined` notification is sent (raised every cycle while
    quarantined, sent once per `notifications.dedupe_window`);
  - approving it again resumes serving immediately, with the new content.
  A higher-ranked source can still take the host name, as always. A changed
  host name reserves nothing new: the old name stays reserved, the new one is
  not claimed until it is approved.
- **Switching a source from `auto` to `approve`.** A service that has a route
  but no stored approval is compared with what its route serves:
  - unchanged content is approved automatically (activity log: `service K:
    grandfathered on mode switch ...`, kind `approval`);
  - changed content, or a route that is already quarantined, is quarantined;
  - a service that never had a route is simply Pending.
  The same applies if an approval row is missing for any other reason. There
  is no revoke action in the UI or API yet.
- **Upgrades**: approvals stored by versions before the quarantine change are
  migrated automatically, once (logged as `migrated approval v1->v2`), but
  only when the service's current content is exactly what its route serves
  (host name, backend scheme, host, port and skip-verify, websockets, and the
  middlewares in order). Otherwise, including when the route is gone, the
  service is quarantined (or Pending without a route) and needs one
  re-approval.
- **Dry run writes no approval.** No migration or grandfathering happens in
  dry run: a service that would be migrated or grandfathered is shown as
  Published, and nothing in the activity log or the logs says an approval
  would be written. The write happens at the first cycle once dry run is
  off.

In `auto` mode nothing is ever quarantined.

## Middlewares

A service may list Traefik middlewares by reference:

- `name`: a definition under `middlewares:` in the Doorwarden config
  (see [configuration.md](configuration.md#middlewares)).
- `name@provider`: a middleware defined elsewhere in Traefik (for example
  `authelia@docker`), allowed only when listed in
  `traefik.external_middlewares`.

References match `[A-Za-z0-9_.-]+` with an optional `@provider`. Middlewares
**fail closed**: a service that references an undefined, invalid or
non-allowlisted middleware is invalid and gets no route. If it already had a
route, that route keeps the middlewares it was last written with, so a typo
in an auth label never exposes the service without auth.

## Websockets

Traefik proxies websocket upgrades by default, so no configuration is needed.
`doorwarden.websockets` and the static `websockets` key are accepted and
stored, but they change nothing in the generated Traefik configuration.

## Backends with self-signed certificates

`skip-verify` (label), `skip_verify` (static) or the UI toggle makes Traefik
connect to an `https` backend without verifying its certificate. Only the
load balancers of services with the setting use the shared servers transport
that has `insecureSkipVerify: true`; every other `https` backend is verified.
Use it only for backends on your own network.
