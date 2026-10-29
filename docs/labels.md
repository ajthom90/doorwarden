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

When two services claim the same host name, the higher-ranked source wins
(static, then TrueNAS, then Docker) and the other is reported as a conflict.

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
service at `<target_ip of the default zone>:<published host port>`, not on a
Docker network. For example:

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
(`no published host port`). A stopped container stays listed as stopped: its
route and records are kept, so a restart never causes churn.

Two containers with the same `doorwarden.name` are both reported and the
conflict is resolved like any other host name conflict.

## TrueNAS apps

With `sources.truenas` set, Doorwarden calls the TrueNAS JSON-RPC API
(`app.query`, read-only) every poll interval. Each installed app becomes a
service named after the app:

- The backend is `<target_ip of the default zone>:<portal port>`. The portal
  named `Web UI` is used when present, otherwise the first portal in name
  order. The portal's host is ignored, its scheme (`http`/`https`) and port
  are used.
- An app that is not `RUNNING` is listed as stopped; its route and records are
  kept.
- A running app without a usable portal is in the error state; publish it with
  a static entry instead.
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
within the grace cancels the removal. In `approve` mode, a rename or
skip-verify change needs a new approval.

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
