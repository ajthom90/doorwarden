# Security model

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What Doorwarden can do, and what it is trusted with

Doorwarden decides which of your services are reachable through Traefik and
what DNS says about them. Whoever controls it can publish an internal service,
point a host name elsewhere, or issue certificates for your zones. It holds:

- DNS provider credentials (from the environment, referenced as `${VAR}`);
- the TrueNAS API key and read access to the Docker API (through the socket
  proxy);
- ACME account keys (in the database, encrypted with `DOORWARDEN_MASTER_KEY`)
  and TLS private keys (files, mode `0600`, readable by Traefik);
- the administrator's password hash and sessions.

## Threat model

| Threat | Mitigation |
|---|---|
| A container or app is exposed that should not be | Docker requires an explicit `doorwarden.enable=true` label; TrueNAS apps wait for approval by default; dry run shows the plan before anything changes |
| A mistake deletes DNS records you own | Doorwarden only modifies records it created or you adopted; removal waits for the grace period; source outages never count as removal; the wildcard record is never removed automatically; a mass-repair breaker stops on implausible listings ([providers.md](providers.md#how-doorwarden-owns-records)) |
| A missing or mistyped auth middleware exposes a service | middlewares fail closed: the service gets no new route, and an existing route keeps the middlewares it was written with ([labels.md](labels.md#middlewares)) |
| Untrusted certificates or CA lockout by accident | issuers default to Let's Encrypt staging; switching to production is an explicit, confirmed action; rate limits below Let's Encrypt's own ([cert-troubleshooting.md](cert-troubleshooting.md#rate-limits-and-backoff)) |
| The Docker socket is used to take over the host | Doorwarden makes one call (`GET /containers/json?all=1`) through an allowlisting proxy on an internal network ([below](#docker-socket-proxy)) |
| Password guessing against the UI | argon2id, per-address and per-name throttling, a global per-name budget ([below](#authentication)) |
| Cross-site requests from a browser that is logged in | `SameSite=Strict` cookie, a CSRF header on every state change, an `Origin` check, JSON-only bodies |
| Credential leaks through logs, errors or the config editor | secrets are typed values that print as redacted; provider errors are scrubbed; the config editor masks secrets and refuses to send a kept secret to a new destination |
| A config edit redirects a credential to another host | hosted DNS providers have no URL setting; plain-HTTP URLs only for private addresses unless explicitly allowed; redirects to another host are refused |

Out of scope: an attacker with a shell on the host, root in a container that
shares Doorwarden's volumes, or control of the DNS provider account. The
master key and the TLS keys are on the same host as the data they protect;
the encryption is against copies of the database (backups), not against the
host.

## Authentication

- **One administrator**, created at first run with the setup token Doorwarden
  logs at start-up (`docker logs <container>`). The token is 192-bit random,
  changes on each restart until setup is done, and setup is refused once an
  administrator exists. Passwords must have at least 12 characters.
- **Password hashing**: argon2id with 64 MiB memory, 3 passes, 2 lanes, a
  16-byte salt and a 32-byte key.
- **Sessions**: cookie `__Host-doorwarden_session` (HttpOnly, Secure,
  SameSite=Strict, path `/`), expiring after `web.session_idle` (8h) without
  use and `web.session_max` (7 days) in all. Logout and a password change end
  sessions on the server.
- **CSRF**: every state-changing request needs the `X-Doorwarden-CSRF` header
  (the token returned by login, setup and `GET /api/v1/auth/me`), a JSON body
  and an `Origin` matching the request's host or `web.allowed_origins`.
- **Throttling**: after 5 failures a (user name, client address) pair waits 30
  seconds, doubling up to 15 minutes; an address failing for 20 different user
  names is backed off the same way. IPv6 addresses count per /64.
- **Residual risk (accepted)**: an attacker rotating through many fresh
  addresses is still bound by one budget per user name of 30 attempts plus 30
  per minute: at most about 1830 guesses an hour, 43,000 a day. Each guess is an
  argon2id check, and with a random password of 12 or more characters that
  is far from enough. Five attempts of that budget are reserved for addresses
  without failures, so an attack cannot lock the real administrator out (at
  worst a login waits up to 5 seconds). Use a long random password, and do
  not publish the UI to the internet unless it sits behind another
  authentication layer.
- **Roles**: the administrator can do everything. Header-authenticated users
  (below) get `viewer` (read-only; every state-changing request answers 403)
  unless `web.trusted_header.role: admin`. The config editor is
  administrator-only.
- **Security headers** on every response: a strict `Content-Security-Policy`
  (`default-src 'self'`, no framing), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.

Everything except `/healthz`, `/api/v1/auth/status`, login and first-run setup
requires a session, including `/metrics` and the event stream.

### Recovering access

With a shell on the host (the image has no shell and the binary is not on
`PATH`, so call it as `/doorwarden`; find the container name with `docker ps`,
for the provided compose file it is `<project>-doorwarden-1`):

```
docker exec <container> /doorwarden admin unlock
docker exec <container> /doorwarden admin reset-password [-user admin]
```

`unlock` ends every session and clears all login limits. `reset-password` also
sets a new random password, prints it once on the terminal (it is never
logged), and creates the administrator if there is none. Both work on the
database (`-db`, default `$DOORWARDEN_DB` or `/data/doorwarden.db`) while the
server runs. They refuse to run as a user other than the database file's owner
(for example `docker exec -u 0`), because SQLite's `-wal`/`-shm` files would
then belong to that user and lock the server out; `-allow-owner-mismatch`
overrides.

## Reverse proxy settings

### `web.trusted_proxies`

Throttling, audit entries and logs use the client address. Behind Traefik
the TCP peer is always Traefik, so without this setting every client shares
one address, and one client's failed logins slow down everyone's. Set it to
the network Traefik reaches Doorwarden from (for the provided compose file,
the subnet of the shared `default` network:
`docker network inspect <project>_default --format '{{(index .IPAM.Config 0).Subnet}}'`).

When the peer is in the list, the client is the rightmost `X-Forwarded-For`
address that is not itself a trusted proxy; anything further left was written
by the client and is ignored. This setting only identifies the client, it
never authenticates anyone. Doorwarden warns in its log when it runs in a
container with the setting empty, and when `X-Forwarded-For` arrives while it
is empty.

### `web.trusted_header`

For single sign-on through a forward-auth proxy (Authelia, Authentik, oauth2-proxy
behind Traefik). With `web.trusted_header.proxies` set, a request whose **TCP
peer** is in those CIDRs is authenticated as the user named in
`web.trusted_header.user_header` (default `Remote-User`), with
`web.trusted_header.role`. `X-Forwarded-For` is never used for this decision,
and the header is stripped from every other peer.

Rules for using it safely:

- List only the proxy that sets the header, as narrowly as possible (a single
  address, not the whole Docker network, if other containers share it).
- That proxy must overwrite any copy of the header sent by the client.
- Every route to Doorwarden's port must go through that proxy; if another
  container on the listed network can reach Doorwarden directly, it can claim
  any user.
- Prefer `role: viewer` and keep the local administrator for changes.

## Docker socket proxy

Access to the Docker API is root on the host for anything beyond reading. A
read-only (`:ro`) bind mount of the socket does not limit API calls. The
compose file therefore puts `wollomatic/socket-proxy` in front of the socket:
it allows only `GET` on `/containers/json`, only from the `doorwarden`
container, on an internal network no other container joins. Container
inspect (other containers' environment variables, often secrets), `/archive`,
logs, exec and every write are refused. Details and how to verify the
allowlist are in [deploy.md](deploy.md#docker-api-access).

## Secrets handling

- Credentials are read from the environment with `${VAR}`, or stored in the
  database sealed with the master key and referenced as `secret:<name>`
  (`doorwarden admin secret set`, which reads the value from standard input
  or a prompt, never the command line;
  [configuration.md](configuration.md#secrets-and-the-master-key)). Nothing in
  the config file needs to be secret.
- Inside Doorwarden secrets are a distinct type whose formatted value is
  redacted; DNS provider errors are scrubbed of credentials, and providers are
  tested to never print a credential with any formatting verb.
- `GET /api/v1/config` returns the config with every secret replaced by
  `<masked>`. A masked value saved back keeps the current secret only for the
  same entry and only while its destination (URL, host, server, type, port)
  is unchanged; `DOORWARDEN_*` variables can never be referenced from the
  editor ([deploy.md](deploy.md#editing-the-config-from-the-ui)).
- ACME account keys are sealed with AES-256-GCM under a key derived (HKDF-SHA256)
  from `DOORWARDEN_MASTER_KEY`. Losing the master key means re-registering ACME
  accounts; leaking it together with a database copy exposes those keys.
- HTTP clients for self-hosted providers ignore `HTTP(S)_PROXY`, bound
  response sizes and refuse redirects to another host. `route53` uses the AWS
  SDK, which honours the standard AWS environment variables.

## Container hardening

The provided compose file runs every container with `read_only: true`,
`cap_drop: [ALL]` and `no-new-privileges`. The Doorwarden image is distroless
(no shell), runs as UID/GID 65532, and publishes no host port; only Traefik
publishes 80 and 443. Doorwarden's own UI is reached through Traefik.
