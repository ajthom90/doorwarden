# DNS providers

Doorwarden uses DNS providers for two separate jobs:

1. **Record providers** (`zones[].records.provider`) create the A/AAAA records
   that point published host names at Traefik. Seven types are built in.
2. **ACME challenge providers** (`zones[].certificate.dns_provider`) publish the
   temporary `_acme-challenge` TXT records for DNS-01 certificate validation.
   These come from lego's catalog of about 190 providers and are configured
   [separately](#acme-dns-01-challenge-providers).

Both are entries under the top-level `providers:` map; the zone setting that
references an entry decides how it is used.

- [Record providers](#record-providers)
- [How Doorwarden owns records](#how-doorwarden-owns-records)
- [ACME DNS-01 challenge providers](#acme-dns-01-challenge-providers)
- [Adding a record provider](#adding-a-record-provider)

## Record providers

| Type | Wildcard A | Writable record types | Settings |
|---|---|---|---|
| `cloudflare` | yes | A, AAAA, CNAME, ... | `api_token` |
| `route53` | yes | A, AAAA, CNAME | `access_key_id`, `secret_access_key`, `region`, `hosted_zone_id` |
| `rfc2136` | yes | A, AAAA, CNAME | `server`, `key_name`, `key_secret`, `algorithm` |
| `technitium` | yes | A, AAAA, CNAME, TXT | `url`, `token` or `username` + `password` |
| `adguard` | yes | A, AAAA, CNAME | `url`, `username`, `password` |
| `unifi` | only with `wildcard: true` | A | `url`, `api_key`, `site_id`, `wildcard` |
| `pihole` | no | A, AAAA | `url`, `password` |

`records.mode: wildcard` needs a type with wildcard support; with `pihole` use
`per-host`. Unknown keys are refused (a typo such as `wildcrd` is an error, not
ignored). Boolean settings accept `true`/`false` and the strings `"true"`/
`"false"`. Use `${VAR}` for every credential.

Self-hosted types (`technitium`, `adguard`, `unifi`, `pihole`) also take
`insecure_skip_verify` (accept a self-signed certificate) and
`allow_insecure_http`. Plain `http://` is accepted without
`allow_insecure_http` only for loopback, private (RFC 1918, ULA) and
link-local addresses and for single-label host names such as `nas`. The
hosted types (`cloudflare`, `route53`) have no URL setting, so a config edit
can never send their credentials to another host.

Implementation notes per type (record identity, multi-value sets, how
ambiguous writes are handled) are in
[internal/dns/providers/README.md](../internal/dns/providers/README.md#provider-notes).

### cloudflare

```yaml
providers:
  cloudflare:
    type: cloudflare
    api_token: ${CF_API_TOKEN}
```

Minimum permissions: an API token with **Zone: Read** and **DNS: Edit**,
restricted to the zones Doorwarden manages. Records are created unproxied
(DNS only). The same entry can also be the zone's `certificate.dns_provider`
(`api_token` is mapped to lego's Cloudflare token).

### route53

```yaml
providers:
  aws:
    type: route53
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}
    # region: us-east-1        # signing region; Route 53 is global
    # hosted_zone_id: Z0123456789EXAMPLE
```

Leave both key settings empty to use the default AWS credential chain
(environment, shared config, IAM role); set both or neither. The hosted zone is
found by the longest matching suffix, preferring a public zone; a private zone
is used only when pinned with `hosted_zone_id`, which also refuses every other
zone. Minimum IAM permissions: `route53:ListHostedZones`,
`route53:GetHostedZone`, `route53:ListResourceRecordSets` and
`route53:ChangeResourceRecordSets` (the last three can be limited to the
hosted zone's ARN). Unlike the other types, route53 uses the AWS SDK's HTTP
client, so it honours `HTTPS_PROXY` and `AWS_ENDPOINT_URL*` from the
environment.

### rfc2136

```yaml
providers:
  bind:
    type: rfc2136
    server: 192.0.2.53:53      # TCP; port defaults to 53
    key_name: doorwarden
    key_secret: ${TSIG_SECRET} # base64
    # algorithm: hmac-sha256   # hmac-sha1|-sha224|-sha256|-sha384|-sha512
```

For BIND, Knot, PowerDNS and other servers that accept dynamic updates. TSIG is
mandatory and every reply must be signed. Doorwarden lists the zone with AXFR,
so the key needs both **update** permission for the zone (for example
`update-policy { grant doorwarden zonesub ANY; };` in BIND) and
**allow-transfer**.

### technitium

```yaml
providers:
  technitium:
    type: technitium
    url: https://dns.example.test:53443
    token: ${TECHNITIUM_TOKEN}
```

An API token (preferred) or `username` + `password`. The user needs permission
to view and modify the zones Doorwarden manages.

### adguard

```yaml
providers:
  adguard:
    type: adguard
    url: http://192.0.2.3:3000
    username: admin
    password: ${ADGUARD_PASSWORD}
```

Uses AdGuard Home DNS rewrites. The account is the AdGuard Home web login
(AdGuard Home has no finer permissions).

### unifi

```yaml
providers:
  unifi:
    type: unifi
    url: https://192.0.2.1
    api_key: ${UNIFI_API_KEY}
    insecure_skip_verify: true   # gateways use self-signed certificates
    # site_id: ...               # auto: the "default" site, or the only site
    # wildcard: true             # only after checking your controller accepts *.zone
```

Uses the UniFi Network Integration API (DNS policies) with an API key created
in the Network application. Wildcard A records are off unless `wildcard: true`;
writes, wildcard and IPv6 policies have not been verified against a real
controller (see the [maturity notes](../README.md#status-and-maturity)).

### pihole

```yaml
providers:
  pihole:
    type: pihole
    url: http://192.0.2.2
    password: ${PIHOLE_PASSWORD}
```

Pi-hole v6 API (local DNS records). Use the web interface password or an
application password. Pi-hole cannot hold wildcard records through its API and
has no per-record TTL.

### Testing a provider

`POST /api/v1/dns/providers/{name}/test` ("Test credentials" on the DNS page)
checks that a record provider is reachable and its credentials work, without
writing anything. Challenge-only entries have no test; a certificate order is
their test (use the staging issuer).

## How Doorwarden owns records

Doorwarden keeps an ownership row in its database for every record it creates
(provider, zone, name, type, value, and the service that owns it). It only
ever updates or deletes records it owns.

- **Foreign records are never touched.** When a record Doorwarden does not
  own already exists at a host name (same type, or a CNAME), the service gets a
  DNS conflict instead of a write, even when the existing value is already
  right. The route and certificate still proceed.
- **Adopt or skip.** On the DNS page ("Adopt" / "Ignore", or
  `POST /api/v1/dns/conflicts/{id}/adopt` and `.../skip`) you either *adopt*
  the record (Doorwarden takes ownership and
  manages it from then on; only A and AAAA records can be adopted, remove a
  CNAME at the provider yourself) or *skip* the conflict (stop reporting it;
  Doorwarden still does not write). Adopting is refused with `409` while dry
  run is on; skipping is allowed.
- **Grace-period deletion.** When a service disappears, is unpublished or is
  renamed, its record is scheduled for removal after `settings.grace_period`
  (default 24h). If it comes back within the grace period, the removal is
  cancelled. Only the exact stored record (name, type and value) is deleted.
- **Outages do not delete.** While a source is unavailable (TrueNAS API down,
  Docker proxy unreachable), its services count as unknown, not gone, so
  nothing is scheduled for removal. A failed provider listing means no new
  records are created in that zone during that cycle.
- **The wildcard record is never removed automatically.**
- **Drift.** If an owned record is changed out of band, Doorwarden reports it
  and does not overwrite it. If an owned record goes missing, it is
  re-created, at most 5 per zone and cycle, with backoff from 1 minute
  doubling to 1 hour per record.
- **Mass-repair breaker.** If more than 3 of a zone's owned records are missing
  and they are more than half of them, Doorwarden assumes the provider or zone
  configuration is wrong (a wiped Pi-hole, a wrong hosted zone), repairs
  nothing, and alerts. If the records really are gone, acknowledge once
  ("Acknowledge and allow repair" on the DNS page, or
  `POST /api/v1/dns/repair/ack` with `{"provider": "...", "zone": "..."}`);
  the acknowledgement is valid for 24 hours and repairs then proceed with the
  usual cap. See [operations.md](operations.md#mass-repair-breaker).
- **Dry run** lists records (read-only) but never writes.

## ACME DNS-01 challenge providers

`certificate.dns_provider` names a `providers:` entry whose `type` is a
[lego DNS provider code](https://go-acme.github.io/lego/dns/) (`cloudflare`,
`route53`, `rfc2136`, `technitium`, `gandiv5`, `ovh`, `duckdns`, ...). Every lego
provider is available except `manual` and `exec`. `unifi`, `pihole` and
`adguard` cannot serve challenges.

Every other key of the entry is a lego setting, written as lego's environment
variable name, case-insensitive with `-` read as `_` (`cf_dns_api_token`,
`AWS_ACCESS_KEY_ID`). `<VAR>_FILE` (a path to a file holding the value) is
accepted for every variable. Keys lego does not document for that provider are
ignored (logged at debug level, values never logged). lego reads its settings
from the process environment, so Doorwarden sets them under a lock only while
it builds the lego provider and then restores the previous environment (for
`oraclecloud` and `namecheap`, which read them later, for the whole order).
See each provider's page on the lego site for its variables; for example the
lego `rfc2136` provider uses `DNSUPDATE_*` names, not the record provider's
keys.

```yaml
zones:
  - name: example.test
    target_ip: 192.0.2.10
    records: {provider: pihole, mode: per-host}
    certificate:
      issuer: letsencrypt
      dns_provider: acme-dns          # challenges at a different provider

providers:
  pihole:
    type: pihole
    url: http://192.0.2.2
    password: ${PIHOLE_PASSWORD}
  acme-dns:
    type: route53
    AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}
    AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}
    AWS_REGION: us-east-1
    AWS_HOSTED_ZONE_ID: Z0123456789EXAMPLE
```

Sharing one entry between `records.provider` and `certificate.dns_provider`
works only for `cloudflare`, where the record provider's `api_token` is also
accepted as lego's `CLOUDFLARE_DNS_API_TOKEN`. For every other type, record
providers refuse lego's variable names, so define two entries (as `route53`
above), one per job.

DNS-01 needs a public DNS zone that Let's Encrypt can query: a LAN-only server
(Pi-hole, AdGuard, UniFi) cannot validate certificates, which is why they are
record-only.

## Adding a record provider

A record provider is one package that registers itself. The full contract
(identity rules, secret handling, ambiguous writes) is in
[internal/dns/providers/README.md](../internal/dns/providers/README.md#adding-a-provider);
the files you touch are:

1. `internal/dns/providers/<type>/<type>.go`: the implementation, calling
   `dns.Register(Type, factory, schema, staticCaps)` from `init()`. Declare
   every setting in the schema (unknown keys are rejected) and read secrets
   with `dns.ResolveField`.
2. `internal/dns/providers/all.go`: add the blank import (the in-memory test
   provider in `internal/dns/providers/fake` is deliberately not imported
   there, so the server rejects `type: fake`; tests import it directly).
3. `internal/dns/providers/all_test.go`: add the type to the `want` list of
   `TestAllTypesRegistered` and a configuration to `leakConfigs` (the test formats every provider
   with every verb to prove no credential leaks).
4. `internal/dns/providers/<type>/<type>_test.go`: run the conformance suite
   against a fake backend you start in the test (`httptest` or an in-process
   DNS server, never a real service):

   ```go
   dnstest.RunWith(t, func(*testing.T) dns.Provider { return p },
       dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
   ```

   plus tests for error mapping (401/403, 404, 429), cancellation, the
   capabilities the instance reports, and that a recognizable fake secret
   never appears in an error.
5. If the type cannot solve ACME challenges, add it to `recordOnlyTypes` in
   `internal/config/validate.go`.
6. Document the type in this file and in the provider notes table of
   `internal/dns/providers/README.md`.

Run `go test ./internal/dns/... -race` before opening a pull request. ACME
challenge providers need no code: they come from lego's catalog.
