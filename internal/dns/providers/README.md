# DNS providers

A provider is one package under `internal/dns/providers/<type>/` that registers
itself from `init()`.

## Adding a provider

1. Create `internal/dns/providers/<type>/<type>.go`:

   ```go
   func init() {
       dns.Register(Type, factory, dns.ConfigSchema{Fields: []dns.Field{
           {Name: "url", Required: true},
           {Name: "token", Secret: true, Required: true},
       }}, staticCaps)
   }
   ```

   - Read every `Secret: true` field with `dns.ResolveField(cfg, sr, name)`;
     it handles literals, `secret:<ref>` references and a nil resolver. Keep the
     result as `secrets.Secret` and never put config values in error text.
   - `staticCaps` is an upper bound for config validation. The constructed
     instance's `Capabilities()` is authoritative and may be narrower.
   - Identity contract (see `dns.Record`): if `ID` is set it wins; otherwise
     Update targets `(name, type)` and Delete targets exact `(name, type, value)`.
     A Delete that matches nothing returns nil and never touches a record with a
     different value. Providers without record IDs return empty `ID` and treat a
     non-empty ID on Update as `dns.ErrNotFound`.
2. Add a blank import to `internal/dns/providers/all.go` (and the type name to
   `all_test.go`).
3. Test with the conformance suite against a fake backend you build in the test
   (`httptest` server or in-process DNS server), never a real service:

   ```go
   dnstest.RunWith(t, func(*testing.T) dns.Provider { return p },
       dnstest.Options{Zone: "example.test", OtherZone: "other.test"})
   ```

   `RunWith` requires `Zone`. Also test: error mapping (401/403, 404 zone,
   429), that a recognisable fake secret never appears in any error string,
   context cancellation, and the capabilities your instance reports.

## Credentials in provider structs

fmt prints struct fields by reflection, dereferencing pointers and ignoring
`String`/`Format` methods behind unexported fields, so a secret stored anywhere
reachable from a Provider can leak (`%s` of a dereferenced copy, a struct
containing the provider, a log line). Therefore a Provider keeps **no
secret-bearing value reachable by reflection**: tokens, passwords, TSIG
secrets, session ids, derived `Authorization` strings, scrub lists and SDK
clients that embed credentials live only inside closures (func-typed fields
print as addresses). Use `dns.StaticSecret`, `dns.SecretCell`, `dns.Scrubber`
and `httpx.Client.AddSecret`; mutexes are pointers (so `go vet` copylocks stays
quiet when the struct is copied); give the Provider value-receiver `String`,
`GoString` and `Format` that call `dns.RedactedFormat`. `all_test.go` formats
every provider with every verb and walks it by reflection; add your type to
`leakConfigs`.

## Security rules for provider URLs

- Providers for a fixed public SaaS endpoint (cloudflare, route53) do **not**
  accept an endpoint in user config; the API base URL is a Go-level constructor
  option for tests only. A config edit must never be able to redirect a bearer
  token to another host.
- Providers for self-hosted servers (unifi, technitium, pihole, adguard) take a
  `url`. `httpx.CheckURL` requires http(s), a host and no userinfo. **Plain
  http** is accepted only for loopback, private (RFC 1918/ULA), link-local IPs
  and dot-less host names (`nas`, `localhost`); any other host needs
  `allow_insecure_http: true`. Prefer https; self-signed gateways can use
  `insecure_skip_verify: true`.
- `httpx.Client` never uses `HTTP(S)_PROXY`, bounds responses (4 MiB), applies a
  10 s default timeout, refuses redirects to a different host or scheme (so
  credential headers are never forwarded), and scrubs configured secrets from
  error text.

## ACME challenge providers

The record providers here manage A/AAAA/CNAME records for published services.
They are **never** ACME DNS-01 challenge providers: route53, pihole, adguard and
unifi cannot (or, for route53, are not made to) publish `_acme-challenge` TXT
records through `dns.Provider`. Certificate issuance uses lego's own DNS
provider catalog, configured separately from these providers.

## Config keys

`dns.New` takes the provider's own settings (`config.ProviderCfg.Extra`; do not
pass a map that still contains `type`). Boolean options accept real bools and
the strings `"true"`/`"false"` (case-insensitive), which is what environment
substitution produces.

`dns.New` rejects config keys that are not declared in the provider's schema
(the error names the key and lists the valid ones), so a typo such as
`wildcrd: true` can never silently change behaviour. Declare every key your
factory reads in `ConfigSchema`; read boolean options with `httpx.BoolOption`,
which accepts bools and the strings `"true"`/`"false"` and errors on anything
else.

## Network behaviour

- Hand-written HTTP providers (cloudflare, unifi, technitium, pihole, adguard)
  use `httpx`, which ignores `HTTP(S)_PROXY`/`NO_PROXY`.
- **route53 uses the AWS SDK's default HTTP client and configuration chain**, so
  it *does* honour `HTTPS_PROXY` and the `AWS_ENDPOINT_URL` /
  `AWS_ENDPOINT_URL_ROUTE_53` environment overrides (and the shared AWS config
  file). These are controlled by whoever runs the process, not by dns config,
  and are deliberate: it is how corporate proxies and VPC endpoints work for
  AWS. The config schema still has no endpoint key.
- rfc2136 speaks DNS over TCP directly to `server`.

## Provider notes

Writable types are the ones Create/Update/Delete accept; every provider lists
foreign records of other types read-only where its API exposes them.

| type | writable types | wildcard A | TTL | IDs | notes |
|---|---|---|---|---|---|
| cloudflare | all via API | yes | yes | yes | token needs Zone:Read + DNS:Edit; records never proxied; Update refuses when several records match (name, type) |
| route53 | A, AAAA, CNAME | yes | yes | no | zone auto-discovery by longest suffix; public preferred; a private zone only with `hosted_zone_id`, which binds the provider to that one zone (every other zone is refused); empty keys use the default AWS credential chain; TXT is not writable (quoting not implemented); Update refuses multi-value and alias sets, is a single compare-and-swap change batch, and every response is validated and every write re-read, polling for up to 60s because Route 53 reads may lag a change |
| rfc2136 | A, AAAA, CNAME (TXT listed read-only) | yes | yes | no | TSIG mandatory and every response must be signed; listing is AXFR, so the server needs `allow-transfer` for the key; Update uses RFC 2136 prerequisites; refuses multi-value sets; A is refused where a CNAME exists; the key_secret must be valid base64 |
| unifi | A | only with `wildcard: true` | yes | yes | Integration API DNS policies; other policy types are listed read-only (CNAME, AAAA, FORWARD_DOMAIN...); set `wildcard: true` only after confirming your controller accepts `*.zone` policies; a disabled policy or a CNAME/FORWARD_DOMAIN policy at the same name blocks Create; list pagination fails closed and retries once if totalCount drifts |
| technitium | A, AAAA, CNAME, TXT | yes | yes | no | token or username+password; Update preserves ttl, disabled flag and comments |
| pihole | A, AAAA | no (dnsmasq `address=/.zone/ip` is not manageable through the API) | no | no | v6 API; user CNAMEs (`dns.cnameRecords`, every alias of `alias[,alias],target[,ttl]`) are listed read-only and block an A at the same name; hosts lines naming several hosts are never edited; session re-auth; the provider implements `io.Closer` (ends the session), and since the registry has no lifecycle hook the owner of the Provider should close it |
| adguard | A, AAAA, CNAME | yes | no | no | basic auth; raw rewrite strings are sent back on delete/update; answers `A`/`AAAA` are listed as type `KEEP` and are not writable; update falls back to add+delete on old servers |

## Multi-value record sets

doorwarden manages one value per (name, type). When a provider can hold several
values at the same name (route53, rfc2136, cloudflare, technitium, pihole,
adguard, unifi), Update without an ID **refuses** (wrapping
`dns.ErrRecordExists`) unless exactly one value exists, and Delete removes only
the exact value. The optional conformance case `Options.SeedMultiValue` checks
this against a fake backend.

## Unconfirmed and ambiguous writes

`dns.ErrUnconfirmed` means a write may exist even though the call did not
report plain success: the service accepted it but a verification read did not
show it (route53), or the request was in flight when it timed out, was
cancelled, was cut off or got an unparseable answer. Providers decide with
`httpx.IsDefinitiveRejection` (the server ANSWERED with an error status or API
error: plain error, empty Record) versus everything else (ambiguous: the
attempted Record plus an error wrapping `ErrUnconfirmed`). Create and Update
return the Record so the caller can record ownership; Delete returns the error
so the caller keeps its ownership row. Errors raised before the request is sent
(validation, zone mismatch, dial failure) stay plain.
