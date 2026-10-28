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

## Provider notes

| type | records | wildcard A | TTL | IDs | notes |
|---|---|---|---|---|---|
| cloudflare | all via API | yes | yes | yes | token needs Zone:Read + DNS:Edit; records never proxied |
| route53 | A/AAAA/CNAME/TXT sets | yes | yes | no | zone auto-discovery by longest suffix; public preferred; private zone only with `hosted_zone_id`; empty keys use the default AWS credential chain |
| rfc2136 | A/AAAA/CNAME/TXT | yes | yes | no | TSIG mandatory; listing is AXFR, so the server needs `allow-transfer` for the key |
| unifi | A writes; any type listed | only with `wildcard: true` | yes | yes | Integration API DNS policies; set `wildcard: true` only after confirming your controller accepts `*.zone` policies; site auto-discovery (`default` or the only site) |
| technitium | A/AAAA/CNAME/TXT | yes | yes | no | token or username+password |
| pihole | A/AAAA | no (dnsmasq `address=/.zone/ip` is not manageable through the API) | no | no | v6 API; session re-auth; call `Close()` to end the session |
| adguard | A/AAAA/CNAME rewrites | yes | no | no | basic auth; update falls back to add+delete on old servers |
