# Certificates: setup and troubleshooting

Doorwarden obtains certificates from an ACME CA (Let's Encrypt by default) with
the [lego](https://go-acme.github.io/lego/) library, writes them to disk and
lists them in Traefik's dynamic configuration. Traefik itself does no ACME.

A zone gets certificates only when it has `certificate.issuer`; see
[configuration.md](configuration.md#zones) for the keys.

## Strategies

| `certificate.strategy` | Certificates | Challenge | Use when |
|---|---|---|---|
| `wildcard` (default) | one per zone: `<zone>` and `*.<zone>` | DNS-01 only | most setups; host names stay out of Certificate Transparency logs and new services need no new order |
| `per-host` | one per published host name | DNS-01 or HTTP-01 | you cannot use DNS-01, or want separate keys per host |
| `san` | one per zone listing every published host name | DNS-01 or HTTP-01 | a few hosts and no wildcard. Re-issued whenever a new host appears; limited to 100 names (the ACME limit), so larger zones need another strategy |

The wildcard covers one level only: `app.example.test`, not
`a.app.example.test`.

HTTP-01 needs `acme.http01_listen` and a Traefik route for
`/.well-known/acme-challenge/` of each host to that address, which you add
yourself (Doorwarden does not generate it), and the hosts must be reachable
from the internet on port 80. DNS-01 needs a challenge provider for a public
zone ([providers.md](providers.md#acme-dns-01-challenge-providers)).

## From staging to production

Issuers default to Let's Encrypt **staging**: real orders against a test CA
whose certificates browsers do not trust ("Fake LE" / "(STAGING)" issuers).
This lets you check DNS, challenges and routing without spending production
rate limits.

1. Run with the staging issuer until every host serves a staging certificate:
   `scripts/verify.sh hosts.txt --insecure` (see [migration.md](migration.md))
   or the Certificates page.
2. Switch: on the Certificates page choose **Switch to production...**, or call
   `POST /api/v1/certs/switch-production` with
   `{"issuer": "letsencrypt", "confirm": true}` (an administrator session and
   the CSRF header are needed). This records the switch for that issuer and
   re-issues every staging certificate of it, one by one; one that fails stays
   on staging and can be retried with **Renew now**.
3. Make it permanent: set `directory: production` on the issuer in the config.
   The recorded switch applies only while the config still names the
   directory it was made from; after you edit the directory it is cleared at
   the next start.

If you edit the directory first instead, existing staging certificates are
not switched by automatic renewal (the log says the issuer directory changed):
use the switch, or **Renew now** on each certificate. Doorwarden never replaces a
production certificate with a staging one by itself; **Renew now** of a
production certificate under a staging issuer is refused.

## Renewal

- Doorwarden checks every certificate hourly (except in dry run) and renews it
  when less than `settings.renew_before` (default `720h`, 30 days) remains.
  Let's Encrypt certificates last 90 days.
- Certificates for new host names (per-host, san) are ordered by the reconcile
  loop as soon as the service is published.
- A renewal failure keeps serving the current certificate. Alerts are sent for
  failures (`cert.failure`, `cert.renewal_failed`) and when a certificate has
  less than 14 days, 7 days and 1 day left (`cert.expiring`); see
  [configuration.md](configuration.md#notifications).
- **Force renewal**: **Renew now** on the Certificates page, or
  `POST /api/v1/certs/{id}/renew` (answers `202 Accepted`; the result appears
  on the page and in the activity log). It skips the failure backoff, but not
  a rate-limit pause from the CA.

## Rate limits and backoff

Doorwarden enforces limits below Let's Encrypt's own, so a misconfiguration
cannot lock you out of the CA for a week:

| Guard | Limit | Let's Encrypt |
|---|---|---|
| failed validations | 3 per host name per hour | 5 |
| duplicate certificates | 4 for the exact same set of names per 7 days | 5 |
| new orders | 250 per issuer per 3 hours | 300 |

After a failure a certificate waits 1 minute, then 2, 4, ... up to 6 hours
(plus up to 10% jitter) before the next attempt. When the CA answers with a
rate-limit error, ordering pauses until the CA's `Retry-After` (1 hour if it
gives none, at most 7 days). An order is recorded *before* it is sent, so a
crash or restart loop does not place a fresh order on every start. The
Certificates page shows why a certificate is waiting and until when
(`backing off after N failure(s)`, `rate limited by the CA`,
`N failed validations for <name> in the last hour`, ...).

## Common errors

| Symptom | Likely cause and fix |
|---|---|
| Doorwarden does not start: `DOORWARDEN_MASTER_KEY is required` | a zone has an issuer; set the master key ([configuration.md](configuration.md#secrets-and-the-master-key)) |
| `email is required for Let's Encrypt` | set `email` on the issuer |
| `certificate.dns_provider ... is not a supported ACME DNS provider` | the entry's `type` must be a lego provider code; `unifi`, `pihole` and `adguard` are record-only |
| DNS-01 times out / `NXDOMAIN` for `_acme-challenge` | the challenge provider writes to a zone the public internet does not see (a split-horizon or LAN-only server), the token lacks edit rights, or propagation is slow: raise `acme.dns_propagation_timeout`, or set `acme.resolvers` to public resolvers |
| `unauthorized` / `incorrect TXT record` | another TXT value at `_acme-challenge` (an old NPM or certbot record); delete stale records |
| HTTP-01 `connection refused` / 404 | port 80 is not reachable from the internet, or the `/.well-known/acme-challenge/` route to `acme.http01_listen` is missing |
| `rateLimited` from the CA | wait for the time shown; meanwhile use the staging issuer to debug |
| Browser says the certificate is not trusted | the issuer is still on staging; [switch to production](#from-staging-to-production) |
| Traefik serves its own default certificate | no certificate covers the name yet (look at the Certificates page and the plan), or several zones and no `settings.default_zone` for clients without SNI |

## Files on disk

Certificates are written to `acme.certs_dir` (default `/data/certs`):

```
/data/certs/<id>/v<N>/fullchain.pem   0600
/data/certs/<id>/v<N>/privkey.pem     0600
```

Directories are `0700`. Each issuance creates a new `v<N>` directory (the
previous version is kept), so Traefik sees a changed path and reloads. Traefik
reads the same directory at `traefik.cert_path_prefix` (default `/certs`, a
read-only mount), which is why Doorwarden and Traefik must run as the same user
(UID/GID 65532 in the provided compose file). The ACME account keys are stored
in the database, encrypted with `DOORWARDEN_MASTER_KEY`.

## Importing existing certificates

Importing existing certificates, such as Nginx Proxy Manager's wildcard
certificate, is **not available in this release**: no command or API exposes
it. Doorwarden issues its own certificates; keep NPM's certificates untouched
as your rollback path ([migration.md](migration.md)). To avoid hitting
duplicate-certificate limits during a migration, test with the staging issuer
first.
