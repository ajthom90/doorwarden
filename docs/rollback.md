# Rolling back to Nginx Proxy Manager

Use this if Doorwarden/Traefik misbehaves after cutover. It works because the
cutover never deletes NPM, never changes DNS, and never touches NPM's
certificates.

> Every TrueNAS state-changing command below must be shown to the operator
> and confirmed before it is run. App names and menus are examples and vary
> by TrueNAS version.

1. **Stop Traefik (the Doorwarden app).** Stop the whole app so ports 80/443
   are released. Doorwarden does not delete anything on stop.
2. **Start the NPM app.** It still has its dataset, database and certificates.
3. **DNS is unchanged.** Records point at `192.0.2.10` (your TrueNAS host) in
   both setups, so no DNS edits are needed. Do not let Doorwarden run while
   NPM serves, or it may re-assert records; leave it stopped.
4. **Certificates are untouched.** NPM keeps using its own; Doorwarden's
   certificates remain on disk in its data dataset and can be reused later.

## Confirm the rollback

```
curl -sS -o /dev/null -w '%{http_code}\n' --resolve app.example.test:443:192.0.2.10 https://app.example.test/
openssl s_client -servername app.example.test -connect 192.0.2.10:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer -dates
```

Expect a 2xx/3xx (or 401/403 for protected apps) and NPM's certificate
issuer. Or run `scripts/verify.sh hosts.txt --resolve 192.0.2.10`.

## Afterwards

Capture the Traefik access log and Doorwarden activity log before retrying,
fix the cause, and repeat the staged procedure in [migration.md](migration.md)
from the alternate-port step.
