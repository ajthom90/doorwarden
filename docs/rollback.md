# Rolling back to Nginx Proxy Manager

Use this if Doorwarden/Traefik misbehaves after cutover. It works because the
cutover never deletes NPM and never touches NPM's certificates, and because
the DNS records point at the same host (`target_ip`) for both setups.

What Doorwarden does to DNS: it never changes or deletes a record it did not
create (records that existed before it are reported as conflicts, or adopted
only when you choose so). Records it created itself stay in place when it is
stopped: stopping deletes nothing. But a Doorwarden left **running** deletes
its own per-host records about `settings.grace_period` (24h by default) after
their service disappears or is unpublished. **Stop Doorwarden when you roll
back to NPM**, and keep it stopped while NPM serves.

> Every TrueNAS state-changing command below must be shown to the operator
> and confirmed before it is run. App names and menus are examples and vary
> by TrueNAS version.

0. If you want to bring Doorwarden back up later for another attempt, first
   **revert `TRAEFIK_HTTP_PORT` / `TRAEFIK_HTTPS_PORT` to 8080/8443** in its
   environment before restarting the Doorwarden stack, otherwise it will take
   80/443 back from NPM. (After a cutover those variables are 80/443; the
   trial values only apply to the alternate-port stage.)
1. **Stop the Doorwarden app (Traefik and Doorwarden).** Stop the whole app,
   not just Traefik, so ports 80/443 are released and Doorwarden stops
   reconciling DNS. Doorwarden does not delete anything on stop.
2. **Start the NPM app.** It still has its dataset, database and certificates.
3. **DNS needs no edits.** Records point at `192.0.2.10` (your TrueNAS host)
   in both setups. Records Doorwarden created remain and still resolve to that
   host. Do not let Doorwarden run while NPM serves; leave it stopped.
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
from the alternate-port step (ports 8080/8443 again).
