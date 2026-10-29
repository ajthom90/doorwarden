# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**
(<https://github.com/ajthom90/doorwarden/security/advisories/new>). Do not
open a public issue for a security problem.

Include what you found, the affected version (`doorwarden --version` or the
image tag), steps to reproduce, and the impact you expect. Remove real host
names, addresses and credentials from logs and configs before you send them.

This is a small project maintained in spare time. The aim is to acknowledge
a report within a week and to publish a fix and an advisory as soon as
practical; reporters are credited unless they ask not to be.

## Supported versions

Only the latest release receives security fixes. The project is in beta (see
[README.md](README.md#status-and-maturity)).

## Scope

In scope: the `doorwarden` binary and container image, the provided deploy
files (`deploy/`), and the documentation's security guidance. Examples:
authentication or CSRF bypass, a way to make Doorwarden modify DNS records it
does not own, credential disclosure through logs, errors or the API, a way to
publish a service that was not opted in or approved, or a path from the web UI
to the Docker socket beyond the documented container listing.

Out of scope: vulnerabilities in Traefik, the socket proxy, lego or other
dependencies (report those upstream; tell us if Doorwarden's use makes them
exploitable), and attacks that require a shell on the host or control of the
DNS provider account.

The security model, its accepted residual risks and the hardening guidance are
in [docs/security.md](docs/security.md).
