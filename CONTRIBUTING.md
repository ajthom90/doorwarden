# Contributing

Thanks for helping. Bug reports, documentation fixes and provider reports from
real setups (what worked, what did not) are as welcome as code. For security
problems, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Development setup

You need Go (the version in `go.mod`), `git`, and for some tests `bash`,
`curl` and `openssl`. Docker is optional (image build, Pebble tests).

```
git clone https://github.com/ajthom90/doorwarden.git
cd doorwarden
make build        # bin/doorwarden (CGO_ENABLED=0)
make test         # go test ./... -race
make vet
```

Everything builds without cgo; SQLite is a pure-Go driver.

### Seeing the UI

```
go run ./internal/web/uidemo
```

serves the real web UI on `http://127.0.0.1:8099/` against seeded fake data
(no Docker, TrueNAS or DNS access) and prints the demo login. `-fresh` starts
without an administrator to show the first-run wizard, `-dry-run=false` starts
with dry run off, `-listen` changes the address (keep it on localhost). The
demo data is deleted on exit.

### More tests

| Command | What it covers |
|---|---|
| `go test ./... -race` | everything that needs no network; every test uses fakes or `httptest` |
| `docker compose -f deploy/test/docker-compose.pebble.yml up -d` then `go test -tags integration ./internal/acme/...` | certificate issuance against Pebble, Let's Encrypt's test CA (stop it with `... down`) |
| `go test -tags acme_slow ./internal/acme/...` | builds every lego DNS provider of the catalog (slow) |
| `go test ./internal/deploycheck/...` | the deploy files, `scripts/verify.sh` and the CI workflows (pinned actions, permissions) |
| `make docs-check` | relative links and `#anchors` in every Markdown file |
| `make check-notices` | `THIRD_PARTY_NOTICES.md` matches the modules in the binary |

Tests never talk to a real DNS provider, CA, Docker daemon or TrueNAS. Use
`example.test`, `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` for names
and addresses in tests, examples and docs, never your own.

## Dependencies

- Keep them few. The standard library first.
- **Every new or updated module must have been released at least two weeks
  before you add it.** Pin exact versions in `go.mod`, and pin GitHub Actions
  to a commit SHA with the version as a comment.
- After any change to `go.mod`, run `make notices` and commit the updated
  `THIRD_PARTY_NOTICES.md` (CI fails when it is stale). The generator refuses
  a module whose license it cannot identify: add an override in
  `scripts/notices/main.go` only after reading the license yourself.

## Code and commits

- `gofmt`, `go vet ./...` and `go test ./... -race` must pass.
- Commit messages: a short summary in the imperative, prefixed with the area
  (`feat(web): ...`, `fix(reconcile): ...`, `docs: ...`, `ci: ...`,
  `build: ...`), then a body explaining why. One logical change per commit.
- Update the docs in the same pull request when behaviour, a config key, a
  label or a UI action changes. Docs describe what the code does; check them
  against the source.

Adding a DNS record provider is described in
[docs/providers.md](docs/providers.md#adding-a-record-provider).

## Security-sensitive areas

Changes here get a careful review; explain the threat you considered in the
pull request:

- `internal/reconcile`: DNS ownership, grace periods, drift repair and the
  mass-repair breaker. Doorwarden must never modify a record it does not own.
- `internal/dns/providers`: credential handling (secrets must never appear in
  errors or formatted values), URL and redirect checks.
- `internal/web`: authentication, sessions, CSRF, login throttling, trusted
  proxies and headers, and the config editor's secret masking
  (`configdoc.go`).
- `internal/config` and `internal/secrets`: `${VAR}` substitution, the
  redacting secret type, the master key and encryption.
- `internal/acme`: rate-limit guards and the staging/production switch.
- `deploy/compose.truenas.yml`: the socket-proxy allowlist, users,
  capabilities and networks. Never widen the allowlist without a reason in the
  pull request.
- `.github/workflows`: permissions and pinned actions.

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the project's license.
