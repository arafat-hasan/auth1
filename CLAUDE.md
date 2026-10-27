# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status: redesign for 1.0

auth1 is being rebuilt to a new design. **The design documents are the source of truth for new
work.** The pre-1.0 prototype was removed in WP-00 and is kept only in git history; 1.0 has a
fresh schema (migrations restart at `000001`) and no compatibility with the prototype's API,
tokens or data. Nothing runs in production, so no migration path is needed.

| Document | Role |
|---|---|
| `docs/design.md` | SDD: needs, decisions D-1…D-19, state models, invariants I-1…I-21, threat model, acceptance tests T-1…T-38 |
| `docs/tdd/TDD-01` … `TDD-08` | TDDs: how each area is built (schema, flows, MFA, tokens, service access, events, abuse, operations) |
| `api/openapi.yaml`, `api/asyncapi.yaml` | Contracts. Wire shapes are final here |
| GitHub issues: roadmap #69 → milestone issues #60–#68 → work packages `WP-NN` (label `work-package`) | The implementation plan. Read a work package with `gh issue view <n>`; its step plan goes in the issue under `## Steps` when work starts. Branch `wp-NN-<slug>`, one PR per work package with `Closes #<n>`. See `docs/plan/README.md` |

Rules for design and implementation work:
- When a TDD needs to change a decision, change the SDD first. When a contract and a TDD disagree on a wire shape, the contract wins and the TDD is corrected.
- Keep the code product-agnostic: no product names in code, default config or migrations (D-1).
- Key 1.0 choices that differ from the prototype:
  - UUIDv7 ids;
  - Argon2id with a pepper (not bcrypt);
  - **optional TOTP MFA** with recovery codes: per account, and a client may require it (`mfa: required`);
  - every account has a password;
  - opaque rotated refresh tokens in PostgreSQL (no Redis blacklists);
  - restricted tokens use auth1's own audience;
  - workload identity or client credentials for services (no static API keys);
  - Redis only for per-IP rate-limit windows.
- Docs use British spelling and the existing plain style; mark advisory TDD text *(guideline)*.

## Commands

```bash
make build                 # bin/auth1 with version and commit from git
make test                  # go test -race ./...
make lint                  # go vet + golangci-lint v2 (.golangci.yml)
make vuln                  # govulncheck ./...
make generate              # go generate ./...
./bin/auth1 version        # version, commit, Go version
./bin/auth1 config check --config config.example.yaml   # load and validate a configuration
AUTH1_APP_ENVIRONMENT=development ./bin/auth1 serve --config config.example.yaml   # API on :8080, metrics on :9090
AUTH1_APP_ENVIRONMENT=development make migrate ARGS="status --config config.example.yaml"   # also up, down [N]
./bin/auth1 migrate create <name>   # next numbered empty pair in migrations/
```

The example's DSN (`testdata/example/secrets/db/dsn`) points at
`postgres://auth1:auth1@localhost:5432/auth1` without TLS, so it needs
`AUTH1_APP_ENVIRONMENT=development`. Tests that need PostgreSQL use Docker: they skip without it,
unless `AUTH1_REQUIRE_DOCKER=1` (set in CI), which makes them fail.

## Layout and guards

Code layout follows TDD-08 §2; every package has a `doc.go` naming the TDD section it implements.
The binary is `cmd/auth1` (cobra; `newRootCmd` in `root.go` is where subcommands are added).

`test/guard` holds the layering check (`TestLayering`), run by `make test` and in CI: from
`go list -deps` (plus files left out by build constraints), `internal/domain` imports nothing
internal, `internal/app` imports only `internal/domain` and `internal/app`, and
`internal/adapters` and `internal/http` do not import each other, and `internal/telemetry` imports
only `internal/config`. `TestMetricNames` fails on any `auth1_…` string literal that is not in the
TDD-08 §5.2 catalogue (`telemetry.InstrumentNames()`); create instruments through
`telemetry.Metrics`.

`internal/config` loads YAML over the defaults in `Default()`, then `AUTH1_<PATH>` overrides
(resolved against the schema's scalar key paths); `Validate()` applies TDD-08 §3.1. Adding a key
means a field with a `koanf` tag, its default, and a line in `config.example.yaml` (tests check
the example lists every key with its default). The example's secret files are empty placeholders
under `testdata/example/`.

HTTP (TDD-08 §2): `internal/http/server` builds the Chi router (`NewRouter(Options)`: middleware
via `Use`, `/livez` and `/readyz` at the root, API routes under `http.base_path` through
`Options.Routes`) and `Run`s the servers with the drain and shutdown sequence; `cmd/auth1/serve.go`
only wires it. Domain failures are `*domain.Error` with a `domain.Code`; only
`internal/http/problem` maps a code to its status (`(*problem.Writer).Write`). Readiness checks are
added with `health.Checker.Register`. Middleware reads the route pattern after routing, so it must
stay installed with `Use`; logs, spans and metric labels carry the route pattern, never the path.

PostgreSQL (TDD-01 §4, §6): `postgres.Open` builds the bun pool on pgx from `database.dsn_file`
(read at start-up, never logged; outside `development` it refuses a DSN without TLS).
`internal/app.UnitOfWork` is the transaction port; `postgres.UnitOfWork` runs one `READ COMMITTED`
transaction, a nested `Do` joins it, and an acquire timeout is `UNAVAILABLE`. Repositories take
their executor from `postgres.Conn(ctx, db)`: the open transaction, else the pool. bun uses `?`
placeholders. Migrations are plain SQL in `migrations/` (embedded as `migrations.FS`), run by
`internal/adapters/postgres/migrate` under an advisory lock; never edit an applied one.
`internal/testing/pgtest` (test files only, enforced by `TestLayering`) gives each test a database:
`pgtest.DSN(t)` migrated from a per-package template, `pgtest.Empty(t)` empty, and
`pgtest.NewServer(t)` a container of its own that the test can stop and start.

`internal/ratelimit` is the prototype's Redis limiter, kept until WP-50 ports it to
`internal/adapters/redis`.
