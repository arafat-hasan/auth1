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
make generate              # go generate ./...: internal/http/gen from api/openapi.yaml (CI fails if stale)
make spec-lint             # vacuum (api/vacuum.yaml) on openapi.yaml, AsyncAPI CLI on asyncapi.yaml
make spec-diff             # oasdiff breaking against the newest v* tag (warn-only in CI until v1.0.0)
./bin/auth1 version        # version, commit, Go version
./bin/auth1 config check --config config.example.yaml   # load and validate a configuration
AUTH1_APP_ENVIRONMENT=development ./bin/auth1 serve --config config.example.yaml   # API on :8080, metrics on :9090
AUTH1_APP_ENVIRONMENT=development make migrate ARGS="status --config config.example.yaml --dsn-file testdata/example/secrets/db/migrator-dsn"   # also up, down [N]
./bin/auth1 migrate create <name>   # next numbered empty pair in migrations/
```

The example's DSNs point at `localhost:5432/auth1` without TLS, so they need
`AUTH1_APP_ENVIRONMENT=development`: `testdata/example/secrets/db/dsn` is `auth1_app`'s (for
`serve`) and `migrator-dsn` is `auth1_migrator`'s (for `migrate`), each with the role's name as
its password. A local database to match:

```bash
docker run -d --name auth1-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=auth1 postgres:18
psql postgres://postgres:postgres@localhost:5432/auth1 -f deploy/postgres/roles.sql \
  -c "ALTER ROLE auth1_migrator PASSWORD 'auth1_migrator'" -c "ALTER ROLE auth1_app PASSWORD 'auth1_app'"
```
 Tests that need PostgreSQL use Docker: they skip without it,
unless `AUTH1_REQUIRE_DOCKER=1` (set in CI), which makes them fail.

## Layout and guards

Code layout follows TDD-08 §2; every package has a `doc.go` naming the TDD section it implements.
The binary is `cmd/auth1` (cobra; `newRootCmd` in `root.go` is where subcommands are added).

`test/guard` holds the layering check (`TestLayering`), run by `make test` and in CI: from
`go list -deps` (plus files left out by build constraints), `internal/domain` imports nothing
internal, `internal/app` imports only `internal/domain` and `internal/app`, and
`internal/adapters` and `internal/http` do not import each other, and `internal/telemetry` imports
only `internal/config`. `TestMetricNames` fails on any `auth1_…` string literal that is not in the
TDD-08 §5.2 catalogue (`telemetry.InstrumentNames()`) or one of the two role names it exempts
(`notMetrics`); create instruments through `telemetry.Metrics`.

Time and ids (TDD-01 §1): use cases take `app.Clock` (wall time in UTC, for stored timestamps;
elapsed time keeps `time.Since`) and `app.IDGenerator` (UUIDv7). The adapters are
`system.Clock` (UTC, truncated to the microsecond, as `timestamptz` stores) and `system.UUIDv7`.
Tests use `internal/testing/fakes`: `NewClock` (moves only on `Set` / `Advance`; reads to the
microsecond, like `system.Clock`) and `NewIDs`, whose nth id is `fakes.ID(n)`.

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

Contract (TDD-08 §11, TDD-05 §3): `internal/http/gen` is generated by `make generate` and committed;
never edit `*_gen.go`. oapi-codegen v2 (a `tool` in `go.mod`, config `oapi-codegen.yaml`) writes
the types and `StrictServerInterface`; `internal/http/gen/internal/routegen` writes
`gen.Operations` (operation id → method, path, security schemes, `x-auth1-scope`) and `gen.Stub`
(every operation returns `gen.ErrNotImplemented`, answered `501`). routegen fails, naming the
operation, when a service operation (`workload` or `serviceToken`) has no `x-auth1-scope`, another
operation has one, or the scope is undeclared. Handlers embed `gen.Stub` and are mounted with
`server.Options.Routes = gen.Routes(si, problems)`, which answers bind failures with `422
VALIDATION_FAILED` (`413` for a body found over the limit while decoding; `problem.WriteBindError`). API tests check exchanges with `internal/testing/apitest`
(`apitest.New(t).Serve(t, h, req)`, libopenapi-validator). vacuum and oasdiff are `tool`s in
`tools/go.mod` (`go -C tools tool …`).

PostgreSQL (TDD-01 §4, §6): `postgres.Open` builds the bun pool on pgx from `database.dsn_file`
(read at start-up, never logged; outside `development` it refuses a DSN without TLS);
`postgres.OpenProbe` builds the one-connection pool that the `/readyz` check pings.
`internal/app.UnitOfWork` is the transaction port; `postgres.UnitOfWork` runs one `READ COMMITTED`
transaction, a nested `Do` joins it, and an acquire timeout or a connection lost before
`COMMIT` is sent is `UNAVAILABLE`. Repositories take
their executor from `postgres.Conn(ctx, db)`: the open transaction, else the pool. bun uses `?`
placeholders. Migrations are plain SQL in `migrations/` (embedded as `migrations.FS`), run by
`internal/adapters/postgres/migrate` under an advisory lock; never edit an applied one.
Roles (TDD-01 §4.1): a DBA runs `deploy/postgres/roles.sql` once per database to create
`auth1_migrator` (runs the migrations, owns `public` and every object) and `auth1_app` (the
service: `USAGE` only, plus the per-table grants in the migrations); `000001` fails, naming the
role, without them. Every new table needs its explicit grants (`TestAppGrants`) and an index for
each foreign key (`TestForeignKeysIndexed`). Audit partitions come from
`auth_audit_create_partitions(months)`, a `SECURITY DEFINER` function that `auth1_app` may call.
`internal/testing/pgtest` (test files only, enforced by `TestLayering`) gives each test a database,
with the roles bootstrapped and the migrations run as `auth1_migrator`: `pgtest.DSN(t)` migrated
from a per-package template, `pgtest.Empty(t)` empty, both as superuser, and
`pgtest.As(t, dsn, pgtest.App)` the same database as another role; `pgtest.NewServer(t)` is a
container of its own, without the roles, that the test can stop and start. A package using
`DSN` or `Empty` needs `func TestMain(m *testing.M) { pgtest.Main(m) }`: `Main` removes the
shared container when the tests end, because the testcontainers reaper (Ryuk) cannot be relied on:
on a host whose `docker-proxy` does not pass on the client's disconnect, Ryuk never reaps.

Crypto (TDD-01 §3, TDD-08 §4): the ports are `app.FieldCrypto` (`Seal` / `Open` at an
`app.Place`, built with `app.NewPlace` or, for `refresh_tokens`, `app.NewKeyPlace`),
`app.BlindIndex` and `app.MAC`; callers tell failures apart with `errors.Is` on `app.ErrPlaceInvalid`,
`app.ErrCiphertextInvalid`, `app.ErrUnknownKey` and `app.ErrBlindIndexType`.
`internal/adapters/crypto` implements them, with `crypto.SHA256` for tokens and handles. Keyrings
are `ParseKeyring(data, otherState)` (a `keys:` list of `{id, key, state}`, one `active`; the
field keyring's other state is `decrypt`); `WatchedKeyring` holds the field keyring behind an atomic
pointer and its `Run` re-reads the file every 30 s, keeping the last good one when the file is bad.
`Key` and `Keyring` redact themselves under `fmt` and `slog`; never take key bytes out of them
for logging. `cmd/auth1/keys.go` loads the keyring and key files for `config check` and `serve`.
The example's `fields/`, `mac/mac.key` and `pepper/` are public development keys (`testdata/example/README.md`).

Passwords (TDD-03 §1): `internal/adapters/crypto/argon2id.Hasher` implements `app.PasswordHasher`
(`Hash`, `Verify` with `needsRehash`, `VerifyDummy`; passwords are `[]byte`). The pepper keyring is
a `crypto.WatchedKeyring` with other state `crypto.StateVerify`; `pepper_kid` is the key id as
plain decimal text. All three methods share one semaphore of `passwords.argon2.max_concurrent`
slots and return `app.ErrOverloaded` (503, `Retry-After: 1`) after `queue_timeout`. `New` computes
the dummy hash, so it takes one hash's time; `serve` builds it at start-up. Never hash inside a
transaction (G-4).

Signing keys (TDD-04 §5): `internal/adapters/keyring.Keyring` loads `keys.keyring_file` (`Load`
validates it; `config check` runs it), polls the file and its PEMs every 30 s, and syncs
`signing_keys` through `app.SigningKeyStore` (`postgres.SigningKeys`; every time comparison is the
database's `now()`). It implements `app.TokenSigner` (`Sign(payload, typ)`) and `app.PublicKeys`
(`Key(kid)`, `Published()`); handlers and use cases take the ports, never the adapter.
`handlers.API` (embeds `gen.Stub`) serves the JWKS and the server metadata. `serve` registers the
`keyring` readiness check and runs `Keyring.Run` beside the servers. Private keys never print
(`String`, `GoString`, `Format`, `LogValue`). The example keyring in
`testdata/example/secrets/signing` holds public test keys; a fresh database makes its key wait
`min_publish_before_use` (tests set `AUTH1_KEYS_MIN_PUBLISH_BEFORE_USE=0s`).

Identifiers (TDD-01 §2): `internal/domain/identifier` holds the `Type` interface (`Normalise`,
`VerifyMethods`, `CanSignIn`, `Variants`, `CheckPolicy`), the built-in `Email` and `Phone`
(`identifier.Builtin()`) and the `Registry`. `NewRegistry` checks the `identifiers` policy against
the types, so `loadConfig` in `cmd/auth1` reports its problems for `config check` and `serve`.
Refusals are `IDENTIFIER_NOT_ALLOWED` and never carry the value. An empty `calling_codes` allows no
phone. Both normalisers are fuzzed (`FuzzEmail`, `FuzzPhone`: deterministic and idempotent).

`internal/ratelimit` is the prototype's Redis limiter, kept until WP-50 ports it to
`internal/adapters/redis`.
