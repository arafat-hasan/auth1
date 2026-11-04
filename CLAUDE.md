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
AUTH1_APP_ENVIRONMENT=development AUTH1_DELIVERY_ADAPTER=capture ./bin/auth1 serve --config config.example.yaml   # API on :8080, metrics on :9090
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
`COMMIT` is sent is `UNAVAILABLE`. A use case that changes an account locks it with
`Accounts.GetForUpdate`; `Do` then sets its version, before `COMMIT`, past the events
`postgres.Outbox` wrote about it (by one when none; TDD-06 §2), so nothing bumps the version by
hand. `Outbox.Event` needs that lock and `Outbox.Delivery` a transaction (I-7); both
`pg_notify('auth1_outbox', destination)`. `postgres.Audit` joins the transaction, or writes alone
outside one. Repositories take
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

Access tokens (TDD-04 §1, §6 steps 1–2): `internal/app/tokens` takes the ports only;
`NewIssuer` and `NewValidator` return an error for a `Config` they cannot use (no issuer, a TTL
not above 0, a client audience empty, repeated or equal to the self audience, which
`config.Validate` also refuses: SDD D-5). `tokens.Issuer.IssueAccess(Session, Account, Client)`
signs exactly the §1 claims with `typ: at+jwt`: an active account gets the client's audience and
its roles ∩ `allowed_roles`, sorted; a suspended or banned one the self audience
(`tokens.self_audience`, else `http.issuer`) and `roles: []`. Any other status, a session of
another client, or a missing id, audience or sign-in time is `ErrNotIssuable`; with no signing key
the error matches `app.ErrNoSigningKey`. `Access` prints and logs without its token.
`tokens.Validator.Validate(token)` refuses with one of `ErrMalformed`, `ErrType`, `ErrUnknownKey`,
`ErrAlgorithm`, `ErrSignature`, `ErrClaims`, `ErrIssuer`, `ErrAudience`, `ErrExpired`,
`ErrNotYetValid`, all matching `errors.Is(err, tokens.ErrInvalid)` and none holding token text; a
published key that cannot verify is `ErrKeyUnusable` (a server fault, not matching `ErrInvalid`).
It accepts only a compact, unpadded base64url JWS of at most 8 KiB whose header is `alg`, `kid`,
`typ`; the `alg` must be the published key's own; claims are typed and consistent; `iss` is exact;
`aud` is the self audience for a restricted status (`Claims.Restricted`) and a client's audience
(`Config.ClientAudiences`) for an active one; refused on or after `exp` + `tokens.Leeway` (30 s)
and before `nbf` or `iat` − 30 s. Key nothing on the token string (signatures are malleable); use
`Claims.ID`. Tests sign with `fakes.NewKeys()` (RS256 and ES256, `SetActive`, `Unpublish`,
`NoSigner`, `FailSign`, `Unsynced`, `Private` for forging).

Flows (TDD-02 §2, TDD-07 §5): `app.Flows` (`postgres.Flows`) stores `flow.Flow` /
`flow.ChallengeRecord` (plaintext records in `internal/domain/flow/records.go`); callers pass the
handle hash (`crypto.SHA256`), the link hash and the OTP MAC, and it seals `pending_secret`,
`secret` and `target_value` and computes `target_bidx`. `Find`, `FindByHandle` and `FindLink` lock
nothing and answer every miss with the same `CHALLENGE_CLOSED` (I-20); then lock the account
(`GetForUpdate`), `LockFlow` (re-checks account and handle) and `LockChallenges`. The transaction
records locked flows and challenges, and a method without its prerequisite lock returns
`postgres.ErrLockOrder` before querying (G-5). `Attempt` (I-4), `RecordSend`, `CloseChallenge` and
`Complete` / `Cancel` (which erase secrets in the closing statement, I-5) are conditional SQL.
`RecordSend` also writes the send's `challenge_sends` row (migration `000002`), which `SendCounts`
counts per window after taking a transaction-scoped advisory lock on the address, so
check-then-send is exact (I-21); `ExhaustedSince` is the L-9 cooldown query.

Sessions (TDD-04 §2, §3): `app.Sessions` (`postgres.Sessions`) stores `session.Session` /
`session.Token` (`internal/domain/session`, with the `RevokeReason`s, refused when unknown with
`session.ErrRevokeReason`); callers pass token hashes (`crypto.SHA256`) and the successor's raw
value as a redacting `session.Secret`, sealed at `app.NewKeyPlace("refresh_tokens",
"successor_enc", <presented token_hash>)`. Every stored time but the caller's `AuthTime`, and every
comparison, is the database's `now()`: `Session.Live` and `Token.InGrace` are computed in SQL, so
tests back-date rows rather than use a fake clock. `FindToken` locks the session without the
account, then reads the token in a second statement (one joined `FOR UPDATE OF s` would return the
token as it was before a racing rotation); `LockSession` locks one of the account's sessions
(`NOT_FOUND`). `Create` and `RevokeAll` / `RevokeAllExcept` need the account lock, `Rotate`,
`Successor` and `Revoke` the session lock (`ErrLockOrder`), and `Accounts.GetForUpdate` refuses once
a session is locked (G-5). `Rotate` is one statement, conditional on `rotated_at IS NULL` (I-3);
`Successor` follows at most 3 steps within the grace window, and a stored successor gone missing is
`postgres.ErrSuccessorChain`, not reuse; `EraseSuccessors` (for the retention job) nulls
`successor_enc` past the window (I-13).

Identifiers (TDD-01 §2): `internal/domain/identifier` holds the `Type` interface (`Normalise`,
`VerifyMethods`, `CanSignIn`, `Variants`, `CheckPolicy`), the built-in `Email` and `Phone`
(`identifier.Builtin()`) and the `Registry`. `NewRegistry` checks the `identifiers` policy against
the types and returns `PolicyErrors`; `loadIdentifiers` in `cmd/auth1` runs it after `Validate`
for `config check` and `serve`. Refusals are `IDENTIFIER_NOT_ALLOWED` and never carry the value.
An empty `calling_codes` allows no phone. `TestSimpleFoldUnicodeVersion` fails when Go's Unicode
version changes: re-check `simpleFold` against CaseFolding.txt. Both normalisers are fuzzed (`FuzzEmail`, `FuzzPhone`: deterministic and idempotent).

Password policy (TDD-03 §2): `internal/domain/password.Check(password []byte, variants, Policy)
[]Reason` returns every reason that applies, in the order of `Reasons()` (checked against the
contract's `Problem.reasons` in `test/contract`); `Rejected(reasons)` is the `PASSWORD_REJECTED`
error. The caller passes the account's identifier variants (`Registry.Variants`). Lengths are code
points of the NFKC form; the password, variants and deny-list entries are compared as
`NFKC(fold(NFKC(s)))` with full case folding, and variants under 4 code points are ignored.
`ParseDenyList(io.Reader)` is pure; `loadPasswordPolicy` in `cmd/auth1` opens
`passwords.deny_list_file` for `config check` and `serve`, so a bad file fails start-up.

Delivery (TDD-06 §5–§9): `internal/domain/message` holds the purposes of TDD-06 §7 as constants
(`message.SignInCode` …, each the default type without `auth.`) with their channel, secret and
variables; `message.NewTypes` applies `delivery.types`, checked by `loadMessageTypes` in
`cmd/auth1` after `Validate` (`internal/config` cannot import domain). Identifier types say their
`Channel()`. In `internal/app`, `MessageDelivery.Send(ctx, DeliveryRow) DeliveryOutcome` (sent,
dropped, retry, parked; the relay owns retries) and `DeliveryResolver` (TDD-06 §6) are the ports;
`Messages` builds the requests (`ChallengeCode`, `ChallengeLink`, `Notice`; not yet the
invitation's `display_name` reference) with references only (`IdentifierRef`, `ChallengeTargetRef`,
`SecretRef`, `LinkRef`) and exactly the purpose's variables, plain strings or integers, refusing
anything else with `ErrMessageInvalid`; a link goes only by email; never build a
`DeliveryRequest` by hand. `MessageDelivery` adapters always set a `DeliveryOutcome` result: the
zero value is none. `Notices.Send` writes a notice in the caller's transaction and returns a
`NoticeSkip` when it writes none. It chooses the recipient: an explicit `Notice.To` if current or
retired less than `retired_address_window` ago (no fallback); otherwise the verified email or, only
when the deployment has no email type, the first verified identifier by type name. With an email
type, notices go only by email. `internal/adapters/delivery/capture`
keeps the last 1000 messages resolved and serves `GET /dev/messages?to=`; `newDelivery` builds it
only in `development` and `serve` mounts it through `server.Options.Dev` at the root, outside the
contract. `test/contract` checks stored delivery bodies against `DeliveryRequest` with
`apitest.CheckSchema`.

Relay (TDD-06 §3.2, §3.3): `internal/worker/relay.Deliveries` sends delivery rows through
`app.DeliveryOutbox` (`postgres.DeliveryOutbox`). The claim is a lease: one short transaction
(`FOR UPDATE OF o SKIP LOCKED`) drops rows whose challenge is not open (`dropped: challenge
closed`) and notices older than 24 h, parks bodies that are not delivery requests, and sets
`attempts + 1` and `next_attempt_at = now() + lease` on the rest. `Send` runs outside any
transaction (G-4), and `Publish` / `Retry` (capped at the request's `deadline`) / `Park` apply only
while `attempts` is still the claimed value, else `app.ErrClaimLost`. A dead relay's row is sent
again when its 30 s lease ends, with the same `request_id`. `relay.Backoff` is TDD-06 §3.1's (1 s
doubling to 5 min, ±20%); a retry at `outbox.max_attempts`, a parked outcome and the zero outcome
park. `Claim` returns an `app.DeliveryClaim`: the leased rows, how many rows it locked (the relay
claims again while that is all it asked for, so dropped rows never hold back due ones) and the rows
it parked for their body, which the relay logs. Each relay has 8 senders and claims only for idle
ones; it wakes on
`postgres.Listener` (a pgx connection of its own on `auth1_outbox`, reconnecting, so `max_conns` + 2
per instance) and on `outbox.poll_interval`, and records `auth1_outbox_age_seconds` /
`auth1_outbox_parked` (destination `delivery`) every 15 s, from the partial indexes
`outbox_delivery_pending` and `outbox_parked` (migration `000003`). `serve` runs both in its errgroup and
refuses a `delivery.adapter` with no adapter yet, so until WP-44 run it with
`AUTH1_DELIVERY_ADAPTER=capture` (the serve tests use `serveEnv`); `serveDeps.resolver` replaces
`unavailableResolver` in tests until WP-43.

Rate limits (TDD-07 §1, §2, §8): `app.RateLimiter` (`Hit`) is the sliding-window port and
`app.RateLimits` the helper use cases call: `CheckIP(ctx, rule, ip)` (keyed by `app.IPKey`: IPv4
whole, IPv6 by /64) or `Check(ctx, rule, key)` for L-15's client id; it returns a `RATE_LIMITED`
`*domain.Error` with `RetryAfter`, and nil when allowed or when the limiter errs (fail open). The
rules are `app.Rule` constants named after their `rate_limits` keys; `newRateLimits` in
`cmd/auth1/ratelimit.go` builds them. `internal/adapters/redis` is the adapter: one Lua script per
hit at `<redis.prefix>rl:<rule>:<key>`, scored by `app.Clock`, refused hits not counted, every call
bounded at 100 ms with no retries; it records `auth1_rate_limited_total{rule}` and
`auth1_rate_limiter_errors_total`. `serve` registers `redis` as a non-critical readiness check.
The client IP comes from `internal/http/clientip` (`Resolver` over `http.trusted_proxies`, its
middleware installed by the router for every request via `server.Options.ClientIP`; read it with
`clientip.From(ctx)` and pass it into commands; never log it). L-1 is `middleware.RateLimit`, in
`server.Options.APIMiddleware`, which runs on the API routes and every 404 (not the probes or
`/dev`); `gen.ServiceRoute(basePath)` exempts service operations. Tests use
`fakes.NewRateLimiter` (counts, no window; `Fail(err)`) and
`internal/testing/redistest` (`Addr` with a per-test `Prefix`, needing `redistest.Main` in
`TestMain`; `NewServer` with `Stop`/`Start`, which does not). The Docker gate and the restart proxy
of pgtest and redistest live in `internal/testing/dockertest`.

Registration (TDD-02 §2.4, §3): `app.Challenges` (`NewChallenges` refuses unusable
`ChallengeRules`) opens a `verify_identifier` challenge (`OpenVerification`: an OTP stored as
`MAC.OTP`, or a link token stored as its SHA-256) and sends it (`Send`: `SendCounts` takes the
address lock, then the L-9 cooldown through `ExhaustedSince` and L-7, `RecordSend`, then
`Messages`; a refusal is `RESEND_TOO_SOON` or `RATE_LIMITED` and writes nothing). Its
`ResendRules` are the per-challenge resend rules. `app.Registration` (`NewRegistration` refuses a
missing dependency) has one method per step (`Start`, `VerifyCode`, `Resend`, `ConfirmLink`), each
one `UnitOfWork.Do` after its per-IP limits (L-4, L-8, L-12) and, for `Start`, after hashing. A
step whose writes must stand although it answers an error (a wrong or last code,
`IDENTIFIER_TAKEN` after consuming) commits and returns the answer after `Do`; a refused resend
rolls back. At `Start` a send refused by L-7 or L-9 is skipped: the challenge stays open, unsent,
for a resend, and the success audit lists `unsent_types`. Refusals are audited outside the
transaction with their code (and the flow id and kind once the flow is found), never a value; an
audit entry that cannot be written is logged; per-IP refusals and store failures are not audited.
A flow, account or identifier gone under the lock is the same `CHALLENGE_CLOSED`. Command secrets
are `flow.Secret`. Event data types live in `internal/app/events.go` (`AccountActor` builds the
actor). `handlers.NewAPI` takes the registration (nil keeps its operations at 501);
`cmd/auth1/registration.go` builds it. API tests in `cmd/auth1/registration_test.go` run `serve`
(`startServeConfig`, phones under +44 allowed) with `dbResolver`, a test stand-in for the WP-43
resolver that reads identifier values and open secrets from the database.

Service callers (TDD-05 §1, §3): `internal/http/middleware/caller.Resolver` is in
`server.Options.APIMiddleware` after `middleware.RateLimit`. It finds the operation before dispatch
with `gen.Match(basePath)` (by route pattern; `gen.ServiceRoute` is built on it; the schemes are
`gen.SchemeWorkload` and `gen.SchemeServiceToken`) and passes every operation that is not a
service one through. For a service operation it resolves the caller by the credentials both
`service_auth.mode` and the operation's security accept: a configured workload identity wins; in
mode `both` an unconfigured one yields to a valid service token; none gives `401 TOKEN_INVALID`
(an unset mode, development only, accepts none). It then checks `x-auth1-scope` (`403
CALLER_NOT_ALLOWED`: `auth1_service_calls_denied_total{caller,scope}`, with `caller="unknown"` for
a workload identity not in `service_auth.callers`; an `auth_audit` row `service_call_denied`
written outside any transaction; a log line with only the request id, route pattern and decision;
a failed audit write is logged and the call still refused), then `Auth1-Actor` (one value, 1–128
of `\x20-\x7E`, else `422 VALIDATION_FAILED`). Handlers read `caller.From(ctx)` (a copy), never
headers. Identity headers count only when the TCP peer (`RemoteAddr`, not `clientip`) is in
`trusted_sidecar_cidrs` (an IPv4-mapped range counts as the IPv4 range); XFCC gives the first
`URI` of its only element (`xfccURI`, fuzzed); `peer_cert` reads `r.TLS.VerifiedChains`, though
nothing terminates TLS yet. Service tokens go through `caller.TokenVerifier`, nil until WP-70.
`caller.New` refuses missing dependencies and a header-sourced mesh mode with no header name.
`loadServiceAuth` in `cmd/auth1/serviceauth.go` maps the config for `config check` and `serve`,
refusing a sidecar entry that is not a CIDR and an empty or repeated caller identity; `serve` warns
for a sidecar range beyond loopback, for service tokens with no verifier and for `peer_cert`.
