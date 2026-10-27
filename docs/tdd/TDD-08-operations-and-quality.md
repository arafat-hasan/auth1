# TDD-08 — Operations, configuration and quality

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.3 |
| Date | 2026-10-27 |
| SDD | [design.md](../design.md) 0.5: D-1, D-18, D-19, §6, §13, §14, §15 |
| Owner | Arafat Hasan |

The binary and its commands, code layout, configuration, secrets, jobs, observability, runbooks,
testing and CI.

## 1. The binary

| Command | Purpose |
|---|---|
| `auth1 serve` | HTTP API, outbox relay, jobs |
| `auth1 migrate up \| down \| status \| create <name>` | Schema migrations (advisory-locked) |
| `auth1 config check` | Load and validate a configuration and its secrets, then exit. Used in CI and before deploys |
| `auth1 keys list \| force-activate <kid>` | Keyring state; skip the publication wait (audited) |
| `auth1 sessions revoke-all [--account <id>]` | Revoke sessions in batches (audited) |
| `auth1 outbox list --parked \| retry <id> \| skip <id>` | Parked rows (audited) |
| `auth1 crypto reencrypt \| rebuild-bidx` | Field-key rotation; blind-index key rotation (audited) |
| `auth1 accounts erase <id>` | Erase a deleted account's personal data (SDD O-2; audited) |

Operator commands run as a Kubernetes job or `kubectl exec`, with the same configuration. They
write `auth_audit` rows with `actor_kind = 'operator'` and the operator name from `--actor`
(required).

## 2. Code layout *(guideline)*

```
cmd/auth1/                 main: subcommands, wiring
api/                       openapi.yaml, asyncapi.yaml
migrations/                000001_init.up.sql, …
internal/
  config/                  load, validate, floors
  domain/                  account, identifier, flow, challenge, session, policy (pure)
  app/                     use cases, one package per area; ports.go per package
  adapters/
    postgres/              repositories, unit of work
    redis/                 sliding-window limiter
    amqp/                  publisher with confirms
    delivery/              notification, direct, capture
    crypto/                field crypto, blind index, MACs, Argon2id hasher
    keyring/               signing keyring, JWKS
  http/
    gen/                   generated server and types
    handlers/              thin: decode → use case → encode
    middleware/            request id, trace, client IP, origin, CORS, auth, scope, rate limit, problems
  worker/                  relay, jobs, leader election
  ops/                     operator commands
test/e2e/                  end-to-end suites
```

Dependency rule: `domain` imports nothing internal; `app` imports `domain` and its own ports;
`adapters` and `http` import `app`. A CI check (`go-arch-lint` or a small `go list` test) enforces
it.

## 3. Configuration

YAML file (`--config`), with environment overrides `AUTH1_<SECTION>_<KEY>` for scalar values. Secrets
are **files** named in the configuration, never values.

```yaml
app:
  environment: production              # development | test | staging | production
http:
  listen: ":8080"
  base_path: ""
  issuer: https://id.example.com        # required
  trusted_proxies: [10.0.0.0/8]
keys:
  keyring_file: /secrets/signing/keyring.yaml
  min_publish_before_use: 15m
encryption:
  keyring_file: /secrets/fields/keyring.yaml
  blind_index_key_file: /secrets/fields/bidx.key
  mac_key_file: /secrets/mac/mac.key
  device_cookie_key_file: /secrets/mac/device.key
tokens:
  access_ttl: 15m                      # floor: at most 15m
  self_audience: ""                    # default: the issuer
  refresh_idle_ttl: 168h
  refresh_absolute_ttl: 720h
  refresh_reuse_grace: 10s             # at most 60s
clients:
  - id: web
    audience: example-web
    allowed_roles: [user]
    default_roles: [user]
    first_factors: [password]          # [password] | [password, otp]
    mfa: optional                      # optional | required (SDD D-8)
    otp_channel: sms                   # when otp is allowed: sms | email
    self_registration: true
    refresh_transport: cookie          # cookie | body
    origins: [https://www.example.com]
    link_base_url: https://www.example.com/account
identifiers:
  email: { required: true, verify: email_link, sign_in: true }
  phone: { required: false, verify: sms_otp, sign_in: false, calling_codes: [] }
passwords:
  min_length: 12                       # floor 8; 15 for strict NIST SP 800-63B-4 conformance (SDD D-7)
  max_length: 128                      # at least 64
  deny_list_file: /config/common-passwords.txt
  pepper_keyring_file: /secrets/pepper/keyring.yaml
  argon2:
    memory: 64MiB                      # floor 19MiB
    iterations: 2                      # floor 2
    parallelism: 1
    max_concurrent: 4
    queue_timeout: 2s
mfa:
  totp:
    issuer: Example                    # shown in authenticator apps
    label: email                       # email | display_name | none
    skew_steps: 1                      # at most 2
  recovery_codes: 10
  attempts_per_flow: 5
  sign_in_flow_ttl: 10m
otp:
  length: 6                            # floor 6
  ttl: 5m
  max_attempts: 3                      # at most 5
  cooldown: 15m
  resend_after: 60s
  max_sends_per_hour: 5
links:
  verification_ttl: 24h
  reset_ttl: 30m                       # at most 2h
  invitation_ttl: 72h
flows:
  pending_registration_ttl: 24h
recovery:
  via: email
  sms_step_up: false                   # SMS code for accounts without TOTP that have a verified phone (SDD D-10)
identifier_changes:
  confirm_old_email: required          # required | notify
roles:
  catalog: [user, admin]
  revoke_sessions_on_removal: true
bootstrap:
  roles: [admin]
  emails_file: /secrets/bootstrap/emails.txt
statuses:
  reason_codes: [policy_violation, admin_action]
  restricted_sign_in: true
locales:
  allowed: [en]
  default: en
delivery:
  adapter: notification                # notification | direct | capture (development only)
  notification:
    request_url: http://notification/v1/requests
  direct:
    smtp: { host: "", port: 587, from: "", username: "", password_file: "" }
    sms: { url: "", sender: "", token_file: "" }
    templates_dir: /config/templates
  retired_address_window: 168h
  notices:
    new_sign_in: false
  types: {}                            # purpose -> message type; defaults in TDD-06 §7
service_auth:
  mode: mesh                           # mesh | client_credentials | both; required outside development
  mesh:
    source: header                     # header | peer_cert
    header: x-forwarded-client-cert
    format: xfcc                       # xfcc | plain
    trusted_sidecar_cidrs: [127.0.0.1/32, "::1/128"]
    ca_file: ""                        # peer_cert only
  client_credentials:
    audience: auth1-services
    token_ttl: 5m                      # at most 15m
    clients:
      - id: billing
        jwks_file: /config/clients/billing.jwks.json   # or jwks_uri
  callers:
    - identity: spiffe://cluster.local/ns/example/sa/billing
      scopes: [tokens:introspect]
rate_limits:
  global_ip:          { limit: 600, window: 1m }
  sign_in_ip:         { limit: 30, window: 5m }
  registration_ip:    { limit: 5, window: 1h }
  reset_ip:           { limit: 10, window: 1h }
  reset_account:      { limit: 3, window: 1h }
  send_ip:            { limit: 20, window: 1h }
  verify_ip:          { limit: 30, window: 1h }
  resume_ip:          { limit: 10, window: 1h }
  token_client:       { limit: 60, window: 1m }
  factor_failures:    { limit: 10, window: 1h }
  sign_in_failures:   { threshold: 5, first_delay: 1s, max_delay: 15m }
  sms_budget_per_hour: 0               # required (> 0) when any SMS method is configured
events:
  exchange: auth1.events
  source: /auth1
outbox:
  poll_interval: 200ms
  batch_size: 100
  max_attempts: 20
  publish_timeout: 5s
database: { dsn_file: /secrets/db/dsn, max_conns: 20, acquire_timeout: 2s }
redis:    { address: redis:6379, prefix: "auth1:", password_file: "" }
amqp:     { url_file: /secrets/amqp/url }
retention:
  expired_registrations: 168h
  closed_challenges: 720h
  revoked_sessions: 2160h
  idempotency_keys: 24h
  published_outbox: 168h
  audit_client_details: 2160h
telemetry:
  otlp_endpoint: ""                    # empty: metrics on /metrics only, no trace export
  service_name: auth1
```

### 3.1 Validation

`auth1 serve` and `auth1 config check` refuse to start on any of:

- a missing required value: issuer, at least one client, the identifier policy, and every key file;
- a value below its floor, outside `development`:

| Setting | Floor |
|---|---|
| `tokens.access_ttl` | ≤ 15m |
| `tokens.refresh_reuse_grace` | ≤ 60s |
| `passwords.min_length` | ≥ 8 |
| `passwords.max_length` | ≥ 64 |
| `passwords.argon2.memory` | ≥ 19MiB |
| `passwords.argon2.iterations` | ≥ 2 |
| `otp.length` | ≥ 6 |
| `otp.max_attempts` | ≤ 5 |
| `mfa.totp.skew_steps` | ≤ 2 |
| `links.reset_ttl` | ≤ 2h |
| `service_auth.client_credentials.token_ttl` | ≤ 15m |

- `delivery.adapter: capture` or no `service_auth.mode` outside `development`;
- a client role outside the catalog; a client origin that is not `https` outside `development`;
- an SMS method configured with `sms_budget_per_hour: 0`;
- a keyring with zero or several `active` keys.

## 4. Secrets

| File | Holds | Rotation |
|---|---|---|
| `keys.keyring_file` + PEMs | Signing keys | §6.1 |
| `encryption.keyring_file` | Field-encryption keys | §6.3 |
| `encryption.blind_index_key_file` | Blind-index key | Rare; `auth1 crypto rebuild-bidx` |
| `encryption.mac_key_file` | OTP and recovery-code MAC key | Rotate between batches: open OTPs fail and are resent; recovery codes must be regenerated, so effectively never |
| `encryption.device_cookie_key_file` | Device-cookie MAC | Rotating it makes every device untrusted once |
| `passwords.pepper_keyring_file` | Pepper keys | Add, activate; old hashes rehash at sign-in; remove the old key when no hash uses it |
| `database.dsn_file`, `amqp.url_file`, `redis.password_file`, SMTP and SMS files | Credentials | By the platform |

Key files are 32 random bytes, base64. Mounted secrets are re-read on change where the SDD says so
(keyrings); the others are read at start-up.

## 5. Observability

### 5.1 Logs

JSON, one object per line, via `log/slog` (replacing Logrus). Fields: `ts`, `level`, `msg`,
`service`, `version`, `trace_id`, `span_id`, `request_id`, `account_id`, `client_id`, `caller`,
`event`, `error`.

- **Redaction** is applied by the handler. It covers `Authorization`, `Cookie`, `Set-Cookie`, and any key named `password`, `code`, `token`, `secret`, `email`, `phone`, `value`, `handle`, `recovery_code`.
- Identifier values are never logged, not even masked.
- Request logs record method, route pattern (not the raw path), status and duration.

### 5.2 Metrics

| Metric | Type | Labels |
|---|---|---|
| `auth1_sign_ins_total` | counter | `client`, `step` (`first_factor`, `second_factor`, `enrolment`), `result` (`ok`, `restricted`, `invalid`, `delayed`, `pending`, `role`, `mfa_required`, `enrolment_required`) |
| `auth1_refresh_total` | counter | `client`, `result` (`ok`, `grace`, `reuse`, `invalid`) |
| `auth1_registrations_total` | counter | `client`, `stage` (`started`, `completed`, `expired`) |
| `auth1_challenges_total` | counter | `purpose`, `result` (`sent`, `verified`, `wrong`, `exhausted`, `expired`) |
| `auth1_second_factor_total` | counter | `kind` (`totp`, `rcode`), `result` |
| `auth1_resolver_requests_total` | counter | `result` (`ok`, `partial`, `denied`) |
| `auth1_outbox_age_seconds` | gauge | `destination` |
| `auth1_outbox_parked` | gauge | `destination` |
| `auth1_introspections_total` | counter | `caller`, `active` |
| `auth1_service_calls_denied_total` | counter | `caller`, `scope` |
| `auth1_hash_duration_seconds` | histogram | — |
| `auth1_hash_queue_seconds` | histogram | — |
| `auth1_hash_rejected_total` | counter | — |
| `auth1_rate_limited_total` | counter | `rule` |
| `auth1_rate_limiter_errors_total` | counter | — |
| `auth1_sms_sent_total`, `auth1_sms_budget_remaining` | counter, gauge | — |
| `auth1_jwks_keys` | gauge | `state` |
| `auth1_job_last_success_timestamp` | gauge | `job` |

Plus the standard HTTP server metrics (OpenTelemetry semantic conventions), with `http.route`.

### 5.3 Traces

OpenTelemetry SDK, OTLP export. Spans per request, per use case, per database transaction and per
outbound call. Attributes never include identifier values or secrets. The incoming `traceparent` is
continued, and the outbox stores it so the relay's spans link to the request.

### 5.4 SLIs and alerts

**SLIs** (99.9% monthly): the share of sign-in, refresh and JWKS requests answered without a 5xx and
within 500 ms, 300 ms and 200 ms.

| Alert | Condition *(cfg thresholds)* | Runbook |
|---|---|---|
| SLO burn | > 14× over 1 h, or > 6× over 6 h | §6.8 |
| Delivery outbox age | > 30 s | §6.5 |
| Event outbox age | > 5 min | §6.5 |
| Parked rows | `auth1_outbox_parked > 0` | §6.5 |
| Refresh reuse | > 3× its 7-day baseline | §6.9 |
| Denied service calls | any increase | §6.10 |
| Key not promotable | any replica | §6.1 |
| Redis down | limiter errors > 0 for 5 min | §6.6 |
| Expiry job stalled | oldest expired open flow > 1 h | §6.11 |
| Hashing saturated | `auth1_hash_rejected_total` rate > 0 for 5 min | §6.12 |
| SMS budget | remaining < 10%, or exhausted | §6.7 |

## 6. Runbooks

Each is a short procedure kept in `docs/runbooks/`. To be written with the implementation:

1. **Signing-key rotation.** Add the key as `next`; wait `min_publish_before_use`; set it `active` and the old one `retired`; after access TTL + 5 min, remove the old key from the file.
2. **Signing-key compromise.** Add the new key as `active`; `auth1 keys force-activate`; remove the compromised key; `auth1 sessions revoke-all`; tell relying services to refresh their JWKS.
3. **Field-key rotation.** TDD-01 §3.1.
4. **Pepper rotation.** §4.
5. **Outbox backlog or parked rows.**
6. **Redis down.**
7. **SMS budget exhausted, or suspected toll fraud.**
8. **SLO burn.**
9. **Refresh-reuse spike.**
10. **Denied service calls.**
11. **Expiry job stalled.**
12. **Hashing saturated.**
13. **Point-in-time restore.** Restore; run migrations; `auth1 sessions revoke-all`; check `signing_keys` against the keyring; announce that people must sign in again.

## 7. Jobs

| Job | Every | Leader | Does |
|---|---|---|---|
| Relay (events, deliveries) | `poll_interval` / notify | No (`SKIP LOCKED`) | TDD-06 §3 |
| Flow expiry | 1 min | Yes | TDD-02 §2.5 |
| Successor erasure | 30 s | Yes | TDD-04 §3 |
| Purge | 1 h | Yes | TDD-01 §5 |
| Audit detail clearing | 1 h | Yes | Null `ip`, `user_agent` past 90 days; same for `sessions.user_agent` |
| Audit partitions | 1 day | Yes | Create the next 2 monthly partitions |
| Keyring sync | On change, 30 s poll | No | TDD-04 §5.2 |
| Bootstrap | Start-up | Yes | TDD-02 §8.1 |

**Leader election.**
- Each leader-elected job holds a session-level `pg_try_advisory_lock(<job id>)` on a dedicated connection.
- A lost connection loses the lock, and another replica takes over at its next tick.
- Every job records `auth1_job_last_success_timestamp`.

## 8. Deployment

- **Replicas and scheduling:** at least 2 replicas, anti-affinity across nodes, a `PodDisruptionBudget` of `maxUnavailable: 1`.
- **Resources:** CPU request 1, limit 2. Memory: 256 MiB + `max_concurrent × argon2.memory` + 25%.
- **Probes:** `/livez` (liveness), `/readyz` (readiness).
- **Migrations:** a pre-deploy job runs `auth1 migrate up`, and `auth1 config check` runs before it.
- **Image:** distroless, non-root, read-only root filesystem. Secrets are mounted read-only.

## 9. Testing

| Level | Tooling *(guideline)* | Scope |
|---|---|---|
| Unit | Go `testing`, table-driven; native fuzzing | Domain state machines (every cell of SDD §8.1); policies; normalisers, the XFCC parser, the PHC parser and cookie codecs (fuzzed) |
| Repository | `testcontainers-go` with PostgreSQL 18 | Every query; partial unique indexes; conditional updates; the relay claim under concurrency |
| API | A request/response validator against `api/openapi.yaml` (`pb33f/libopenapi-validator`, which handles OpenAPI 3.1) | Every endpoint's success and error shapes |
| Contract | `oasdiff`, the AsyncAPI CLI | Breaking changes; event examples valid |
| End to end | Containers: PostgreSQL, Redis, RabbitMQ, a fake notification service | SDD §15 acceptance cases |
| Load | k6 | Sign-in and refresh throughput; Argon2id tuning (SDD O-3) |
| Security | `govulncheck`; a ZAP baseline scan in CI against the e2e stack | Dependency and HTTP hygiene |

Every invariant (SDD §11) has at least one test that would fail if its enforcement were removed.

## 10. CI

On every pull request:
- `go vet`, `golangci-lint` and `govulncheck`
- unit, repository and API tests
- migrations up and down on an empty database
- `oasdiff` against the last release tag; AsyncAPI validation
- the layering check (§2)
- `auth1 config check` on the example configuration

On a release tag: the e2e suite, the image build and an SBOM.

## 11. To be detailed

- The OpenAPI code generator. Go generators' support for OpenAPI 3.1 varies. Proposal: generate types and a Chi server interface with `oapi-codegen`, and keep `api/openapi.yaml` within the subset it supports; or move the contract to 3.0.3 if that subset is too narrow. Decide with the first implementation step (SDD O-6).
- Runbook texts.
- Dashboards.
