# TDD-06 — Events and message delivery

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.2 |
| Date | 2026-10-27 |
| SDD | [design.md](../design.md) 0.4: D-15, D-16, I-7, I-8, I-15 |
| Owner | Arafat Hasan |

The outbox, the relay, the CloudEvents mapping, the delivery port and its adapters, the resolver
hook, and security notices.

## 1. The outbox

One table, two destinations (TDD-01 §4):

| Destination | Written by | Relayed to | Order |
|---|---|---|---|
| `event` | Every use case that changes an account | AMQP topic exchange | Per account, by `account_version` |
| `delivery` | Every send of a challenge or a notice | The delivery adapter | None |

Rows are written only through the unit of work, in the use case's transaction (I-7). The `body` of
an event row is the CloudEvent's `data`. The `body` of a delivery row is the delivery request (§5).

## 2. Versions and event order

Inside a use case's transaction, with the account row locked (TDD-01 §4.2):

1. Read `v = accounts.version`.
2. Give the i-th event of this transaction `account_version = v + i` (i from 1).
3. At the end: `UPDATE accounts SET version = v + max(1, n)`, where `n` is the number of events.

Versions are **monotonic, not contiguous**: a change with no event (a TOTP replacement) still moves
the version. Step 3 runs for every account the transaction locked, so a committed lock with no
change (an idempotent no-op) moves it too (TDD-01 §4.2). Consumers must accept gaps and use the
version only to order and to discard stale data.

## 3. The relay

Every replica runs the relay. Each loop claims rows, publishes them and records the outcome.

### 3.1 Events

```sql
SELECT o.*
FROM outbox o
WHERE o.destination = 'event'
  AND o.published_at IS NULL AND o.parked_at IS NULL
  AND o.next_attempt_at <= now()
  AND NOT EXISTS (
      SELECT 1 FROM outbox p
      WHERE p.destination = 'event' AND p.subject = o.subject
        AND p.published_at IS NULL AND p.account_version < o.account_version)
ORDER BY o.created_at
LIMIT $1
FOR UPDATE SKIP LOCKED;
```

A row is claimable only if no earlier unpublished event of its account exists, **including a parked
one** (I-8). Two replicas never publish one account's events out of order: the earlier row is
either locked by the other replica, which makes the later row unclaimable, or already published.

For each claimed row, in its own small transaction:
1. Publish with publisher confirms (timeout 5 s *(cfg)*).
2. **On confirm:** set `published_at`.
3. **On failure:** `attempts + 1`, `next_attempt_at = now() + backoff(attempts)`, and `last_error`.
   - The backoff is exponential with ±20% jitter, from 1 s to 5 min.
   - At `outbox.max_attempts` (20 *(cfg)*), set `parked_at` and alert.

**Operator commands:**
- `auth1 outbox list --parked`
- `auth1 outbox retry <id>`: clears `parked_at` and resets `attempts`.
- `auth1 outbox skip <id>`: marks the row published with `last_error = 'skipped by operator'`, and audits.

### 3.2 Deliveries

The claim is `destination = 'delivery' AND published_at IS NULL AND parked_at IS NULL AND
next_attempt_at <= now()`, ordered by `next_attempt_at`, with `FOR UPDATE SKIP LOCKED`.

1. **Drop what can no longer work.** For a secret-bearing row, if the challenge has closed, mark it published with `last_error = 'dropped: challenge closed'` and do not send. A notice is dropped after 24 h.
2. **Hand the row to the adapter** (§8).
3. **By outcome:**
   - 2xx, or a duplicate: published.
   - A 4xx other than 408 or 429: parked, and alert. The request is wrong; retrying will not help.
   - Anything else: backoff as for events, capped at the challenge's expiry.

### 3.3 Latency

`outbox.poll_interval` is 200 ms. *(guideline)* Also `pg_notify('auth1_outbox', destination)` in the
writing transaction, with the relay `LISTEN`ing, so a committed OTP is picked up at once. The poll
remains as the safety net.

## 4. CloudEvents

**Mode:** structured JSON, `content_type = application/cloudevents+json`.

**AMQP:**
- `message_id` = the event id;
- persistent delivery mode;
- routing key = `type`;
- the exchange is `events.exchange` (topic, durable).

| Attribute | Value |
|---|---|
| `specversion` | `1.0` |
| `id` | The outbox row's UUIDv7. Consumers deduplicate on it |
| `source` | `events.source` (default `/auth1`) |
| `type` | Below |
| `subject` | The account id |
| `time` | The transaction's commit time, RFC 3339 UTC |
| `datacontenttype` | `application/json` |
| `dataversion` | Extension. Integer version of `data`'s schema, from 1 |
| `accountversion` | Extension. The row's `account_version` |
| `traceparent`, `tracestate` | Extension (distributed tracing) |

Every `data` carries `account_id` and `actor`: `{kind: account|service|operator|system, id,
on_behalf_of}`.

| Type | `data` (besides `account_id`, `actor`) |
|---|---|
| `account.registered` | `client_id` (or `invitation`), `roles`, `locale` |
| `account.identifier_verified` | `identifier_id`, `identifier_type` |
| `account.identifier_changed` | `identifier_type`, `identifier_id`, `previous_identifier_id` |
| `account.profile_updated` | `changed`: list of `display_name`, `locale` |
| `account.password_changed` | — |
| `account.password_reset` | `second_factor` (`totp`, `recovery_code`, `sms`, `none`) |
| `account.mfa_enrolled` | `via` (`self_service`, `sign_in`) |
| `account.mfa_removed` | — |
| `account.mfa_reset` | — |
| `account.status_changed` | `status`, `previous_status`, `reason_code`, `until`, `sessions_revoked` |
| `account.roles_changed` | `roles`, `previous_roles`, `added`, `removed` |
| `account.sessions_revoked` | `reason`, `count` |
| `account.registration_expired` | `client_id` (or `invitation`) |
| `account.deleted` | — |

`account.sessions_revoked` reports revocations of every session at once (a service, a status
change, a role removal, an operator), not sign-outs.

**No identifier value, display name or secret appears in any event** (SDD T-9). The schemas and
examples are in `api/asyncapi.yaml`, which is the final word.

## 5. Delivery requests

```json
{
  "request_id": "0192…:2",
  "type": "auth.phone_verification_code",
  "channel": "sms",
  "locale": "en",
  "recipient": "auth1:identifier:0192…",
  "variables": { "code": "auth1:secret:0192…" },
  "deadline": "2026-10-26T10:05:00Z",
  "traceparent": "00-…",
  "resolver": "auth1"
}
```

| Reference | Resolves to |
|---|---|
| `auth1:identifier:<identifier id>` | The identifier's value |
| `auth1:challenge-target:<challenge id>` | The challenge's `target_value` (an address under change) |
| `auth1:secret:<challenge id>` | The OTP |
| `auth1:link:<challenge id>` | The full URL: `link_base_url` + the purpose's path + `#token=<token>` |

- **`request_id`** is `<challenge id>:<send number>` for a challenge, and `<outbox id>` for a notice.
- **`deadline`** is the challenge's expiry, so the notification service can drop late messages itself.
- **Plain variables** (for notices) are non-secret values only, for example `remaining_codes`, `client_id`, `occurred_at`.

## 6. The resolver hook

`POST /v1/hooks/delivery/resolve` (`delivery:resolve`), body `{request_id, references[]}`, answer
`{values: {<reference>: <value>}}`, headers `Cache-Control: no-store`.

Rules, checked for each reference:

1. **The request was really sent.** The `request_id` must name a delivery outbox row (kept 7 days), and the reference must appear in that row's body. auth1 resolves only what it asked to send. Possessing a challenge id is not enough (I-20).
2. **Secrets and challenge targets:** the challenge is open (`closed_at` null, `expires_at` in the future, `attempts < max_attempts`).
3. **Identifiers:** current; or, for a notice row, retired less than `delivery.retired_address_window` ago (7 days).
4. **Anything else** is omitted from `values`, which means "do not send".

Resolving reads only. It changes no counter or row (I-15), so a retry by the notification service
is harmless. Each call is audited (request id, number resolved, number omitted) and counted in
`auth1_resolver_requests_total`. Values are never logged.

## 7. Message types

| Purpose | Default type | Channel | Variables | Secret |
|---|---|---|---|---|
| Phone verification | `auth.phone_verification_code` | SMS | `code` | Yes |
| Email verification | `auth.email_verification_link` | Email | `link` | Yes |
| Resume | `auth.registration_resume` | the identifier's | `code` or `link` | Yes |
| Sign-in code | `auth.sign_in_code` | SMS or email | `code` | Yes |
| Reset link | `auth.password_reset_link` | Email | `link` | Yes |
| Reset step-up (accounts without TOTP, `recovery.sms_step_up`) | `auth.password_reset_code` | SMS | `code` | Yes |
| Email change, old address | `auth.email_change_confirm_old` | Email | `link` | Yes |
| Email change, new address | `auth.email_change_confirm_new` | Email | `link` | Yes |
| Phone change | `auth.phone_change_code` | SMS | `code` | Yes |
| Invitation | `auth.invitation_link` | Email | `link`, `display_name` (reference) | Yes |
| Notice: password changed / reset | `auth.notice_password_changed` | Email | `occurred_at`, `how` | No |
| Notice: email change requested | `auth.notice_email_change_requested` | Email (old address) | `occurred_at` | No |
| Notice: identifier changed | `auth.notice_identifier_changed` | Email (old address, or the account's email) | `type`, `occurred_at` | No |
| Notice: MFA enrolled / replaced / removed / reset | `auth.notice_mfa_changed` | Email | `change`, `occurred_at` | No |
| Notice: recovery codes regenerated / one used | `auth.notice_recovery_codes` | Email | `change`, `remaining_codes` | No |
| Notice: sessions revoked | `auth.notice_sessions_revoked` | Email | `reason`, `occurred_at` | No |
| Notice: new sign-in *(off by default)* | `auth.notice_new_sign_in` | Email | `client_id`, `user_agent`, `occurred_at` | No |

Type names are configuration (`delivery.types`, keyed by purpose: the default type without
`auth.`, for example `password_reset_link`). Notices go to the account's current verified email.
When the deployment has no email identifier type, they go to the account's first verified
identifier by type name, by that type's channel. A notice to an identifier retired less than
`delivery.retired_address_window` ago (the old address after a change) is still sent.

## 8. Adapters

### 8.1 `notification`

The relay `POST`s the request to `delivery.notification.request_url` over the mesh, with the
request id as the idempotency key (`Idempotency-Key` header). The notification service later calls
the resolver (§6).

### 8.2 `direct`

- **Resolution.** The relay resolves the references itself, in process, under the same rules as §6, just before sending.
- **Templates:** `templates_dir/<type>/<locale>/` holds `subject.txt`, `body.txt` and `body.html` for email, and `sms.txt` for SMS. Rendered with `text/template` and `html/template`; a missing locale falls back to `locales.default`.
- **Email:** SMTP with mandatory STARTTLS (or implicit TLS on 465), and authentication from a mounted secret.
- **SMS:** a generic HTTP provider, `POST {to, text, sender}` with a bearer token from a mounted secret. Provider-specific shapes need their own small adapter.
- Neither the rendered message nor the resolved values are logged.

### 8.3 `capture`

- Keeps the last 1000 messages in memory, values resolved, readable at `GET /dev/messages?to=<value>`.
  The route is not part of the API contract and sits at the root, beside `/livez`, not under
  `http.base_path`.
- Allowed only when `app.environment` is `development`. Start-up refuses it elsewhere (SDD T-17).
- End-to-end tests use it, or a fake notification service that calls the resolver.

## 9. Implementation guidelines *(guideline)*

- `OutboxWriter` (inside the unit of work): `Event(type, accountID, data)` and `Delivery(request)`. The use case never builds CloudEvents itself.
- `MessageDelivery` port: `Send(ctx, row) Outcome`. The relay owns retries, so adapters stay stateless.
- One relay goroutine pool per destination, so a slow broker never delays OTPs.

## 10. To be detailed

- The exact `DeliveryRequest` JSON schema, aligned with the notification service (SDD O-1).
- The link paths per purpose under `link_base_url`.
- Dead-lettering on the broker side (the product's concern), and whether auth1 declares the exchange or expects it to exist.
