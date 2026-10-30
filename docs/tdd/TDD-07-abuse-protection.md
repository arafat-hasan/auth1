# TDD-07 — Abuse protection

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-10-26 |
| SDD | [design.md](../design.md) 0.4: D-7, D-17, I-21, §12 |
| Owner | Arafat Hasan |

Rate limits, the client IP, sign-in throttling with device cookies, second-factor failure limits,
send limits and budgets, and overload behaviour.

## 1. Client IP

- `http.trusted_proxies` lists CIDRs: the product's edge and load balancers.
- **The client IP** is the right-most address in `X-Forwarded-For` that is not trusted, after appending the TCP peer address. If every hop is trusted, it is the left-most. With no trusted proxies, it is the TCP peer.
- **Limit key:** IPv4 addresses are used whole; IPv6 addresses by their /64 prefix.
- The audit records the full address (cleared after 90 days, TDD-01 §5).

## 2. Limits

| # | Control | Key | Store | Default *(cfg)* | Answer | On store failure |
|---|---|---|---|---|---|---|
| L-1 | Global | IP | Redis | 600 / 1 min | `RATE_LIMITED` | Fail open, alert |
| L-2 | Sign-in attempts | IP | Redis | 30 / 5 min | `RATE_LIMITED` | Fail open, alert |
| L-3 | Failed sign-ins | Account × device bucket (§4) | PostgreSQL | From the 5th failure, a delay doubling from 1 s to 15 min; reset on success | `SIGN_IN_DELAYED` | — |
| L-4 | Registrations | IP | Redis | 5 / 1 h | `RATE_LIMITED` | Fail open, alert |
| L-5 | Reset requests | IP | Redis | 10 / 1 h | 202 (silently not sent) | Fail open, alert |
| L-6 | Reset requests | Account | PostgreSQL (open and recent flows) | 3 / 1 h | 202 (silently not sent) | — |
| L-7 | Sends | Target value (blind index) | PostgreSQL (`challenges`) | 1 / 60 s; 5 / 1 h | `RESEND_TOO_SOON`, `RATE_LIMITED`; 202 where the endpoint always answers 202 | — |
| L-8 | Sends | IP | Redis | 20 / 1 h | as L-7 | Fail open, alert |
| L-9 | OTP attempts | Challenge | PostgreSQL | 3, then closed; 15-minute cooldown on new sends to that value | `CHALLENGE_CLOSED` | — |
| L-10 | Second-factor attempts | Flow | PostgreSQL | 5, then closed | `CHALLENGE_CLOSED` | — |
| L-11 | Second-factor failures | Account | PostgreSQL (`accounts.factor_failures`) | 10 / 1 h, across OTP, TOTP and recovery codes | `RATE_LIMITED` | — |
| L-12 | Failed verifications | IP | Redis | 30 / 1 h, across accounts | `RATE_LIMITED` | Fail open, alert |
| L-13 | SMS budget | Deployment | PostgreSQL (counter row per hour) | `sms_budget_per_hour` (no default: required when an SMS method is configured) | SMS sends refused, `UNAVAILABLE` | — |
| L-14 | Resume requests | IP | Redis | 10 / 1 h | 202 (silently not sent) | Fail open, alert |
| L-15 | Token endpoint | Client id | Redis | 60 / 1 min | `invalid_client` after `429` semantics | Fail open, alert |

Order of checks: per-IP limits first (cheap), then the per-account and per-value limits, then any
hashing. **Nothing hashes a password before L-1 and L-2 pass.**

## 3. Second-factor failures (L-11)

`accounts.factor_failures` and `factor_failures_since` form a fixed one-hour window:

```sql
UPDATE accounts
SET factor_failures = CASE WHEN factor_failures_since IS NULL OR factor_failures_since < now() - interval '1 hour'
                           THEN 1 ELSE factor_failures + 1 END,
    factor_failures_since = CASE WHEN factor_failures_since IS NULL OR factor_failures_since < now() - interval '1 hour'
                           THEN now() ELSE factor_failures_since END
WHERE id = $1
RETURNING factor_failures;
```

Before any verification, a count at the limit within the window refuses the request. A correct code
does not reset it. This counter is not the account's `version`; it does not emit events.

## 4. Sign-in throttling and device cookies (L-3)

**The device cookie.**
- **Name:** `__Host-auth1_dev`, `Path=/; Secure; HttpOnly; SameSite=Strict`, 1 year.
- **Value:** `base64url(device_id ‖ issued_at ‖ HMAC-SHA256(device_key, device_id ‖ issued_at))`.
- **Set** on every completed sign-in that does not already present a valid one. The `device_id` is a new UUIDv7, recorded on the session.

**Buckets.** On a sign-in attempt for account A:
- With a valid device cookie whose `device_id` appears on one of A's sessions (live, or ended within 90 days), the bucket is `device:<device_id>`.
- Otherwise the bucket is `untrusted`.

Failures increment only that bucket's row in `sign_in_throttles`. The delay applies only to that
bucket. So an attacker hammering A from anywhere fills `untrusted`, while A's own browser keeps
signing in through its device bucket.

**Native clients** send no cookie and always use `untrusted`. *(to be detailed: a device token in
the body for native clients)*

**A success** resets the bucket used. A password reset resets all of A's buckets.

## 5. Send limits per value (L-7)

Before a send, in the transaction, with the account locked, take a transaction-scoped lock on the
value, then count:

```sql
SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0));

SELECT count(*) FILTER (WHERE sent_at > now() - interval '60 seconds') AS last_minute,
       count(*) AS last_hour
FROM challenge_sends
WHERE target_bidx = $1 AND sent_at > now() - interval '1 hour';
```

The query covers every send to that value, whatever account, flow or challenge it was for (I-21).
`challenge_sends` holds one row per send (TDD-01 §4), written in the statement that counts the send
on the challenge, so each window counts exactly the sends made within it. Counting on `challenges`
cannot: `sends` and `last_sent_at` do not say when the earlier sends were, and a verification link
lives 24 h, so counting all of a challenge's sends whenever one was recent would let one send an
hour hold the value at its limit for every account. The windows are configuration *(cfg)*. The lock makes the check and the send
exact: two concurrent sends to one value from different accounts cannot both pass. It is taken
after the account, flow and challenge locks and held until commit; a use case sending to several
values checks them in one order, by type.

The 15-minute cooldown after an exhausted challenge (L-9) is checked the same way, on `closed_at`
of the challenges to that value closed unconsumed with `attempts >= max_attempts`: no close reason
is stored for a challenge, and this is what exhausted means (TDD-02 §2.2).

## 6. SMS budget (L-13)

- A row per hour in `sms_budget` (TDD-01 §4), incremented with `INSERT … ON CONFLICT DO UPDATE … RETURNING sent` when an SMS delivery row is written.
- Over budget, the send is refused: the user sees `UNAVAILABLE` with `Retry-After`, and the alert `sms_budget_exhausted` fires.
- **Calling codes** outside `calling_codes` never reach this point (TDD-01 §2.3). That is the first defence against toll fraud.

## 7. Overload

- **Argon2id semaphore** (TDD-03 §1.3). Waiting past `queue_timeout` answers `503 UNAVAILABLE` with `Retry-After: 1`. The metric `auth1_hash_queue_seconds` and the alert `hashing_saturated` follow it.
- **HTTP server timeouts:** read header 5 s, read 10 s, write 15 s, idle 60 s. Bodies are limited to 64 KiB.
- **Database pool:** a bounded pool. A request waits at most 2 s for a connection, then gets `UNAVAILABLE`.

## 8. Redis windows

The existing sliding-window limiter (sorted sets, `rl:<rule>:<key>`) is kept for L-1, L-2, L-4,
L-5, L-8, L-12, L-14 and L-15. Keys are prefixed with `redis.prefix`.

- **Fail open**, metric and alert on any Redis error. These limits slow abuse; the PostgreSQL controls protect accounts.
- **Headers** on `429`: `Retry-After`. *(guideline: also `RateLimit-Policy` and `RateLimit` when the IETF draft is final)*.

## 9. Bot defence port

A `Challenge` port (not to be confused with flow challenges) with no adapter in 1.0. Registration,
resume, reset requests and OTP sign-in call it with the request context. The default adapter allows
everything. A product can later add CAPTCHA or risk scoring here (SDD O-8).

## 10. To be detailed

- Device binding for native clients.
- Whether L-3 should also slow the `untrusted` bucket per IP, to stop one IP from delaying many accounts' untrusted buckets cheaply (it can today, which only costs those accounts' owners on new devices).
- Default values for `sms_budget_per_hour`, from the product's expected volume.
