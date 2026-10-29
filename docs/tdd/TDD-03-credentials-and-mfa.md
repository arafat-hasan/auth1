# TDD-03 — Credentials and multi-factor authentication

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.2 |
| Date | 2026-10-27 |
| SDD | [design.md](../design.md) 0.4: D-7, D-8, D-9, D-10, I-16 … I-19 |
| Owner | Arafat Hasan |

Passwords, the optional TOTP factor, recovery codes, enrolment (forced and self-service), removal,
reauthentication and the service-driven MFA reset. MFA is optional per account, and a client may
require it (SDD D-8).

## 1. Password hashing

### 1.1 Input

1. Normalise the password to Unicode NFKC (NIST SP 800-63B-4). Length is counted in code points after normalisation.
2. Pepper: `p = HMAC-SHA256(pepper[active_kid], normalised_password)`, 32 bytes.
3. `hash = Argon2id(p, salt, m, t, p_lanes, 32)`, with a 16-byte salt from `crypto/rand`.

The pepper keyring (`passwords.pepper_keyring_file`) has the same shape as the field keyring:
`{id, key, state: active|verify}`, with exactly one active key.

### 1.2 Storage

`password_credentials.hash` holds the PHC string:
`$argon2id$v=19$m=65536,t=2,p=1$<salt, base64 without padding>$<hash, base64 without padding>`.
`pepper_kid` holds the pepper key id.

### 1.3 Parameters

| Parameter | Default *(cfg)* | Floor |
|---|---|---|
| `memory` | 64 MiB | 19 MiB |
| `iterations` | 2 | 2 |
| `parallelism` | 1 | 1 |
| `max_concurrent` (per replica) | 4 | 1 |
| `queue_timeout` | 2 s | — |

A stored hash's parameters are bounded too: memory at most 1 GiB, iterations and parallelism at
most 16. A PHC string beyond them is refused as invalid before anything is allocated, so a corrupt
row cannot exhaust memory, and the configuration may not exceed them (TDD-08 §3.1).

The final values come from the load test (SDD O-3). Target: 100–250 ms per hash on the production
CPU, with `max_concurrent × memory` within the pod's memory limit plus headroom.

### 1.4 Verification

1. **Acquire a semaphore slot** within `queue_timeout`; otherwise answer `503 UNAVAILABLE` with `Retry-After: 1`.
2. **Parse the PHC string** and recompute with its own parameters and the pepper key `pepper_kid`. Compare with `subtle.ConstantTimeCompare`.
3. **Rehash** if the stored parameters differ from the configured ones, or if `pepper_kid` is not the active pepper key. Hash afresh, outside the transaction, and write it in the sign-in's transaction.
4. **Unknown identifier:** verify against a dummy PHC string computed at start-up with the current parameters, so the time is the same.
5. **Never** hash or verify inside a database transaction.

### 1.5 Changing the password

`POST /v1/me/password` (`current_password`, `second_factor` when the account has TOTP, `new_password`), with a full session:

1. Reauthenticate (§5.1).
2. Check the policy (§2), then hash.
3. `[tx]`:
   - store the hash and `changed_at`;
   - revoke every session except the current one;
   - send the `password_changed` notice;
   - emit `account.password_changed`.
4. Answer `204`.

## 2. Password policy

Checks, in order. Each failure adds a reason to `PASSWORD_REJECTED.reasons`.

| Reason | Rule |
|---|---|
| `too_short` | Fewer than `min_length` code points (default 12, floor 8; SDD D-7 records the deviation from NIST's 15 for single-factor passwords) |
| `too_long` | More than `max_length` code points (default 128, at least 64) |
| `contains_identifier` | The case-folded password contains any `Variants()` (TDD-01 §2) of the account's identifiers, ignoring variants shorter than 4 characters |
| `common` | The case-folded password is in the deny-list |

- No composition rules, no periodic expiry, no hints.
- **The deny-list** is a file of one password per line, loaded at start-up into a hash set. *(guideline: start from a public list of the 100 000 most common passwords, plus product-specific words in the product's configuration repository)*.
- **Every character is accepted**, including spaces and emoji.

## 3. Second-factor verification

One component verifies a `second_factor` value for an account. Sign-in (TDD-02 §5.3), reset
(TDD-02 §6) and reauthentication (§5) all use it.

### 3.1 TOTP

- RFC 6238: HMAC-SHA1, 6 digits, a 30 s step, and drift of ±1 step *(cfg: `mfa.totp.skew_steps`)*.
- **Acceptance:**
  1. Decrypt the confirmed secret. Compute the codes for steps `s-1`, `s`, `s+1`, and compare each in constant time.
  2. On a match at step `m`: `UPDATE totp_factors SET last_step = $m WHERE account_id = $1 AND confirmed_at IS NOT NULL AND (last_step IS NULL OR last_step < $m)`.
  3. If no row is updated, the code was already used (I-19). Treat it as a wrong code.
- *(guideline)* Implement RFC 6238 directly (about 40 lines) and test it with the RFC's Appendix B vectors. That gives exact control over step tracking.

### 3.2 Recovery codes

| Item | Rule |
|---|---|
| Count | 10 *(cfg)* per batch |
| Format | 10 characters of Crockford base32 (50 bits), shown as `XXXXX-XXXXX` |
| Input normalisation | Upper-case; drop spaces and hyphens; map `I`, `L` → `1` and `O` → `0` |
| Stored | `HMAC-SHA256(mac_key, "rcode|" ‖ account_id ‖ "|" ‖ code)` |
| Use | `UPDATE recovery_codes SET used_at = now() WHERE account_id = $1 AND code_mac = $2 AND used_at IS NULL` (I-18) |
| After use | Send the `recovery_code_used` notice with the number remaining; `GET /v1/me` shows the count |

### 3.3 Failures

- Every wrong code increments the flow's `attempts` when there is a flow (sign-in, reset, enrolment). At 5 *(cfg)*, the flow closes (`attempts`) and the answer is `CHALLENGE_CLOSED`.
- Every wrong code also counts in `accounts.factor_failures` (TDD-07 §3). While that is at its limit, verification is refused with `RATE_LIMITED` before any code is checked.
- A correct code never resets `factor_failures`. The counter's window does that.

### 3.4 The second step of sign-in

**Deciding it.** After the first factor (TDD-02 §5.1 step 9, §5.2), and after registration or
invitation completion (TDD-02 §3, §8), in this order:

| The account | The client's `mfa` | Answer |
|---|---|---|
| Has a confirmed TOTP | any | `202 MFA_REQUIRED`; the `sign_in` flow moves to step `second_factor` |
| Has none | `required` | `202 MFA_ENROLMENT_REQUIRED`; the flow moves to step `enrolment` (§4.1) |
| Has none | `optional` | Complete the sign-in at once (TDD-02 §5.3); `200` with the tokens |

**Completing it.** `POST /v1/sessions/mfa` (`handle`, `second_factor`). The flow must be a
`sign_in` at step `second_factor`. Verify (§3.1, §3.2), then complete the sign-in (TDD-02 §5.3).
The session's `amr` is set by §7.

## 4. Enrolment

Enrolment has two entry points, which share the secret handling and the confirmation: **forced**
(§4.1), inside a sign-in on a `required` client; and **self-service** (§4.2), by a signed-in person.

### 4.1 Forced, inside sign-in

1. **Start.** `POST /v1/sessions/mfa/enrolment` (`handle`), for a `sign_in` flow at step `enrolment`:
   - draw a 20-byte secret (160 bits);
   - `[tx]` upsert the `totp_factors` row with `confirmed_at = null`, replacing an earlier unconfirmed secret;
   - answer `200` with `secret` (base32) and `otpauth_uri`: `otpauth://totp/<issuer>:<label>?secret=…&issuer=<issuer>&algorithm=SHA1&digits=6&period=30`. `<issuer>` is `mfa.totp.issuer` *(cfg)*. `<label>` follows `mfa.totp.label`: `email`, `display_name` or `none`.
   - Calling start again before confirming issues a new secret.
2. **Confirm.** `POST /v1/sessions/mfa/enrolment/confirm` (`handle`, `code`):
   1. Verify the code against the unconfirmed secret (§3.1, with `last_step`). Failures count (§3.3).
   2. `[tx]`:
      - set `confirmed_at` and `last_step`;
      - create a batch of recovery codes;
      - send the `mfa_enrolled` notice;
      - emit `account.mfa_enrolled`;
      - complete the sign-in (TDD-02 §5.3).
   3. Answer `200` with the tokens and `recovery_codes`. The response carries `Cache-Control: no-store`. The codes are never shown again.

### 4.2 Self-service

1. **Start.** `POST /v1/me/totp` (`current_password`), with a full session:
   - reauthenticate with the password (§5.1);
   - refuse with `409 MFA_STATE_INVALID` if the account already has a confirmed TOTP (replacement is §5.2);
   - draw a secret and `[tx]` upsert the unconfirmed `totp_factors` row, as in §4.1;
   - answer `200` with `secret` and `otpauth_uri`.
2. **Confirm.** `POST /v1/me/totp/confirm` (`code`):
   - verify the code against the unconfirmed secret;
   - `[tx]`: set `confirmed_at` and `last_step`, create a batch of recovery codes, send the `mfa_enrolled` notice, and emit `account.mfa_enrolled`;
   - answer `200` with `recovery_codes` and `Cache-Control: no-store`.

The current session is unchanged: its `amr` still records how it signed in. From the next sign-in
on, every client asks for the second factor.

**I-16 holds by construction.** Every path that issues a session passes the decision of §3.4. It
issues one without a second factor only for an account with no confirmed TOTP on an `optional`
client; every other path requires a verified second factor (§3.4, §4.1).

## 5. Reauthentication and sensitive operations

### 5.1 Reauthentication

Every sensitive operation's request carries `current_password`, and `second_factor` when the account
has a confirmed TOTP. Checks:

1. Refuse if the session is restricted (`ACCOUNT_RESTRICTED`).
2. Refuse while the sign-in throttle bucket for this account and device is delayed (`SIGN_IN_DELAYED`).
3. Verify the password (§1.4). A failure counts in the throttle bucket.
4. If the account has a confirmed TOTP, verify the second factor (§3); a missing one is a failure. A failure counts in `factor_failures`. For an account without TOTP, a `second_factor` in the request is ignored.
5. Any failure answers `REAUTHENTICATION_REQUIRED`, without saying which part failed.

### 5.2 Replacing the TOTP factor

1. `POST /v1/me/totp/replacement` (`current_password`, `second_factor`):
   - refuse with `409 MFA_STATE_INVALID` if the account has no confirmed TOTP (enabling is §4.2);
   - reauthenticate;
   - draw a secret, and `[tx]` open a `totp_replacement` flow with `pending_secret` set;
   - answer `200` with `flow_id`, `handle`, `secret` and `otpauth_uri`.
2. `POST /v1/me/totp/replacement/{flowId}/confirm` (`handle`, `code`):
   - verify the code against `pending_secret`;
   - `[tx]`: replace `totp_factors.secret`, set `last_step` to the matched step and `confirmed_at = now()`, complete the flow (which erases `pending_secret`), and send the `mfa_replaced` notice;
   - answer `204`.

Recovery codes are kept. No event is emitted: consumers have nothing to act on. `version` still
increments (TDD-06 §2).

### 5.3 Regenerating recovery codes

`POST /v1/me/recovery-codes` (`current_password`, `second_factor`):
1. Refuse with `409 MFA_STATE_INVALID` if the account has no confirmed TOTP. Reauthenticate.
2. `[tx]`: delete the old batch, insert a new one, and send the `recovery_codes_regenerated` notice.
3. Answer `200` with the codes and `Cache-Control: no-store`.

### 5.4 Removing MFA

`DELETE /v1/me/totp` (`current_password`, `second_factor`):
1. If the account has no confirmed TOTP, answer `204`: removal is idempotent.
2. Reauthenticate.
3. `[tx]`:
   - delete the `totp_factors` row and every recovery code;
   - cancel open `totp_replacement` flows;
   - revoke every session except the current one;
   - send the `mfa_removed` notice;
   - emit `account.mfa_removed`.
4. Answer `204`.

Sessions are revoked because removing the factor lowers the account's protection: an attacker who had
reached the account should not keep a session the owner does not see. The next sign-in on a
`required` client enrols again.

## 6. MFA reset by a service

`POST /v1/accounts/{id}/mfa/reset` (`accounts:mfa:reset`, `Idempotency-Key`, `Auth1-Actor`). The
account must not be `pending` or `deleted`. `[tx]`:

- delete the `totp_factors` row and every recovery code;
- cancel open `sign_in` and `totp_replacement` flows;
- revoke every session;
- send the `mfa_reset` notice;
- emit `account.mfa_reset`;
- audit with the caller and the actor.

Answer `204`. The next sign-in on a `required` client leads to enrolment; on an `optional` client the account signs in with its password and may enable TOTP again (§4.2).

## 7. `amr`

| First factor | Second factor | `amr` |
|---|---|---|
| Password | — (no TOTP, `optional` client) | `["pwd"]` |
| SMS code | — | `["sms"]` |
| Email code | — | `["email"]` |
| Password | TOTP | `["pwd","otp","mfa"]` |
| Password | Recovery code | `["pwd","rcode","mfa"]` |
| SMS code | TOTP | `["sms","otp","mfa"]` |
| Email code | TOTP | `["email","otp","mfa"]` |
| SMS code | Recovery code | `["sms","rcode","mfa"]` |
| Email code | Recovery code | `["email","rcode","mfa"]` |
| Any | Enrolment confirmation | As with TOTP |

The session keeps its `amr` and `auth_time`; every token issued from it repeats them.

## 8. Implementation guidelines *(guideline)*

- `PasswordHasher` port: `Hash(password) (phc, kid string, err error)` and `Verify(password, phc, kid) (ok, needsRehash bool, err error)`. The semaphore lives in the adapter.
- `SecondFactor` component: `Verify(ctx, tx, accountID, value, flow *Flow) (kind string, err error)`, where `kind` is `otp` or `rcode`.
- Keep TOTP secrets decrypted only for the time needed to compute the codes, and zero the buffers afterwards (best effort in Go).
- Benchmarks for the hasher on CI hardware guard against an accidental parameter drop.

## 9. To be detailed

- The final Argon2id parameters and `max_concurrent` (SDD O-3).
- Whether recovery codes are offered for download as a file by the client (client concern) and whether auth1 says so in the contract.
- The deny-list's source and size.
