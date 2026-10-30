# TDD-02 — Flows and challenges

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.2 |
| Date | 2026-10-27 |
| SDD | [design.md](../design.md) 0.4: D-3, D-4, D-5, D-6, D-10, D-11, §8, §9 |
| Owner | Arafat Hasan |

How every multi-step interaction is built: the flow and challenge machinery, then each flow. The
second-factor steps inside flows are specified in TDD-03; token issuing in TDD-04. Endpoint paths
here match `api/openapi.yaml`, which is the final word on shapes.

## 1. Conventions

- Every step is one use case and one transaction `[tx]`, except password hashing, which happens before the transaction opens.
- A **handle** is sent in the JSON body as `handle`. A flow id in a path is never enough without it (I-20).
- A **second factor** in a body is `second_factor: {"totp": "123456"}` or `second_factor: {"recovery_code": "ABCDE-FGHJK"}`.
- Every failure is audited with the flow id and kind, never a secret.

## 2. Machinery

### 2.1 Flows

| Kind | Lifetime *(cfg)* | `state` (non-secret JSON) |
|---|---|---|
| `registration` | 24 h | `pending_types` |
| `invitation` | 72 h | `roles`, `accepted`, `pending_types` |
| `sign_in` | 10 min | `first_factor` (`pwd`, `sms`, `email`), `step` (`first_factor`, `second_factor`, `enrolment`), `device_id` |
| `password_reset` | 30 min | `started`, `proof` (`totp`, `sms`, `none`) |
| `email_change` | 24 h | `confirm_old` (`required`, `notify`, `support`), `old_confirmed`, `new_confirmed` |
| `phone_change` | 15 min | — |
| `totp_replacement` | 10 min | — (the pending secret is in `flows.pending_secret`, encrypted) |

- **Opening** a flow draws a 256-bit handle (base64url, 43 characters) and stores its SHA-256.
- **Opening a flow of the same kind** for the same account cancels the previous open one (`close_reason = 'replaced'`), except `sign_in`, where several may be open (several devices).
- **Finding** a flow: `SELECT … FROM flows WHERE id = $1 AND handle_hash = sha256($2) AND completed_at IS NULL AND cancelled_at IS NULL AND expires_at > now() FOR UPDATE`. No match answers `CHALLENGE_CLOSED`; the answer is the same for an unknown id, a wrong handle and an expired flow.
- **Closing** sets `completed_at` or `cancelled_at` with `close_reason` (`replaced`, `expired`, `account_closed`, `attempts`), and closes the flow's open challenges (§2.3).

The columns behind this (`state`, `pending_secret`, `close_reason`, `attempts`) are in TDD-01 §4.

### 2.2 Secrets

| Kind | Generation | Stored |
|---|---|---|
| OTP | 6 digits *(cfg, ≥ 6)*, uniform from `crypto/rand` (rejection sampling, no modulo bias) | `HMAC-SHA256(mac_key, "otp|" ‖ challenge_id ‖ "|" ‖ code)` (TDD-01 §3.3); encrypted copy while open |
| Link token | 32 random bytes, base64url | SHA-256; encrypted copy while open |
| Handle | 32 random bytes, base64url | SHA-256 only |

**Verifying** an OTP:
1. Compute the MAC of the input and compare it in constant time with `secret_mac`.
2. Under the challenge row lock, increment `attempts` with `UPDATE … SET attempts = attempts + 1 WHERE id = $1 AND closed_at IS NULL AND attempts < max_attempts RETURNING attempts` (I-4).
3. On a wrong code, answer `CODE_INVALID` with `attempts_left`. At `max_attempts`, close the challenge (`exhausted`) and answer `CHALLENGE_CLOSED`.
4. Count the failure against the account's second-factor failures (TDD-07).

A **link token** is found by `secret_mac = sha256(token)` through the unique index, so there is no attempt counter: a wrong token simply matches nothing.

### 2.3 Challenges

| Purpose | Method | Target | Opened by |
|---|---|---|---|
| `verify_identifier` | the type's method | the identifier | registration, invitation acceptance |
| `resume` | the type's method | the identifier | resume (§4) |
| `invitation` | `email_link` | the invited email | invitation |
| `sign_in` | `sms_otp` or `email_code` | the sign-in identifier | OTP sign-in (§5.2) |
| `reset_link` | `email_link` (or the `recovery.via` type's link/code method) | the recovery identifier | reset request |
| `reset_step_up` | `sms_otp` | the account's verified phone | reset start, when the proof is `sms` (§6) |
| `email_change_old` | `email_link` | the current email | email change, `confirm_old: required` |
| `email_change_new` | `email_link` | the new value (`target_value`) | email change |
| `phone_change` | `sms_otp` | the new value (`target_value`) | phone change |

Every challenge stores `target_bidx`, the blind index of the address it is sent to. Send limits use
it (TDD-07 §5).

**Closing** a challenge sets `closed_at`, and `consumed_at` when it was used, and sets `secret` to null in the same statement (I-5).

### 2.4 Sending and resending

**Sending** a challenge, inside the use case's transaction:
1. Check the send limits for `target_bidx` (TDD-07 §5). On refusal, answer `RESEND_TOO_SOON` or `RATE_LIMITED`.
2. Increment `sends` and set `last_sent_at`.
3. Write a delivery outbox row (TDD-06 §5): `request_id = <challenge id>:<sends>`.

**Resend** (`POST …/resend` with the handle and the identifier type):
- reuses the open challenge and its secret, and runs the same three steps;
- if the challenge has closed by expiry, opens a new one with a new secret;
- if it has closed because its attempts are exhausted, refuses during the cooldown (15 min *(cfg)*).

### 2.5 Expiry

A job runs every minute on the leader:
1. Take up to 500 open flows with `expires_at < now()`, `FOR UPDATE SKIP LOCKED`.
2. Close each one (`expired`) and close its challenges.
3. For an expired `registration` or `invitation` whose account is still `pending`:
   - retire every current identifier (I-12);
   - set the account `deleted` (`status_reason` stays null; `registered_via` keeps the origin);
   - emit `account.registration_expired`.
4. Close challenges past `expires_at` in open flows, which erases their secrets.

The purge job deletes those `pending`-then-`deleted` accounts and their rows 7 days later *(cfg)*.

## 3. Registration

`POST /v1/registrations`, with `client_id`, `display_name`, `locale`, `identifiers: {type: value}`
and `password`:

1. The client exists and has `self_registration`. The per-IP registration window allows it.
2. Every required type is present, and no unknown type. Each value normalises (`IDENTIFIER_NOT_ALLOWED`).
3. No value is another account's verified, current identifier (`IDENTIFIER_TAKEN`). This reveals that the value is taken: a product requirement (SDD §12).
4. The password passes the policy against these identifiers (`PASSWORD_REJECTED`). Hash it with Argon2id, outside the transaction.
5. `[tx]` In one transaction:
   - an account `pending`, with `registered_via = client_id`;
   - the identifiers, unverified;
   - the password credential;
   - a `registration` flow;
   - one `verify_identifier` challenge per identifier, each sent (§2.4).
6. Answer `201` with `flow_id`, `handle`, `pending_types` and `expires_at`.

**Verify a code:** `POST /v1/registrations/{flowId}/verify` (`handle`, `identifier_type`, `code`).
**Verify a link:** `POST /v1/verification-links/confirm` (`token`).

On success, `[tx]`:
- set the identifier's `verified_at`. The unique index may refuse it: answer `IDENTIFIER_TAKEN` (I-1). The challenge is consumed, and the person must change the value (§12);
- close the challenge;
- remove the type from `pending_types`;
- emit `account.identifier_verified`.

**Complete:** `POST /v1/registrations/{flowId}/complete` (`handle`):
- if `pending_types` is not empty, answer `VERIFICATION_INCOMPLETE`;
- otherwise `[tx]`: set the account `active`, grant the client's `default_roles`, complete the registration flow, and emit `account.registered`. Then, by the client's `mfa`:
  - `required`: open a `sign_in` flow with `first_factor = pwd` and `step = enrolment`, and answer `202 MFA_ENROLMENT_REQUIRED` with its handle. Enrolment follows TDD-03 §4;
  - `optional`: complete the sign-in in the same transaction (§5.3, `amr` `["pwd"]`) and answer `200` with the tokens.

## 4. Resume

`POST /v1/registrations/resume` (`client_id`, `identifier` as `{type, value}`). Always `202`, whatever is found.

1. Normalise; on failure still answer 202.
2. Find the open `registration` and `invitation` flows whose account holds a **current** identifier with this blind index, at most 3, newest first.
3. `[tx]` For each flow, open a `resume` challenge on that identifier and send it (§2.4). The per-value send limits apply across all of them.

**Following it:**
- an emailed link goes to `POST /v1/verification-links/confirm`;
- a code goes to `POST /v1/registrations/resume/verify` (`identifier`, `code`). The request has no flow id: `resume` answers 202 with no body and the message carries only the code, so the code picks the flow (I-20).

Verifying a code:
1. Normalise the identifier. Find the open `resume` challenges with its blind index whose flows are open, at most 3, newest first: the candidates. None answers as step 4 does.
2. `[tx]` Lock the candidates' accounts in id order, then each flow, then its challenges (G-5). Compute the input's MAC for each candidate (each MAC is bound to its challenge id, §2.2) and compare in constant time.
3. The try counts on every candidate (§2.2 step 2), so several open flows give no more guesses than one. A candidate whose attempts are used up closes (`exhausted`).
4. No match: answer `CODE_INVALID` without `attempts_left`, whether there are candidates, open or exhausted, or none, as §5.2 does for a sign-in code. `resume` always answers 202, so its verify must not tell whether a flow holds the value. Count the failure per IP (L-12) and against each candidate's account (L-11).
5. A match picks its flow (the newest, should two codes match). Its challenge is consumed; the other candidates stay open.

On success, in the same transaction:
- the identifier becomes verified, if it was not (the unique index applies);
- the flow's handle is replaced (I-20: the old one stops working);
- answer `200` with `flow_id`, the new `handle` and `pending_types`. For an invitation not yet accepted, the answer says so, and the client continues with acceptance (§8).

## 5. Sign-in

### 5.1 Password

`POST /v1/sessions` (`client_id`, `identifier` as `{type, value}`, `password`):

1. Check the per-IP sign-in window. The type must be a sign-in type for this deployment, and `password` must be in the client's `first_factors`.
2. Find the account through a **verified, current** identifier of that type. If none matches, verify against the dummy hash and answer `INVALID_CREDENTIALS`.
3. Read the device cookie (TDD-07 §4), choose the throttle bucket, and refuse with `SIGN_IN_DELAYED` while it is delayed.
4. Verify the Argon2id hash, outside a transaction.
5. **On failure** `[tx]`: increment the bucket's failures, set its delay, and audit. Answer `INVALID_CREDENTIALS`.
6. **On success**, by status:
   - `deleted`: answer `INVALID_CREDENTIALS`.
   - `pending`: answer `REGISTRATION_INCOMPLETE`.
   - `suspended` or `banned` with `restricted_sign_in: false`: answer `ACCOUNT_RESTRICTED`.
7. Check that roles ∩ client roles is not empty, else `ROLE_NOT_PERMITTED`.
8. `[tx]` Reset the bucket, rehash if the parameters are old (TDD-03 §1), and open a `sign_in` flow with `first_factor = pwd`.
9. Decide the second step (TDD-03 §3.4):
   - the account has a confirmed TOTP: answer `202 MFA_REQUIRED`;
   - it has none and the client has `mfa: required`: answer `202 MFA_ENROLMENT_REQUIRED`;
   - otherwise complete the sign-in in this transaction (§5.3) and answer `200` with the tokens.

### 5.2 OTP as the first factor

Only for clients with `otp` in `first_factors`, and identifier types with `sign_in: true`.

1. `POST /v1/sessions/otp` (`client_id`, `identifier`). Always `202` with a `handle`.
   - If a verified, current identifier matches an account that may sign in, `[tx]`: open a `sign_in` flow (`first_factor` = `sms` or `email`, `step = first_factor`) with one `sign_in` challenge, sent.
   - Otherwise the handle is random and matches nothing.
2. `POST /v1/sessions/otp/verify` (`handle`, `code`). A handle that matches nothing answers `CODE_INVALID` without `attempts_left`, and so does a wrong code. On success the second step is decided as in §5.1 step 9: `202 MFA_REQUIRED`, `202 MFA_ENROLMENT_REQUIRED`, or `200` with the tokens.

Enumeration through this path is no worse than through registration, which already reveals verified
identifiers. The per-IP and per-value limits bound it.

### 5.3 Second factor and completion

The second step, when there is one, is specified in TDD-03 §3 and §4. Completing a sign-in `[tx]`, whether
after the first factor alone or after the second:
- re-reads the status;
- creates a full or restricted session (TDD-04 §2);
- completes the flow;
- audits `sign_in`;
- sends the optional new-sign-in notice.

## 6. Recovery

1. **Request.** `POST /v1/password-resets` (`client_id`, `value` of type `recovery.via`). Always `202`.
   - If a verified, current identifier matches an account that is `active`, `suspended` or `banned`, `[tx]`: open a `password_reset` flow with a `reset_link` challenge, sent. The per-account reset limit (3/h) and the per-value send limits apply.
   - The link is `<client.link_base_url>/reset#token=<token>`. Using a fragment keeps the token out of server logs and `Referer` headers.
2. **Start.** `POST /v1/password-resets/start` (`token`). Find the challenge, open and of purpose `reset_link`. Choose the proof and mark `started`:
   - `totp` when the account has a confirmed TOTP (a TOTP code or a recovery code);
   - otherwise `sms` when `recovery.sms_step_up` is on and the account has a verified, current phone. `[tx]` open a `reset_step_up` challenge to that phone and send it (`password_reset_code`; the per-value send limits apply);
   - otherwise `none`.

   Answer `200` with `flow_id`, `proof` and, for `sms`, `masked_phone` (the last 4 digits).
3. **Complete.** `POST /v1/password-resets/{flowId}/complete` (`token`, `new_password`, and `second_factor` for `totp` or `code` for `sms`):
   1. Verify the proof: the second factor (TDD-03 §3), or the SMS code (§2.2). Failures count, and 5 close the flow.
   2. Check the policy, then hash.
   3. `[tx]`:
      - store the hash;
      - consume the challenge and complete the flow;
      - revoke every session;
      - leave the status and the TOTP factor unchanged;
      - send the `password_reset` notice;
      - emit `account.password_reset`.
   4. Answer `204`.

## 7. Identifier changes

### 7.1 Email, by the account

`POST /v1/me/email-changes` (`current_password`, `second_factor` when the account has TOTP, `new_email`), with a full session:

1. Reauthenticate (TDD-03 §5).
2. Normalise. The new value must differ from the current email and must not be another account's verified email (`IDENTIFIER_TAKEN`).
3. `[tx]`:
   - open an `email_change` flow with `confirm_old` from configuration;
   - open an `email_change_new` challenge (`target_value`, `target_bidx` = the new value), and, if `required`, an `email_change_old` challenge on the current identifier, and send them;
   - if `notify`, send the old address the `email_change_requested` notice.
4. Answer `202` with `flow_id`.

**Confirming** a link (`POST /v1/verification-links/confirm`) marks its side. When the flow's
requirement is met, `[tx]`:
- retire the old identifier;
- insert the new one, current and verified. The unique index decides a race (`IDENTIFIER_TAKEN`);
- complete the flow;
- send the `identifier_changed` notice to the **old** address (resolved as retired, TDD-06 §7);
- emit `account.identifier_changed`.

### 7.2 Email, by support

`POST /v1/accounts/{id}/identifier-changes` (`accounts:identifiers:write`, `Idempotency-Key`,
`identifier: {type: email, value}`) opens the same flow with `confirm_old = support`. Only the new address
confirms. The account's other addresses get a notice when the change is requested and when it
applies. The audit records the caller and the actor.

### 7.3 Phone

1. `POST /v1/me/phone-changes` (`current_password`, `second_factor` when the account has TOTP, `new_phone`):
   - reauthenticate and normalise; the new value must not be another account's verified phone;
   - `[tx]`: open a `phone_change` flow with a `phone_change` challenge to the new number, sent;
   - answer `202` with `flow_id` and `handle`.
2. `POST /v1/me/phone-changes/{flowId}/verify` (`handle`, `code`). On success, `[tx]`:
   - retire the old phone and insert the new one, verified;
   - send the account's email the `identifier_changed` notice;
   - emit `account.identifier_changed`.

A support-driven phone change works like §7.2, with an OTP to the new number that the person enters
on a page the product shows.

## 8. Invitations

1. **Invite.** `POST /v1/invitations` (`accounts:invite`, `Idempotency-Key`, `Auth1-Actor`; `email`, `display_name`, `client_id`, `roles`, `locale`):
   - every role must be in the catalog;
   - the email must not be another account's verified email;
   - `[tx]`: create an account `pending` with `registered_via = 'invitation'`, an unverified email identifier, the roles, an `invitation` flow and an `invitation` challenge, sent;
   - answer `201` with `account_id`.
2. **Accept.** `POST /v1/invitations/accept` (`token`, `password`, `identifiers` for the other required types, `locale`):
   1. Find the `invitation` challenge; it must be open.
   2. Check the policy (the password against all identifiers), then hash.
   3. `[tx]`:
      - verify the email (unique index);
      - store the password;
      - insert the other identifiers, unverified, with one `verify_identifier` challenge each, sent;
      - set `accepted`, replace the handle, and consume the invitation challenge.
   4. Answer `200` with `flow_id`, `handle` and `pending_types`.
3. **Verify and complete.** The flow continues on the registration endpoints (`/v1/registrations/{flowId}/verify`, `/resend`, `/complete`), which accept `invitation` flows. `complete` grants the invited roles instead of the client's defaults, emits `account.registered` with `client_id: invitation`, and continues by the invitation client's `mfa`, as for a registration (§3): `202 MFA_ENROLMENT_REQUIRED` or `200` with the tokens.

### 8.1 Bootstrap

At start-up, the leader checks whether any account that is not `deleted` holds a role in
`bootstrap.roles`. If none does, it invites each email in `bootstrap.emails_file` with those roles,
on the first client whose `allowed_roles` include them, with the actor `system:bootstrap`. Each
invitation uses a deterministic idempotency key (`bootstrap:<email bidx>`), so restarts do not
duplicate it.

## 9. Closing an account

`DELETE /v1/accounts/{id}` (`accounts:delete`, `Idempotency-Key`). `[tx]` In one transaction:
- lock the account and set it `deleted`;
- cancel its open flows (`account_closed`) and close their challenges;
- revoke every session;
- delete the password credential, the TOTP factor and the recovery codes;
- retire every identifier;
- emit `account.deleted`;
- audit.

Answer `204`. No notice is sent: the product decides how to tell the person.

## 10. Errors by step

| Step | Possible codes |
|---|---|
| Register | `VALIDATION_FAILED`, `IDENTIFIER_NOT_ALLOWED`, `IDENTIFIER_TAKEN`, `PASSWORD_REJECTED`, `RATE_LIMITED`, `UNAVAILABLE` |
| Verify, resend | `CODE_INVALID`, `CHALLENGE_CLOSED`, `IDENTIFIER_TAKEN`, `RESEND_TOO_SOON`, `RATE_LIMITED` |
| Complete | `VERIFICATION_INCOMPLETE`, `CHALLENGE_CLOSED` |
| Sign in | `INVALID_CREDENTIALS`, `SIGN_IN_DELAYED`, `REGISTRATION_INCOMPLETE`, `ACCOUNT_RESTRICTED`, `ROLE_NOT_PERMITTED`, `RATE_LIMITED`, `UNAVAILABLE` |
| Reset | `CHALLENGE_CLOSED`, `CODE_INVALID`, `PASSWORD_REJECTED`, `RATE_LIMITED` |
| Changes | `REAUTHENTICATION_REQUIRED`, `ACCOUNT_RESTRICTED`, `IDENTIFIER_TAKEN`, `IDENTIFIER_NOT_ALLOWED`, `CODE_INVALID`, `CHALLENGE_CLOSED` |

## 11. Implementation guidelines *(guideline)*

- One application service per flow family (`Registration`, `SignIn`, `Recovery`, `IdentifierChange`, `Invitation`), sharing a `Flows` component that owns §2. Keep step logic in the domain as pure functions over (flow, challenge, account, now) that return decisions, so the state × flow matrix (SDD §8.1) is unit-testable without a database.
- Build the response from the decision after commit. Send nothing to the network before commit: the outbox does that.
- Use table-driven tests for every row of §10.

## 12. To be detailed

- A registration whose identifier loses the race at verification (`IDENTIFIER_TAKEN`): an endpoint to replace that one value inside the flow (`PUT /v1/registrations/{flowId}/identifiers/{type}`), or start again. Proposal: replace in the flow.
- The exact link paths per purpose under `link_base_url`.
- Whether the resume message reuses the verification message type or has its own (`auth.registration_resume_link`).
