# TDD-01 — Identity model and data

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-10-26 |
| SDD | [design.md](../design.md) 0.4: D-2, D-3, D-5, D-18, D-19, §11 |
| Owner | Arafat Hasan |

How auth1 identifies records, models accounts and identifiers, protects personal data at rest, and
lays out its PostgreSQL schema. Statements marked *(guideline)* are advice to the implementer, not
rules.

## 1. Record ids

- **UUIDv7** (RFC 9562) for every id column, generated in Go through an `IdGenerator` port. The default adapter uses `github.com/google/uuid` (`uuid.NewV7()`), which is monotonic within a millisecond in one process.
- Tests inject a deterministic generator.
- Columns are `uuid`. No `DEFAULT` in the schema *(guideline: a `DEFAULT uuidv7()` from PostgreSQL 18 may be added as a safety net, but the application always supplies the id)*.
- **No id is a capability** (SDD I-20). Handlers never authorise on possession of an id alone.
- The audit log uses `bigint GENERATED ALWAYS AS IDENTITY`; its ids never leave auth1.

## 2. Identifier types

### 2.1 The registry

Each type implements one interface *(guideline: the shape, not the names)*:

```go
type IdentifierType interface {
    Name() string                                 // "email", "phone"
    Normalise(raw string, p Policy) (string, error) // canonical form or IDENTIFIER_NOT_ALLOWED
    VerifyMethods() []Method                      // email_link, email_code, sms_otp
    CanSignIn() bool                              // the policy may still turn it off
    Variants(normalised string) []string          // forms a password must not contain (TDD-03 §2)
}
```

The policy (configuration) chooses for each type: `required`, `verify` (one method), `sign_in`,
and the type's own options.

### 2.2 Email

1. Trim surrounding white space; refuse inner white space and control characters.
2. Unicode NFC.
3. Split at the last `@`. Refuse if the local part is empty or longer than 64 octets.
4. Domain: IDNA 2008 to ASCII (`golang.org/x/net/idna`, lookup profile), lower-cased; refuse if it has no dot or is longer than 253 octets.
5. Local part lower-cased (Unicode simple case folding). No provider-specific rules: no dot removal, no `+tag` stripping.
6. Whole address at most 254 octets.

Syntax is checked by a strict parser *(guideline: `net/mail.ParseAddress` on the bare address, then
the rules above)*. No DNS look-up at normalisation.

### 2.3 Phone

1. Parse with libphonenumber (`github.com/nyaruka/phonenumbers`), with no default region: the input must start with `+`.
2. Refuse unless the number is valid for its region, its calling code is in `calling_codes`, and, when `verify` is `sms_otp`, its type is `MOBILE` or `FIXED_LINE_OR_MOBILE`.
3. Store E.164.

`Variants` returns the E.164 form, the form without `+`, and the national significant number.

### 2.4 Adding a type

A new type adds an implementation and a policy block. No migration is needed: `identifiers.type` is
text, and the policy is validated at start-up against the registry.

## 3. Protection at rest

### 3.1 Field encryption

| Item | Rule |
|---|---|
| Algorithm | AES-256-GCM, 96-bit random nonce |
| Format | `0x01` (format version) ‖ key id (2 bytes, big-endian) ‖ nonce (12) ‖ ciphertext ‖ tag (16) |
| Associated data | `auth1|<table>|<column>|<row id>`. A ciphertext moved to another row or column fails to open |
| Keyring | File `encryption.keyring_file`: a list of `{id, key (base64, 32 bytes), state: active|decrypt}`. Exactly one `active` |
| Rotation | 1) add the key as `decrypt` to every replica; 2) make it `active` (old one `decrypt`); 3) `auth1 crypto reencrypt` rewrites every field under the new key in batches; 4) remove the old key |
| Encrypted columns | `accounts.display_name`, `identifiers.value`, `challenges.secret`, `challenges.target_value`, `flows.pending_secret`, `totp_factors.secret`, `refresh_tokens.successor_enc` |

*(guideline)* One `FieldCrypto` port with `Seal(place Place, plaintext)` and `Open(place, ciphertext)`, where
`Place` carries the table, column and row id. Repositories call it; the domain never sees ciphertext.

### 3.2 Blind index

- `HMAC-SHA256(bidx_key, type ‖ 0x00 ‖ normalised value)`, all 32 bytes, stored as `bytea`.
- The key is in `encryption.blind_index_key_file` and has no key id: every index row must use the same key, or uniqueness breaks.
- **Rotation** is a planned operation (`auth1 crypto rebuild-bidx`). It adds a second column, fills it from decrypted values, swaps the indexes and drops the old column. Expect to do it rarely, if ever.

### 3.3 Other MACs and hashes

| Value | Stored as | Key |
|---|---|---|
| OTP | HMAC-SHA256 | `encryption.mac_key_file` |
| Recovery code | HMAC-SHA256 | `encryption.mac_key_file` (domain-separated: prefix `rcode|`) |
| Link token, flow handle, refresh token | SHA-256 | None: 256 random bits need no key |
| Password | Argon2id over a peppered HMAC (TDD-03) | `passwords.pepper_keyring_file` |

## 4. Schema `000001`

PostgreSQL 18. Plain SQL, `migrations/000001_init.up.sql` and `.down.sql`. *enc* = §3.1;
*bidx* = §3.2.

```sql
CREATE TABLE accounts (
    id                  uuid PRIMARY KEY,                       -- UUIDv7
    status              text NOT NULL CHECK (status IN ('pending','active','suspended','banned','deleted')),
    status_reason       text,
    status_until        timestamptz,
    status_changed_at   timestamptz NOT NULL,
    display_name        bytea NOT NULL,                         -- enc
    locale              text NOT NULL,
    registered_via      text NOT NULL,                          -- client id, or 'invitation'
    factor_failures     integer NOT NULL DEFAULT 0,             -- failed OTP/TOTP/recovery-code verifications in the window (TDD-07)
    factor_failures_since timestamptz,
    version             bigint NOT NULL DEFAULT 1,
    created_at          timestamptz NOT NULL,
    updated_at          timestamptz NOT NULL,
    CHECK (status_until IS NULL OR status = 'suspended'),
    CHECK ((status IN ('suspended','banned')) = (status_reason IS NOT NULL))
);
CREATE INDEX accounts_status ON accounts (status, id);

CREATE TABLE identifiers (
    id           uuid PRIMARY KEY,
    account_id   uuid NOT NULL REFERENCES accounts (id),
    type         text NOT NULL,
    value        bytea NOT NULL,                                -- enc, normalised
    value_bidx   bytea NOT NULL,                                -- bidx(type, normalised value)
    verified_at  timestamptz,
    retired_at   timestamptz,                                   -- replaced, expired or released on deletion
    created_at   timestamptz NOT NULL
);
CREATE UNIQUE INDEX identifiers_verified_unique ON identifiers (type, value_bidx)
    WHERE verified_at IS NOT NULL AND retired_at IS NULL;      -- I-1
CREATE UNIQUE INDEX identifiers_current_per_type ON identifiers (account_id, type)
    WHERE retired_at IS NULL;                                   -- I-2
CREATE INDEX identifiers_lookup ON identifiers (type, value_bidx) WHERE retired_at IS NULL;
CREATE INDEX identifiers_account ON identifiers (account_id);      -- FK; the purge (§5)

CREATE TABLE password_credentials (
    account_id   uuid PRIMARY KEY REFERENCES accounts (id),
    hash         text NOT NULL,                                 -- PHC string, $argon2id$...
    pepper_kid   text NOT NULL,
    changed_at   timestamptz NOT NULL
);

CREATE TABLE totp_factors (
    account_id    uuid PRIMARY KEY REFERENCES accounts (id),
    secret        bytea NOT NULL,                               -- enc
    confirmed_at  timestamptz,                                  -- null while enrolling or replacing
    last_step     bigint,                                       -- I-19
    created_at    timestamptz NOT NULL
);
-- A replacement in progress lives in the flow (TDD-03 §5), so one row per account is enough.

CREATE TABLE recovery_codes (
    id          uuid PRIMARY KEY,
    account_id  uuid NOT NULL REFERENCES accounts (id),
    code_mac    bytea NOT NULL,
    batch       uuid NOT NULL,                                  -- a regeneration replaces the batch
    used_at     timestamptz,
    created_at  timestamptz NOT NULL
);
CREATE UNIQUE INDEX recovery_codes_mac ON recovery_codes (account_id, code_mac);
CREATE INDEX recovery_codes_unused ON recovery_codes (account_id) WHERE used_at IS NULL;

CREATE TABLE account_roles (
    account_id  uuid NOT NULL REFERENCES accounts (id),
    role        text NOT NULL,
    granted_at  timestamptz NOT NULL,
    granted_by  text,                                           -- actor
    PRIMARY KEY (account_id, role)
);
CREATE INDEX account_roles_role ON account_roles (role, account_id);

CREATE TABLE flows (
    id            uuid PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('registration','invitation','sign_in','password_reset','email_change','phone_change','totp_replacement')),
    account_id    uuid NOT NULL REFERENCES accounts (id),
    client_id     text NOT NULL,
    handle_hash   bytea UNIQUE,                                 -- sha256 of the handle
    state         jsonb NOT NULL DEFAULT '{}',                  -- non-secret step state (TDD-02 §2.1)
    pending_secret bytea,                                       -- enc: a TOTP secret being replaced; erased when closed
    attempts      integer NOT NULL DEFAULT 0,                   -- second-factor attempts in the flow
    expires_at    timestamptz NOT NULL,
    completed_at  timestamptz,
    cancelled_at  timestamptz,
    close_reason  text,                                         -- replaced, expired, account_closed, attempts
    created_at    timestamptz NOT NULL,
    CHECK ((completed_at IS NULL AND cancelled_at IS NULL) OR pending_secret IS NULL)
);
CREATE INDEX flows_account_open ON flows (account_id, kind) WHERE completed_at IS NULL AND cancelled_at IS NULL;
CREATE INDEX flows_open_expiry ON flows (expires_at) WHERE completed_at IS NULL AND cancelled_at IS NULL;
CREATE INDEX flows_account ON flows (account_id);                  -- FK; the purge (§5)
CREATE INDEX flows_closed ON flows (coalesce(completed_at, cancelled_at))
    WHERE completed_at IS NOT NULL OR cancelled_at IS NOT NULL;  -- retention (§5)

CREATE TABLE challenges (
    id             uuid PRIMARY KEY,
    flow_id        uuid NOT NULL REFERENCES flows (id),
    purpose        text NOT NULL,                               -- TDD-02 §2.3
    method         text NOT NULL CHECK (method IN ('sms_otp','email_link','email_code')),
    identifier_id  uuid REFERENCES identifiers (id),            -- the target, when it is an identifier
    target_value   bytea,                                       -- enc: a value under change
    target_bidx    bytea NOT NULL,                              -- bidx of the address it is sent to (I-21)
    secret_mac     bytea NOT NULL,
    secret         bytea,                                       -- enc; erased when closed
    attempts       integer NOT NULL DEFAULT 0,
    max_attempts   integer NOT NULL,
    sends          integer NOT NULL DEFAULT 0,
    last_sent_at   timestamptz,
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    closed_at      timestamptz,
    created_at     timestamptz NOT NULL,
    CHECK (identifier_id IS NOT NULL OR target_value IS NOT NULL),
    CHECK (closed_at IS NULL OR secret IS NULL)                 -- I-5
);
CREATE UNIQUE INDEX challenges_link ON challenges (secret_mac) WHERE method = 'email_link';
CREATE INDEX challenges_open ON challenges (expires_at) WHERE closed_at IS NULL;
CREATE INDEX challenges_flow ON challenges (flow_id);
CREATE INDEX challenges_target ON challenges (target_bidx, created_at);  -- send limits per value
CREATE INDEX challenges_identifier ON challenges (identifier_id);  -- FK; the purge (§5)
CREATE INDEX challenges_closed ON challenges (closed_at) WHERE closed_at IS NOT NULL;  -- retention (§5)

CREATE TABLE sessions (
    id                   uuid PRIMARY KEY,
    account_id           uuid NOT NULL REFERENCES accounts (id),
    client_id            text NOT NULL,
    amr                  text[] NOT NULL,
    auth_time            timestamptz NOT NULL,
    device_id            uuid,                                  -- from the device cookie (TDD-07 §4)
    user_agent           text,                                  -- cleared 90 days after last_used_at (§5)
    created_at           timestamptz NOT NULL,
    last_used_at         timestamptz NOT NULL,
    idle_expires_at      timestamptz NOT NULL,
    absolute_expires_at  timestamptz NOT NULL,
    revoked_at           timestamptz,
    revoke_reason        text
);
CREATE INDEX sessions_account_live ON sessions (account_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_revoked ON sessions (revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX sessions_account ON sessions (account_id);            -- FK; the purge (§5)
CREATE INDEX sessions_expiry ON sessions (least(idle_expires_at, absolute_expires_at))
    WHERE revoked_at IS NULL;                                   -- retention (§5)
CREATE INDEX sessions_user_agent ON sessions (last_used_at) WHERE user_agent IS NOT NULL;  -- clearing (§5)

CREATE TABLE refresh_tokens (
    token_hash      bytea PRIMARY KEY,                          -- sha256
    session_id      uuid NOT NULL REFERENCES sessions (id),
    issued_at       timestamptz NOT NULL,
    rotated_at      timestamptz,
    successor_hash  bytea,
    successor_enc   bytea                                       -- enc, grace window only (I-13)
);
CREATE INDEX refresh_tokens_session ON refresh_tokens (session_id);
CREATE INDEX refresh_tokens_successor ON refresh_tokens (rotated_at) WHERE successor_enc IS NOT NULL;

CREATE TABLE sign_in_throttles (                                -- TDD-07 §4
    account_id   uuid NOT NULL REFERENCES accounts (id),
    bucket       text NOT NULL,                                 -- 'untrusted' or 'device:<uuid>'
    failures     integer NOT NULL DEFAULT 0,
    delay_until  timestamptz,
    updated_at   timestamptz NOT NULL,
    PRIMARY KEY (account_id, bucket)
);
CREATE INDEX sign_in_throttles_updated ON sign_in_throttles (updated_at);  -- retention (§5)

CREATE TABLE sms_budget (                                       -- TDD-07 §6
    hour  timestamptz PRIMARY KEY,                              -- truncated to the hour
    sent  integer NOT NULL DEFAULT 0
);

CREATE TABLE client_assertions (                                -- jti replay protection (TDD-05 §2)
    client_id   text NOT NULL,
    jti         text NOT NULL,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (client_id, jti)
);
CREATE INDEX client_assertions_expiry ON client_assertions (expires_at);   -- retention (§5)

CREATE TABLE idempotency_keys (
    caller        text NOT NULL,
    key           text NOT NULL,
    request_hash  bytea NOT NULL,
    status        integer,                                      -- null while in flight
    response      jsonb,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (caller, key)
);
CREATE INDEX idempotency_keys_created ON idempotency_keys (created_at);

CREATE TABLE signing_keys (
    kid                 text PRIMARY KEY,                       -- RFC 7638 thumbprint
    alg                 text NOT NULL,
    first_published_at  timestamptz NOT NULL,
    activated_at        timestamptz,
    retired_at          timestamptz
);

CREATE TABLE auth_audit (
    id          bigint GENERATED ALWAYS AS IDENTITY,
    at          timestamptz NOT NULL DEFAULT now(),
    account_id  uuid,
    actor_kind  text NOT NULL CHECK (actor_kind IN ('account','service','operator','system','anonymous')),
    actor_id    text,
    on_behalf   text,                                           -- Auth1-Actor, verbatim
    action      text NOT NULL,
    outcome     text NOT NULL,
    client_id   text,
    ip          inet,
    user_agent  text,
    details     jsonb NOT NULL DEFAULT '{}',                    -- never a secret or identifier value
    PRIMARY KEY (id, at)
) PARTITION BY RANGE (at);
CREATE INDEX auth_audit_account ON auth_audit (account_id, at);
CREATE INDEX auth_audit_uncleared ON auth_audit (at)
    WHERE ip IS NOT NULL OR user_agent IS NOT NULL;              -- clearing after 90 days (§5)

CREATE TABLE outbox (
    id               uuid PRIMARY KEY,                          -- UUIDv7; CloudEvents id for events
    destination      text NOT NULL CHECK (destination IN ('event','delivery')),
    subject          uuid,                                      -- account id
    account_version  bigint,                                    -- events only (I-8)
    type             text NOT NULL,
    body             jsonb NOT NULL,
    trace_context    jsonb,
    created_at       timestamptz NOT NULL,
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL,
    published_at     timestamptz,
    parked_at        timestamptz,
    last_error       text,
    CHECK ((destination = 'event') = (account_version IS NOT NULL AND subject IS NOT NULL))
);
CREATE UNIQUE INDEX outbox_event_order ON outbox (subject, account_version) WHERE destination = 'event';
CREATE INDEX outbox_event_pending ON outbox (subject, account_version)
    WHERE destination = 'event' AND published_at IS NULL;
CREATE INDEX outbox_delivery_pending ON outbox (next_attempt_at)
    WHERE destination = 'delivery' AND published_at IS NULL AND parked_at IS NULL;
CREATE INDEX outbox_published ON outbox (published_at) WHERE published_at IS NOT NULL;  -- retention (§5)
```

### 4.1 Grants

- `auth1_migrator` owns the schema.
- `auth1_app` gets `SELECT, INSERT, UPDATE, DELETE` on every table except `auth_audit`. On `auth_audit` it gets `INSERT, SELECT`, and `UPDATE (ip, user_agent)` only (I-11).
- Partitions are created by the job, which runs as `auth1_app` through a `SECURITY DEFINER` function owned by the migrator.

### 4.2 Concurrency rules

| Rule | How |
|---|---|
| Changes to one account apply in order (I-10) | Every use case that changes an account first takes `SELECT … FOR UPDATE` on its row, and finishes with `UPDATE accounts SET version = version + n, updated_at = now() WHERE id = $1`. Optimistic preconditions for service callers (`If-Match` on `version`) are not offered in 1.0 |
| Event order (I-8) | The outbox `account_version` values are assigned from the locked row inside the same transaction (TDD-06 §2) |
| Lock order | Account row, then flow, then challenge, then session. Never the reverse, to avoid deadlocks |
| Isolation | `READ COMMITTED` with explicit row locks and conditional updates. No reliance on `SERIALIZABLE` |

### 4.3 Migration rules

- Plain SQL, numbered `NNNNNN_<name>.up.sql` / `.down.sql`, applied by `auth1 migrate` with a PostgreSQL advisory lock.
- After 1.0 ships: **expand and contract**. Add a column nullable or with a default, backfill in a job, then constrain in a later release. Never rename or drop in the same release that stops using a column.
- Every migration runs in CI against an empty database and against the previous release's schema with data.

## 5. Retention

| Data | Kept | Then |
|---|---|---|
| Pending account of an expired flow | Identifiers retired at expiry | Rows purged 7 days later *(cfg)* |
| Closed challenges | 30 days | Deleted |
| Closed flows | 30 days after `completed_at` or `cancelled_at` | Deleted, after their challenges |
| Revoked or expired sessions and their refresh tokens | 90 days | Deleted |
| Refresh successor | Grace window | `successor_enc` set to null within a minute |
| Recovery codes, used or not | Until the next regeneration or the removal of MFA | Deleted in that transaction (TDD-03 §5.3, §5.4); no purge |
| `client_assertions` | Until `expires_at` | Deleted |
| `sms_budget` | 30 days | Deleted |
| `sign_in_throttles` | 90 days after `updated_at` | Deleted |
| Idempotency keys | 24 h | Deleted |
| Published outbox rows | 7 days | Deleted |
| `auth_audit` | Kept; monthly partitions | `ip`, `user_agent` set to null after 90 days; a product may drop partitions past its legal horizon |
| `sessions.user_agent` | 90 days after `last_used_at`, so a live session keeps it | Null |
| Deleted accounts | Kept encrypted, released from uniqueness | Erasure on request (SDD O-2) |

Each purge by age, and each clearing of IPs and user agents, reads an index on its cut-off column, and every foreign key has an
index that starts with its column, so a purge scans no table, either to find its rows or to check
the rows that reference them. Only a pending account's rows are purged from `accounts`; there is no
`ON DELETE CASCADE`, so the purge deletes the referencing rows first.

## 6. Implementation guidelines *(guideline)*

- One repository per aggregate (accounts with identifiers, roles and credentials; flows with challenges; sessions with refresh tokens; outbox; audit), behind ports in the application layer.
- A `UnitOfWork` that opens a transaction, hands repositories bound to it to the use case, and commits once. Outbox and audit writes go through it.
- Use bun for simple reads and writes. Write the conditional updates (I-3, I-4, version checks) as explicit SQL, and check `RowsAffected`.
- Never `SELECT *`. Never decrypt in bulk for a list endpoint unless the caller has the scope for values.

## 7. To be detailed

- The `flows.state` JSON shapes per kind (with TDD-02).
- Whether `display_name` needs a length and character policy beyond "non-empty, at most 100 characters".
- The exact `auth_audit.action` vocabulary (with TDD-08).
