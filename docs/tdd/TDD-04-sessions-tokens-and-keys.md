# TDD-04 — Sessions, tokens and keys

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-10-26 |
| SDD | [design.md](../design.md) 0.4: D-5, D-6, D-12, I-3, I-6, I-13, I-14 |
| Owner | Arafat Hasan |

Access tokens, sessions, refresh rotation, browser transport, the signing keyring, the JWKS,
introspection, and what relying services must check.

## 1. Access tokens

**Header:** `alg` (from the active key), `kid`, `typ: at+jwt`.

| Claim | Full session | Restricted session |
|---|---|---|
| `iss` | `http.issuer` | same |
| `sub` | Account id (UUIDv7) | same |
| `aud` | The client's `audience` | `tokens.self_audience` (default: the issuer) |
| `exp`, `iat`, `nbf` | `iat` = `nbf` = now; `exp` = now + `access_ttl` (≤ 15 min) | same |
| `jti` | UUIDv7 | same |
| `sid` | Session id | same |
| `client_id` | The client | same |
| `roles` | Account roles ∩ client `allowed_roles`, sorted | `[]` |
| `status` | `active` | `suspended` or `banned` |
| `amr` | TDD-03 §7 | same |
| `auth_time` | Seconds since epoch of the sign-in | same |

auth1's own bearer-protected endpoints accept tokens whose `aud` is one of the clients' audiences or
the self audience. A restricted token is accepted only on `GET /v1/me`, `GET /v1/me/sessions`,
`DELETE /v1/me/sessions/{id}` and `DELETE /v1/sessions/current`. Everywhere else it gets
`ACCOUNT_RESTRICTED`.

**Token response** (`200`):
- `access_token`, `token_type: Bearer`, `expires_in`
- `session_id`, `account_status`, `status_until`
- `refresh_token`, only for `refresh_transport: body`

It carries `Cache-Control: no-store`.

## 2. Sessions

- **Created** when a sign-in completes (TDD-02 §5.3), from the flow. The session records `client_id`, `amr` and `auth_time`, and the `device_id` from the device cookie (TDD-07 §4). Its `idle_expires_at` is now + `refresh_idle_ttl` and its `absolute_expires_at` is now + `refresh_absolute_ttl`.
- **Full or restricted** is decided each time tokens are issued, from the account's status at that moment.
- **Listing:** `GET /v1/me/sessions` returns `id`, `client_id`, `created_at`, `last_used_at`, `user_agent` and `current` (true for the caller's own session).
- **Revoking one:** `DELETE /v1/me/sessions/{id}` revokes one of the caller's own sessions (`user_revoked`).
- **Revoking the others:** `DELETE /v1/me/sessions` revokes every session but the caller's (`user_revoked`). Not available to a restricted session.
- **Sign-out:** `DELETE /v1/sessions/current` takes the bearer token or the refresh cookie, revokes that session (`signed_out`) and clears the cookie.
- **Revoke reasons:** `signed_out`, `user_revoked`, `refresh_reuse`, `password_changed`, `password_reset`, `mfa_reset`, `status_change`, `roles_removed`, `service_revoked`, `account_deleted`, `operator`.

## 3. Refresh rotation

`POST /v1/sessions/refresh`, with the cookie or `refresh_token` in the body. In one transaction:

1. `h = sha256(token)`. Select the token row and lock its session row: `SELECT … FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE r.token_hash = $1 FOR UPDATE OF s`. No row: `SESSION_INVALID`.
2. If the session is revoked, or past its idle or absolute expiry: `SESSION_INVALID`.
3. **Current token** (`rotated_at IS NULL`):
   1. Read the account's status, version and roles (no lock).
   2. If the account is `deleted`: revoke the session (`account_deleted`) and answer `SESSION_INVALID`.
   3. If the client role intersection is empty: revoke the session (`roles_removed`) and answer `SESSION_INVALID`.
   4. Draw the successor `n` (32 bytes) and insert its row.
   5. Mark the presented token rotated: `UPDATE refresh_tokens SET rotated_at = now(), successor_hash = sha256(n), successor_enc = seal(n) WHERE token_hash = $1 AND rotated_at IS NULL` (I-3).
   6. Set `last_used_at = now()` and `idle_expires_at = least(now() + idle_ttl, absolute_expires_at)`.
   7. Issue an access token. Answer with `n`.
4. **Rotated within the grace window** (`now() - rotated_at ≤ refresh_reuse_grace` and `successor_enc` not null):
   1. Follow `successor_hash` to the newest token of the chain, at most 3 steps, each rotated within the grace window.
   2. If that token is current, decrypt its value (from its predecessor's `successor_enc`), issue a new access token, and answer with it. Nothing new is stored.
   3. Otherwise treat it as reuse (step 5).
5. **Anything else is reuse.** Revoke the session (`refresh_reuse`), audit `refresh_reuse` with the session and client, and answer `SESSION_INVALID`.

A job sets `successor_enc = null` on rows rotated more than `refresh_reuse_grace` ago, every
30 seconds (I-13). The refresh path also ignores `successor_enc` once the window has passed, so
the job's timing never widens it.

## 4. Browser transport

### 4.1 The refresh cookie

| Attribute | Value |
|---|---|
| Name | `__Secure-auth1_rt` |
| Path | `<base_path>/v1/sessions` (refresh and sign-out only) |
| Flags | `HttpOnly; Secure; SameSite=Strict` |
| `Max-Age` | Seconds until the session's absolute expiry |
| Domain | Not set (host-only) |

The `__Host-` prefix is not used because it requires `Path=/`. Sign-out and a `SESSION_INVALID`
answer clear the cookie (`Max-Age=0`).

### 4.2 CORS and origin

- **The allowed origins** are the union of the clients' `origins`.
- **Preflight:**
  - `Access-Control-Allow-Origin` echoes the request's `Origin` exactly, when allowed;
  - `Access-Control-Allow-Credentials: true`;
  - `Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE`;
  - `Access-Control-Allow-Headers: Content-Type, Authorization, Idempotency-Key`;
  - `Access-Control-Max-Age: 600`;
  - `Vary: Origin`.
- **Unsafe methods on browser endpoints:**
  - `Content-Type` must be `application/json`;
  - `Origin` must be one of the **client's** origins (the client from the body, the token or the flow);
  - a request that carries the refresh cookie and no `Origin` is refused.
- **Native clients** (`refresh_transport: body`) send no cookie and need no `Origin`.

## 5. Signing keyring

### 5.1 File

`keys.keyring_file`, a mounted secret:

```yaml
keys:
  - alg: RS256
    state: retired
    private_key_file: /secrets/signing/k1.pem
  - alg: RS256
    state: active
    private_key_file: /secrets/signing/k2.pem
  - alg: ES256
    state: next
    private_key_file: /secrets/signing/k3.pem
```

**Validation** (on load; a failure keeps the previous keyring and logs an error naming the file
and the entry). The file is one YAML document with no unknown field, and:
- exactly one `active` key;
- `alg` is `RS256` or `ES256`, and `state` is `next`, `active` or `retired`;
- RSA keys of at least 2048 bits for `RS256`; P-256 for `ES256`;
- no duplicate keys (the same thumbprint twice).

`private_key_file` is resolved against the keyring file's directory when it is not absolute. The
PEM is PKCS#8, or PKCS#1 for RSA, or SEC 1 for EC. The `kid` is the RFC 7638 thumbprint (SHA-256,
base64url), computed, never configured.

### 5.2 Loading and publication times

Each replica polls the keyring file and the PEM files it names every 30 s; mounted secrets change
by symlink swap, so the content is compared, not the modification time. It parses the keyring
again only when the content changed, but it runs the steps below on every poll, so a key becomes
promotable, and a retired key leaves the JWKS, without another change to the file. Every time
comparison uses the database's `now()`, so a replica's clock skew cannot shorten I-14. A new file
takes effect only together with a successful sync; until the first one, the replica has no
signing key and answers the JWKS with `503`.

1. For every key in the file: `INSERT INTO signing_keys (kid, alg, first_published_at) VALUES (…, now()) ON CONFLICT DO NOTHING`.
2. For the `active` key:
   - if `first_published_at ≤ now() - min_publish_before_use`, sign with it, set `activated_at` to `now()`, and clear `retired_at` (a key retired earlier and made active again starts a new retirement window when it is retired again);
   - otherwise keep signing with the previously active key: the key in the file, other than the `active` one, with the latest `activated_at`, and set its `activated_at` to `now()` and clear its `retired_at` as above. Log the error `signing key not promotable`. If there is no such key, no key signs and readiness is refused.

   `activated_at` is therefore the last load at which the key signed, not its first activation, so after a rollback the previously active key is the one that signed last.
3. For each `retired` key that does not sign, set `retired_at` if it is null. A retired key that still signs (step 2) gets it at the first load after it stops, so its JWKS window starts after its last signature.

While a new file rolls out, a replica still on the old file keeps the old key signing and clears its `retired_at` on every load, and a replica on the new file sets it again. The old key's window therefore starts once the last replica has the new file, which only keeps it published longer.

**The JWKS** publishes `next` and `active` keys, `retired` keys while `retired_at` is null or
`now() < retired_at + access_ttl + 5 min`, and the signing key whatever its state, in the file's
order. Response headers:
`Cache-Control: public, max-age=300` and a strong `ETag` over the body; a matching
`If-None-Match` answers `304`.

### 5.3 Rotation

The operator procedure is in TDD-08 §6. `auth1 keys force-activate <kid>` sets
`first_published_at = now() - min_publish_before_use` for that key, so it can sign at once. It is
audited, and it is the only way to skip the wait (I-14).

### 5.4 Metadata

`/.well-known/oauth-authorization-server`, served under `http.base_path` like every route. Its
URLs are the issuer's origin, then `http.base_path`, then the route. This is the RFC 8414 location
when neither the issuer nor `http.base_path` has a path.
- `issuer`
- `jwks_uri`
- `introspection_endpoint`
- when `service_auth.mode` is `client_credentials` or `both`:
  - `token_endpoint`
  - `token_endpoint_auth_methods_supported: [private_key_jwt]`
  - `token_endpoint_auth_signing_alg_values_supported: [RS256, ES256]`
  - `grant_types_supported: [client_credentials]`

`introspection_endpoint_auth_methods_supported` is left out: no registered method describes a mesh
identity or a client-credentials bearer token.

## 6. Introspection

`POST /v1/introspect` (`tokens:introspect`), form or JSON `token`.

1. Parse the JWT, with `typ` `at+jwt`. Find the key by `kid` among the published keys. Verify the signature with the key's own `alg`; there is no algorithm negotiation.
2. Check `iss`. Check `exp` and `nbf` with 30 s leeway. `aud` must be a client's audience or the self audience.
3. Load the session by `sid`, with the account's status: one join on primary keys.
4. `active` is false if any check fails, the session is revoked or expired, or the account is `deleted`. Answer `{"active": false}` and nothing else.
5. Otherwise answer `active: true` with `sub`, `aud`, `sid`, `client_id`, `roles`, `status`, `amr`, `exp`, `iat`, `jti`. `status` is the account's **current** status, which may differ from the token's.

The answer is never cached by auth1, and carries `Cache-Control: no-store`.

## 7. What relying services check

A checklist the product's services follow. auth1 publishes it with the contract.

1. Fetch the JWKS at start-up. Refresh it at most every 5 minutes, and on an unknown `kid` (rate-limited to once a minute).
2. Accept only `typ: at+jwt`, and only the `alg` of the JWK named by `kid`. Never `none`.
3. Check `iss` exactly; `exp` and `nbf` with leeway of at most 60 s.
4. Check that `aud` is one of the audiences the route accepts. This alone refuses restricted tokens.
5. Authorise on `roles` and `sub`. Do not read personal data from the token; use the directory.
6. For high-value operations, introspect.

## 8. Implementation guidelines *(guideline)*

- `TokenSigner` port: `Sign(payload, typ) (string, error)` with the signing key, so claim encoding stays with the tokens use case and private keys stay in the keyring; `PublicKeys` for the JWKS and for finding a key by `kid`. Keyring state is held in an atomic pointer swapped on reload.
- Library: `github.com/lestrrat-go/jwx/v3` for signing, parsing and RFC 7638 thumbprints, everywhere.
- The refresh use case is the hottest write path. Keep it to one transaction with one session lock, one account read, one insert and one update.

## 9. To be detailed

- Whether `GET /v1/me/sessions` also shows an approximate location or the last IP (privacy trade-off; proposal: no).
- The exact `auth1 sessions revoke-all` behaviour for very large tables (batching).
