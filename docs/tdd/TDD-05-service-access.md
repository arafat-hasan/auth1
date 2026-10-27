# TDD-05 — Service access, directory and account control

| Field | Contents |
|---|---|
| Status | Draft |
| Version | 0.1 |
| Date | 2026-10-26 |
| SDD | [design.md](../design.md) 0.4: D-13, D-14, I-9 |
| Owner | Arafat Hasan |

How backend services authenticate to auth1, how scopes are enforced, how idempotency works, and the
directory and account-control operations.

## 1. Workload identity (mesh mode)

| `service_auth.mesh.source` | Identity taken from | Trusted when |
|---|---|---|
| `header`, `format: xfcc` | The `URI=` element of `X-Forwarded-Client-Cert` | The TCP peer address is in `trusted_sidecar_cidrs` and the header has exactly one element |
| `header`, `format: plain` | The whole header value (for example `l5d-client-id`) | Same peer-address rule |
| `peer_cert` | The first URI SAN of the verified client certificate | auth1 terminates mTLS and the chain verified against `service_auth.mesh.ca_file` |

- **A request that fails the trust rule has no service identity.** Its identity headers are ignored, never an error by themselves.
- **The identity is compared exactly** with the configured caller identities (for example `spiffe://cluster.local/ns/billing/sa/billing`).
- **`trusted_sidecar_cidrs` defaults to loopback.** A non-loopback value logs a warning at start-up.

## 2. Client credentials

`POST /v1/oauth/token`, `application/x-www-form-urlencoded`:
- `grant_type=client_credentials`
- `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- `client_assertion=<JWT>`
- optionally `scope`

**Assertion checks.** Any failure answers `invalid_client`.

1. Header `alg` is `RS256` or `ES256`, and `kid` is present.
2. `iss` = `sub` = a configured client id. Its keys come from `jwks_file` or from `jwks_uri`, fetched and cached for 10 minutes and refetched on an unknown `kid` at most once a minute.
3. The signature verifies with that `kid`'s key and its own algorithm.
4. `aud` contains the token endpoint URL or the issuer.
5. `exp` is in the future and at most 5 minutes after `iat`. `iat` is not more than 30 s in the future.
6. `jti` is present, at most 256 characters, and new: `INSERT INTO client_assertions (client_id, jti, expires_at) VALUES (…) ON CONFLICT DO NOTHING`. No row inserted means a replay.

**Response.** RFC 6749 JSON: `access_token`, `token_type: Bearer`, `expires_in`, `scope`.
- The token is signed by the keyring with:
  - `aud` = `service_auth.client_credentials.audience` (default `auth1-services`);
  - `sub` = `client_id` = the client id;
  - `scope` = the requested scopes ∩ the configured ones, or all the configured ones if none were requested;
  - `exp` = 5 minutes *(cfg, ≤ 15)*.
- An empty grant answers `invalid_scope`.
- Errors on this endpoint follow RFC 6749 §5.2, not problem details, so OAuth client libraries work.

**Audience separation.**
- Service tokens are accepted only on service endpoints.
- User tokens (client audiences, the self audience) are never accepted there.
- Service tokens are never accepted on user endpoints.

## 3. Scope enforcement

- **Caller.** A middleware resolves the caller: the mesh identity, or a valid service token. In mode `both`, either is accepted. With neither, it answers `401 TOKEN_INVALID`.
- **Scopes.** Each operation's required scope comes from the OpenAPI `x-auth1-scope`, through generated route metadata, not a hand-written table. A caller without it gets `403 CALLER_NOT_ALLOWED`. The denial increments `auth1_service_calls_denied_total` and is audited.
- **`Auth1-Actor`.**
  - **Format:** at most 128 printable ASCII characters. *(guideline: `<kind>:<id>`, for example `staff:7f3c…`)*.
  - **Recorded** in `auth_audit.on_behalf` and in the event's `actor` extension.
  - **A malformed value** is a `VALIDATION_FAILED`.

## 4. Idempotency

Every account-control write requires `Idempotency-Key` (1–255 printable ASCII characters). In the
operation's transaction:

1. Compute `request_hash = sha256(method ‖ path ‖ JCS(body))`, using the RFC 8785 canonical JSON of the body.
2. `INSERT INTO idempotency_keys (caller, key, request_hash, created_at) VALUES (…) ON CONFLICT DO NOTHING`.
   - **Inserted:** run the operation. Store `status` and `response` in the same transaction, then commit.
   - **Conflict:** the insert waits if another transaction holds the key, then sees its committed row. `SELECT … FOR UPDATE` it. A different `request_hash` answers `422 IDEMPOTENCY_KEY_REUSED`; otherwise replay the stored `status` and `response`.
3. 2xx and 4xx outcomes are stored and replayed. A 5xx rolls back the transaction, so the key is free for a retry.

No in-flight state is visible to others, because the key row commits only with the operation (I-9).

## 5. Directory

| Operation | Request | Answer |
|---|---|---|
| `POST /v1/directory/accounts/batch-get` | `ids` (1–100), `include_deleted` | `accounts` in request order; `not_found` ids |
| `POST /v1/directory/accounts/search` | `identifier` (`type`, `value`), `include_deleted` | `accounts`: zero or one record |
| `POST /v1/directory/accounts/list` | `statuses`, `roles`, `created_from`, `created_to`, `include_deleted`, `cursor`, `limit` (≤ 100, default 20) | `accounts`, `next_cursor` |

- **Search** normalises the value with the type's rules, computes the blind index, and matches only verified, current identifiers. A value that fails normalisation returns no records, not an error.
- **List** orders by `id` ascending (creation order, since ids are UUIDv7). The cursor is opaque: base64url of `{last_id, filter_hash}`. A cursor used with different filters is refused (`VALIDATION_FAILED`).
- **A record:** `account_id`, `display_name`, `status`, `status_reason`, `status_until`, `roles`, `locale`, `mfa_enrolled`, `created_at`, `version`. With `directory:read:identifiers`, also `identifiers: [{type, value, verified_at}]` (current ones only). Values are decrypted only for those callers.
- **Every call writes one audit row:** action `directory_<op>`, the caller, the actor and the result count. Never the queried value.

## 6. Account control

| Operation | Body | Effect `[tx]` | Event | Notice |
|---|---|---|---|---|
| `PUT /v1/accounts/{id}/status` | `status`, `reason_code`, `until`, `revoke_sessions` | SDD §8.1 transition; `status_changed_at`; sessions revoked if asked (`status_change`) | `account.status_changed` (+ `account.sessions_revoked`) | — |
| `POST /v1/accounts/{id}/sessions/revoke` | — | Revoke every session (`service_revoked`) | `account.sessions_revoked` | `sessions_revoked` |
| `PUT /v1/accounts/{id}/roles` | `roles` | Replace the set; record `granted_by`; revoke sessions if a role was removed and `roles.revoke_sessions_on_removal` | `account.roles_changed` (`added`, `removed`) | — |
| `POST /v1/invitations` | TDD-02 §8 | TDD-02 §8 | — (`account.registered` on completion) | — |
| `POST /v1/accounts/{id}/identifier-changes` | `identifier` (`type`, `value`) | TDD-02 §7.2 | on completion | requested, applied |
| `POST /v1/accounts/{id}/mfa/reset` | — | TDD-03 §6 | `account.mfa_reset` | `mfa_reset` |
| `DELETE /v1/accounts/{id}` | — | TDD-02 §9 | `account.deleted` | — |

- Every operation locks the account row first (TDD-01 §4.2).
- It answers with the account's directory record, without values, or `204` for `DELETE` and `mfa/reset`.
- **Validation:** `reason_code` must be in `statuses.reason_codes`; `until` must be in the future and only with `suspended`; roles must be in the catalog (`ROLE_UNKNOWN`).

## 7. Implementation guidelines *(guideline)*

- A `Caller` value in the request context (`kind`, `id`, `scopes`, `actor`). Handlers never read headers for identity.
- Generate the scope table from the OpenAPI document at build time, and fail the build if a service operation has no `x-auth1-scope`.
- Use `github.com/gowebpki/jcs` (or an equivalent) for RFC 8785 canonicalisation; test that key order and white space do not change the hash.

## 8. To be detailed

- The `jwks_uri` fetch's TLS and timeout settings, and whether it goes through the mesh.
- Whether `list` needs a total count (proposal: no; counts on large tables are slow and rarely needed).
