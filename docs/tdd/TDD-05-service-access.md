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

**Assertion checks.** Any failure answers `invalid_client`, the same body whichever check failed.
They run in this order:

1. The assertion is a compact JWS of at most 8 KiB. Its protected header holds `alg`, `kid` and
   optionally `typ`, nothing else (`jku`, `jwk`, `x5u`, `x5c`, `crit` are refused). `alg` is
   `RS256` or `ES256` (never `none` or HMAC), `kid` is present, and `typ`, if present, is `JWT` or
   `client-authentication+jwt`.
2. `iss` = `sub` = a configured client id.
3. The key `kid` of that client (see *Client keys*), outside any transaction (SDD §6.3).
4. The signature verifies with that key, whose algorithm is the header's `alg`.
5. `aud`, a string or an array, contains the token endpoint URL (the metadata's `token_endpoint`:
   the issuer's origin, `http.base_path`, `/v1/oauth/token`) or the issuer.
6. `exp` is in the future, with no leeway. `iat` is present, not more than 30 s in the future, and
   `exp` is at most 5 minutes after it. `nbf`, if present, is not more than 30 s in the future.
7. `jti` is 1–256 characters.
8. The scope is granted (see *Response*); an empty grant answers `invalid_scope` and records no
   `jti`.
9. `jti` is new: `INSERT INTO client_assertions (client_id, jti, expires_at) VALUES (…)
   ON CONFLICT DO NOTHING`, one statement on its own, with `expires_at` = `exp` + 30 s so the row
   outlives clock skew between replicas. No row inserted means a replay.

**Client keys.** Each client has exactly one of `jwks_file` and `jwks_uri`. A key is used when it
has a `kid`, its `use` is absent or `sig`, it is RSA of at least 2048 bits (`RS256`) or P-256
(`ES256`), and its `alg`, if given, matches. A set with no usable key, or with a repeated `kid`, is
refused.
- **`jwks_file`** is read at start-up (`config check` and `serve` refuse a bad one) and re-read
  every 30 s; a bad file keeps the last good set.
- **`jwks_uri`** is fetched when first needed and cached for 10 minutes; an unknown `kid` refetches
  it at most once a minute per client, with one fetch in flight per client. A fetch has a 5 s
  timeout, TLS 1.2 or later against the system roots, no redirects, and accepts only a `200` of at
  most 64 KiB. It goes directly, not through the mesh. A failed fetch keeps the cached set. With no
  set cached and the fetch failed, the answer is `503 UNAVAILABLE`.

**Response.** RFC 6749 JSON: `access_token`, `token_type: Bearer`, `expires_in`, `scope`, with
`Cache-Control: no-store`.
- The token is signed by the keyring. Header: `alg`, `kid`, `typ: at+jwt` (RFC 9068). Claims:
  - `iss` = `http.issuer`;
  - `sub` = `client_id` = the client id;
  - `aud` = `service_auth.client_credentials.audience` (default `auth1-services`);
  - `iat` = `nbf` = now; `exp` = now + `token_ttl`, 5 minutes *(cfg, ≤ 15)*;
  - `jti` = a UUIDv7;
  - `scope` = the requested scopes ∩ the configured ones, or all the configured ones if none were
    requested, space-separated. A client's configured scopes are those of its
    `service_auth.callers` entry whose `identity` is the client id; a client without one is a
    configuration error.
- An empty grant answers `invalid_scope`.
- Errors on this endpoint follow RFC 6749 §5.2, not problem details, so OAuth client libraries
  work: `invalid_client` is `401`, without `WWW-Authenticate` (the client authenticates in the
  body, not the `Authorization` header) and without `error_description`; `invalid_request`,
  `unsupported_grant_type` and `invalid_scope` are `400`. A body that cannot be decoded at all is
  `422 VALIDATION_FAILED`; a store or keyring failure is `503 UNAVAILABLE`.
- When `service_auth.mode` does not include client credentials, the endpoint answers `404`.

**Audience separation.**
- Service tokens are accepted only on service endpoints.
- User tokens (client audiences, the self audience) are never accepted there.
- Service tokens are never accepted on user endpoints.
- The service audience differs from every client audience, the self audience and the issuer
  (TDD-08 §3.1), and the claim sets differ (`sub` is a client id, not an account id), so each
  validator refuses the other kind on either ground.

## 3. Scope enforcement

- **Caller.** A middleware resolves the caller: the mesh identity, or a valid service token. In mode `both`, either is accepted. With neither, it answers `401 TOKEN_INVALID`.
- **Scopes.** Each operation's required scope comes from the OpenAPI `x-auth1-scope`, through generated route metadata, not a hand-written table. A caller without it gets `403 CALLER_NOT_ALLOWED`. The denial increments `auth1_service_calls_denied_total` and is audited.
- **`Auth1-Actor`.**
  - **Format:** at most 128 printable ASCII characters. *(guideline: `<kind>:<id>`, for example `staff:7f3c…`)*.
  - **Recorded** in `auth_audit.on_behalf` and in the event's `actor` extension.
  - **A malformed value** is a `VALIDATION_FAILED`.

## 4. Idempotency

Every account-control write requires `Idempotency-Key`: 1–255 visible ASCII characters (`!` to
`~`, no space), as the contract's pattern. A key belongs to its caller: rows are keyed by
`(caller, key)`, where `caller` is `<kind>:<id>` (`workload:<identity>` or `client:<client id>`),
so two callers never share a key.

1. Before any transaction, the middleware computes `request_hash = sha256(method ‖ 0x00 ‖ path ‖
   0x00 ‖ JCS(body))`: the method in upper case; the escaped request path, `http.base_path`
   included and the query left out (so `%00` stays three characters; no account-control operation
   takes a query); and the RFC 8785 canonical JSON of the body, empty when no body is sent. A body
   that is not I-JSON (a duplicate member, say) is `422 VALIDATION_FAILED`. Headers, `Auth1-Actor`
   included, are not part of the hash. The rest runs in the operation's transaction.
2. `INSERT INTO idempotency_keys (caller, key, request_hash, created_at) VALUES (…, now())
   ON CONFLICT (caller, key) DO UPDATE … WHERE idempotency_keys.created_at < now() - retention`:
   a row older than `retention.idempotency_keys` counts as absent, though the purge (TDD-01 §5) has
   not removed it yet.
   - **Inserted:** run the operation under a savepoint. Store `status` and `response` in the same
     transaction, then commit.
   - **Conflict:** the insert waits if another transaction holds the key uncommitted. On a
     committed row it leaves that row locked (`ON CONFLICT … DO UPDATE` locks the row even when its
     `WHERE` refuses the update), and `SELECT … FOR UPDATE` reads it. A different `request_hash` answers `422 IDEMPOTENCY_KEY_REUSED`;
     otherwise replay the stored `status` and `response`. The wait is bounded by a `lock_timeout` of
     5 s on the claim; past it the answer is `503 UNAVAILABLE` with `Retry-After: 1`, and nothing
     is stored. If the holder rolls back, the waiting request claims the key and runs the operation
     itself.
3. 2xx and 4xx outcomes are stored and replayed, with these rules:
   - An operation that refuses (its answer a 4xx) first rolls back to the savepoint, so it leaves
     no effect, and no version change on an account it locked (TDD-01 §4.2). Only the stored
     outcome commits. A success must answer a 2xx and a refusal a 4xx; any other pairing is a
     fault, a 5xx.
   - A 429 is not stored: it says "try later", not what the request did. It rolls back like a 5xx.
   - A 5xx rolls back the transaction, so the key is free for a retry.
   - The stored `response` is the content type and the body, at most 64 KiB, sealed with field
     encryption (TDD-01 §3), because an account in a body carries its display name and may carry
     identifiers. A larger body is a fault: the whole transaction rolls back, the operation has no
     effect and the answer is 503. Other headers (`Location`, `Retry-After`) are not stored, so
     an account-control operation answers without them; only 429 and 503, never stored, carry
     `Retry-After`.

The key row is locked before anything else in the transaction (TDD-01 §4.2); a claim after
another lock is refused. No in-flight state is
visible to others, because the key row commits only with the operation (I-9). The key itself is
never logged, traced or used as a metric label. Bootstrap invitations (TDD-02 §8.1) use the same
component without HTTP, with the caller `system`, the key `bootstrap:<email bidx>`, and the
request hash computed as for `POST /v1/invitations` with the invitation's body.

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

- Whether `list` needs a total count (proposal: no; counts on large tables are slow and rarely needed).
