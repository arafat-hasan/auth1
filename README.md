# auth1

A product-agnostic identity service in Go: accounts, identifiers, passwords, optional multi-factor
authentication, sessions, tokens, account state and roles. One deployment serves one product;
everything that differs between products is configuration.

> **Status: redesign for 1.0.** The design below is agreed; the implementation plan is in GitHub
> issues, starting from the pinned [roadmap #69](https://github.com/arafat-hasan/auth1/issues/69).
> The repository holds the 1.0 skeleton; the pre-1.0 prototype is in git history only. 1.0 has a
> fresh schema and no compatibility with the prototype's API, tokens or data.

## Design

| Document | Contents |
|---|---|
| [docs/design.md](docs/design.md) | Software Design Description (SDD): needs, decisions and their reasons, architecture, state models, threat model |
| [docs/tdd/](docs/tdd/) | Technical Design Documents TDD-01…08: schema, flows, credentials and MFA, tokens and keys, service access, events and delivery, abuse protection, operations |
| [api/openapi.yaml](api/openapi.yaml) | HTTP contract (OpenAPI 3.1) |
| [api/asyncapi.yaml](api/asyncapi.yaml) | Lifecycle events (AsyncAPI 3.0, CloudEvents 1.0) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | One-page overview and a map of the documents |

**auth1 1.0 in brief:**
- Several identifiers per account, each verified on its own, unique once verified.
- Every account has a password (Argon2id).
- Optional TOTP with recovery codes, which any account may enable and a client may require.
- Opaque, rotated refresh tokens with reuse detection.
- Signed access tokens from a rotating keyring, with a JWKS.
- Restricted sessions for suspended or banned accounts.
- Services authenticated by workload identity or client credentials, with scopes.
- A directory and account-control API for the product's services.
- CloudEvents through a transactional outbox.
- Messages whose secrets are resolved only at send time.

## Building

Go 1.27 or later.

```bash
make build
```

```bash
./bin/auth1 version
```

`make test` and `make lint` run the tests and the linters. Nothing else runs yet; the work packages
in the roadmap add the service step by step.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
