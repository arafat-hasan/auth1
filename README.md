# auth1

A product-agnostic identity service in Go: accounts, identifiers, passwords, mandatory multi-factor
authentication, sessions, tokens, account state and roles. One deployment serves one product;
everything that differs between products is configuration.

> **Status: redesign for 1.0.** The design below is agreed and the implementation plan comes next.
> The code in this repository is a pre-1.0 prototype that 1.0 replaces, with a fresh schema and no
> compatibility with the prototype's API, tokens or data.

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
- Every account has a password (Argon2id) and TOTP with recovery codes.
- Opaque, rotated refresh tokens with reuse detection.
- Signed access tokens from a rotating keyring, with a JWKS.
- Restricted sessions for suspended or banned accounts.
- Services authenticated by workload identity or client credentials, with scopes.
- A directory and account-control API for the product's services.
- CloudEvents through a transactional outbox.
- Messages whose secrets are resolved only at send time.

## Running the prototype

The prototype needs Go, PostgreSQL, Redis and RabbitMQ.

```bash
./scripts/generate_keys.sh
```

```bash
cp config.example.yaml config.yaml
```

```bash
docker compose up -d
```

[QUICK_START.md](QUICK_START.md) and [DOCKER_SETUP.md](DOCKER_SETUP.md) describe the prototype's
setup in more detail. `CLAUDE.md` describes its code layout. None of it describes 1.0.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
