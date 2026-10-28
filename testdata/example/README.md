# Example placeholders

Empty files named by `config.example.yaml`, so that `auth1 config check --config
config.example.yaml` passes from the repository root. They hold no keys: `config check` only
checks that each file exists and is readable. Real fixtures replace them when the packages that
parse keyrings and keys arrive (WP-10, WP-12). Never put real secrets here.

`secrets/db/dsn` is the exception: it holds a local development DSN,
`postgres://auth1:auth1@localhost:5432/auth1?sslmode=disable`, so `auth1 serve` and `auth1 migrate`
reach a PostgreSQL container started with those credentials. It has no TLS, so it is accepted only
with `AUTH1_APP_ENVIRONMENT=development`.
