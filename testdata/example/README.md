# Example placeholders

Empty files named by `config.example.yaml`, so that `auth1 config check --config
config.example.yaml` passes from the repository root. They hold no keys: `config check` only
checks that each file exists and is readable. Real fixtures replace them when the packages that
parse keyrings and keys arrive (WP-10, WP-12). Never put real secrets here.

`secrets/db/` is the exception: it holds local development DSNs for the two roles of
`deploy/postgres/roles.sql`, with each role's name as its password. `dsn` is `auth1_app`'s, which
`auth1 serve` reads through `database.dsn_file`; `migrator-dsn` is `auth1_migrator`'s, which
`auth1 migrate` takes with `--dsn-file`. They reach a local PostgreSQL bootstrapped as CLAUDE.md
shows. They have no TLS, so they are accepted only with `AUTH1_APP_ENVIRONMENT=development`.
