# Example secrets

Files named by `config.example.yaml`, so that `auth1 config check --config config.example.yaml`
passes from the repository root. Never put real secrets here.

`secrets/fields/` and `secrets/mac/mac.key` hold **public development keys**, generated for this
repository: the field keyring (`fields/keyring.yaml`: key 2 `active`, key 1 `decrypt`), the
blind-index key (`fields/bidx.key`) and the OTP and recovery-code MAC key (`mac/mac.key`). Anyone
can read them, so they protect nothing: never use them anywhere else, and never copy them into a
deployment. `config check` and `serve` parse them as they would real keys.

The other files are empty placeholders: `config check` only checks that each exists and is
readable. Real fixtures replace them when the packages that parse them arrive (WP-11 for
`pepper/`, WP-12 for `signing/`; `mac/device.key` with the device cookie).

`secrets/db/` holds local development DSNs for the two roles of `deploy/postgres/roles.sql`, with
each role's name as its password. `dsn` is `auth1_app`'s, which `auth1 serve` reads through
`database.dsn_file`; `migrator-dsn` is `auth1_migrator`'s, which `auth1 migrate` takes with
`--dsn-file`. They reach a local PostgreSQL bootstrapped as CLAUDE.md shows. They have no TLS, so
they are accepted only with `AUTH1_APP_ENVIRONMENT=development`.
