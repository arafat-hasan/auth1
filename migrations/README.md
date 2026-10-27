# Migrations

Plain SQL, applied in order by `auth1 migrate up` under a PostgreSQL advisory lock (TDD-01 §4.3).

- Each migration is a pair, `NNNNNN_<name>.up.sql` and `NNNNNN_<name>.down.sql`: a six-digit
  version and a name of lower-case letters, digits and `_`. Every migration has a down file.
- Create the next pair with `auth1 migrate create <name>` (or `make migrate ARGS="create <name>"`).
- The files are embedded in the binary. Each runs in its own transaction, so a statement that
  cannot run in a transaction, such as `CREATE INDEX CONCURRENTLY`, cannot be used.
- Never edit a migration once it has been applied anywhere: `up` refuses a changed file (it keeps
  the SHA-256 of each up file in `schema_migrations`).
- After 1.0 ships, migrations are expand and contract only.
