# Migrations

Plain SQL, applied in order by `auth1 migrate up` under a PostgreSQL advisory lock (TDD-01 §4.3).

- Each migration is a pair, `NNNNNN_<name>.up.sql` and `NNNNNN_<name>.down.sql`: a six-digit
  version and a name of lower-case letters, digits and `_`. Every migration has a down file.
- Create the next pair with `auth1 migrate create <name>` (or `make migrate ARGS="create <name>"`).
- The files are embedded in the binary. Each runs in its own transaction, so a statement that
  cannot run in a transaction, such as `CREATE INDEX CONCURRENTLY`, cannot be used.
- Never edit a migration once it has been applied anywhere: `up` and `down` refuse a changed file
  and `status` shows it as `applied, changed` (`schema_migrations` keeps the SHA-256 of each up
  file).
- Only `up` creates `schema_migrations`, so `status` works for a role that may read the table but
  not create tables. `up`, `down` and `status` wait at most `--wait` (default 1m) for a connection
  and the advisory lock.
- After 1.0 ships, migrations are expand and contract only.
