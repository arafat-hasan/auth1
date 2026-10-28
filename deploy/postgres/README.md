# PostgreSQL roles

auth1 uses two roles (TDD-01 §4.1):

- `auth1_migrator` runs `auth1 migrate` and owns the `public` schema and everything in it.
- `auth1_app` is the service at run time. It may use the schema but not create anything in it; the
  migrations grant it what it may read and write.

The migrations do not create the roles, since roles belong to the cluster and creating them needs
`CREATEROLE`. A DBA creates them once, before the first `auth1 migrate up`:

1. Create the database, then run `roles.sql` in it as a superuser:
   `psql -d auth1 -f deploy/postgres/roles.sql`. The script can be run again safely.
2. Set the passwords, for example with `\password auth1_migrator` and `\password auth1_app` in
   psql, or use another authentication method for the two roles.
3. Run `auth1 migrate up --dsn-file <file>` with a DSN for `auth1_migrator`. It fails, naming the
   role, if one is missing.
4. Give the service a DSN for `auth1_app` in `database.dsn_file`.
