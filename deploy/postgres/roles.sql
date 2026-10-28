-- The roles of TDD-01 §4.1. A superuser runs this once, connected to the service's database; it
-- is safe to run again. Roles belong to the cluster, so on a second database only the schema
-- statements change anything.
--
-- auth1_migrator runs the migrations and owns every object they create.
-- auth1_app is the service at run time: the migrations grant it what it may do.
--
-- Neither role gets a password here: set them afterwards (see README.md).

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auth1_migrator') THEN
        CREATE ROLE auth1_migrator LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auth1_app') THEN
        CREATE ROLE auth1_app LOGIN;
    END IF;
END
$$;

ALTER SCHEMA public OWNER TO auth1_migrator;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO auth1_app;
