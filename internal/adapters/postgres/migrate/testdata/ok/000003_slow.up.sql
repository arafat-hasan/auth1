-- Slow and not idempotent: a second run would fail on CREATE TABLE.
SELECT pg_sleep(0.2);
CREATE TABLE slow (id int);
