-- Reverts 000001: drops the partition function, then every table in the reverse order of
-- creation, with its indexes and, for auth_audit, its partitions. No CASCADE, so a dependency the
-- up file adds and this file misses fails instead of being hidden.

DROP FUNCTION auth_audit_create_partitions(integer);
DROP TABLE outbox;
DROP TABLE auth_audit;
DROP TABLE signing_keys;
DROP TABLE idempotency_keys;
DROP TABLE client_assertions;
DROP TABLE sms_budget;
DROP TABLE sign_in_throttles;
DROP TABLE refresh_tokens;
DROP TABLE sessions;
DROP TABLE challenges;
DROP TABLE flows;
DROP TABLE account_roles;
DROP TABLE recovery_codes;
DROP TABLE totp_factors;
DROP TABLE password_credentials;
DROP TABLE identifiers;
DROP TABLE accounts;
