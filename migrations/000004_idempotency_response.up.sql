-- The stored response of an idempotency key is sealed with field encryption (TDD-05 §4, TDD-01 §3):
-- an account in a response body carries its display name and may carry its identifiers. Nothing
-- has stored a response yet, so the column is replaced, not converted.
ALTER TABLE idempotency_keys ALTER COLUMN response TYPE bytea USING NULL;
