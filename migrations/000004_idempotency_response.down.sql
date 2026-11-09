-- Reverts 000004. Sealed responses cannot be read back as JSON, so they are dropped.

ALTER TABLE idempotency_keys ALTER COLUMN response TYPE jsonb USING NULL;
