-- Parked outbox rows, for the relay's auth1_outbox_parked gauge (TDD-06 §3.2, TDD-08 §5.2), which
-- every replica reads every 15 s. No other index covers them: outbox_delivery_pending leaves them
-- out, and without this one the count scans the outbox, published rows included. Parked rows are
-- rare, so the index stays small.
CREATE INDEX outbox_parked ON outbox (destination) WHERE parked_at IS NOT NULL AND published_at IS NULL;
