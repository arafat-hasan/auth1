// Package idempotency runs the idempotency component end to end (TDD-05 §4, I-9, T-26): the
// Idempotency-Key middleware, app.Idempotency and the PostgreSQL repositories, behind a test-only
// handler, since no account-control operation is served yet.
package idempotency
