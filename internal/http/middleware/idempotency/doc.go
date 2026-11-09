// Package idempotency reads the Idempotency-Key header of the operations that take it (TDD-05 §4):
// it validates the key, computes the request hash, sha256(method ‖ 0x00 ‖ path ‖ 0x00 ‖ JCS(body))
// with the RFC 8785 canonical JSON of the body, and keeps the app.IdempotencyRequest, scoped by
// the caller, in the request context for handlers (From). It opens no transaction: the use case
// claims the key with app.Idempotency.Run. The key is never logged, traced or a metric label.
package idempotency
