// Package argon2id implements app.PasswordHasher (TDD-03 §1): the password is normalised to NFKC,
// HMAC-SHA256'd under a pepper key and hashed with Argon2id, stored as a PHC string beside the
// pepper key's id. A per-replica semaphore bounds the hashes running at once (SDD D-7, T-36), and
// a dummy hash computed at start-up keeps an unknown identifier as slow as a known one.
//
// No error, log or metric shows a password, a pepper, a salt or a hash (G-6).
package argon2id
