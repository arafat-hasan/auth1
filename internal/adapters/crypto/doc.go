// Package crypto implements field encryption, blind indexes, MACs and the SHA-256 helper
// (TDD-01 §3), with the keys and keyrings they use (TDD-08 §4), the pepper keyring among them; the
// Argon2id password hasher (TDD-03 §1) is its subpackage argon2id.
//
// Keys and keyrings never show key bytes when formatted or logged, and no error names a key,
// a plaintext or a row (G-6).
package crypto
