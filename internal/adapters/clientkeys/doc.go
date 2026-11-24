// Package clientkeys holds the public keys of service clients (TDD-05 §2): it parses a client's
// JWKS, loads jwks_file at start-up and re-reads it every 30 s, and fetches and caches jwks_uri.
// Store implements app.ClientKeys.
package clientkeys
