// Package keyring holds the signing keyring (TDD-04 §5): it loads and validates the keyring file
// (§5.1), syncs publication times with the database (§5.2, I-14), signs with the current key
// (app.TokenSigner) and publishes the key set (app.PublicKeys).
package keyring
