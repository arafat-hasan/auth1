// Package assertiontest makes service clients and their client assertions (TDD-05 §2) for tests:
// a key pair with its JWKS, and private_key_jwt assertions minted with any claim, header,
// signer or algorithm, including those the token endpoint must refuse. Only test files import it.
package assertiontest
