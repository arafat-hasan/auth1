// Package tokens issues and validates access tokens (TDD-04 §1, §6 steps 1–2; SDD D-5, D-12):
// RFC 9068 JWTs, typ at+jwt, signed through app.TokenSigner and verified against app.PublicKeys
// (the signing keyring of TDD-04 §5) with the published key's own alg. It holds no key and logs
// nothing; no error it returns holds any part of a token.
package tokens
