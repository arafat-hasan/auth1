// Package clientcreds is the client-credentials grant of POST /v1/oauth/token (TDD-05 §2): it
// checks a service client's private_key_jwt assertion, records its jti once and issues a service
// token with the scopes granted.
package clientcreds
