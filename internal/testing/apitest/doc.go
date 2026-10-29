// Package apitest checks HTTP exchanges against api/openapi.yaml in API tests (TDD-08 §9), with
// pb33f/libopenapi-validator, which handles OpenAPI 3.1. Only test files import it.
//
// New loads the contract once per test package or test; Serve runs a handler and reports every
// way the request or the response breaks the contract through t.Errorf.
package apitest
