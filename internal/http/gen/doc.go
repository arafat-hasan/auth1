// Package gen holds the server interface and types generated from api/openapi.yaml by
// oapi-codegen (TDD-08 §2, §11), the route metadata with each operation's x-auth1-scope
// (TDD-05 §3), Stub, which answers every operation 501, and Routes, which mounts a
// StrictServerInterface on a Chi router. Run `make generate` after changing the contract.
package gen
