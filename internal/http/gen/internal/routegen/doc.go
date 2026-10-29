// Command routegen writes two files of package gen from api/openapi.yaml: the route metadata
// (each served operation's method, path, security schemes and x-auth1-scope) and Stub,
// which answers every operation with ErrNotImplemented. It fails, naming the operation, when a
// service operation (one that accepts workload or serviceToken) has no scope, another operation
// has one, or a scope is not declared (TDD-05 §3, §7), and when an operation that takes
// parameters or a body does not declare 422, which gen.Routes answers when it cannot bind them.
package main
