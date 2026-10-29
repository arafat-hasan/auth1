// Command routegen writes the route metadata of api/openapi.yaml for package gen: each served
// operation's method, path, security schemes and x-auth1-scope. It fails, naming the operation,
// when a service operation (one that accepts workload or serviceToken) has no scope, another
// operation has one, or a scope is not declared (TDD-05 §3, §7).
package main
