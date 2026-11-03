// Package caller authenticates the services that call auth1's service operations (TDD-05 §1, §3):
// it resolves the caller from the mesh's workload identity, or from a service token through a
// hook, enforces each operation's x-auth1-scope from the generated route metadata, validates
// Auth1-Actor, and keeps the Caller in the request context for handlers (From). Identity headers
// count only from a peer in service_auth.mesh.trusted_sidecar_cidrs; nothing logs them (G-6).
package caller
