// Package health serves the liveness and readiness probes of SDD D-19 and TDD-08 §2: /livez answers
// while the process runs, and /readyz runs the registered checks. PostgreSQL and the keyrings
// register critical checks (WP-05, WP-12); Redis and the broker register non-critical ones.
package health
