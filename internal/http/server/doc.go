// Package server assembles the HTTP API router (middleware, probes, routes under http.base_path)
// and runs the HTTP servers with the timeouts of TDD-07 §7 and a bounded graceful shutdown
// (TDD-08 §1, §2).
package server
