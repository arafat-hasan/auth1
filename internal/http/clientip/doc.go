// Package clientip finds the client IP of a request (TDD-07 §1) from the TCP peer and, through the
// proxies of http.trusted_proxies, X-Forwarded-For, and keeps it in the request context. Handlers
// and middleware read it with From; nothing logs it (G-6).
package clientip
