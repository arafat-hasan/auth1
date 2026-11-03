// Package middleware holds the HTTP middleware (TDD-08 §2, §5; TDD-07 §1, §7). WP-03 adds trace,
// access log with the request-duration metric, panic recovery and the body limit; WP-50 the L-1
// rate limit (RateLimit), with the client IP in internal/http/clientip; WP-40 service-caller
// authentication and scopes in the subpackage caller. Origin, CORS and user authentication follow
// in later work packages. Request ids are in internal/http/requestid and problem details in
// internal/http/problem.
//
// Each middleware is installed with chi.Router.Use on the root router, so it runs inside Chi's
// routing context and reads the matched route pattern after the handler returns.
package middleware
