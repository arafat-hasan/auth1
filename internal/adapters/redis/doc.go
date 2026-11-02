// Package redis implements the sliding-window rate limiter on Redis (TDD-07 §8): app.RateLimiter
// for the limits L-1, L-2, L-4, L-5, L-8, L-12, L-14 and L-15. Redis holds nothing else.
package redis
