package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"
)

// checkTimeout bounds each readiness check.
const checkTimeout = 2 * time.Second

// Checker holds the readiness checks. It is safe for concurrent use.
type Checker struct {
	logger  *slog.Logger
	timeout time.Duration

	mu     sync.Mutex
	checks []check
}

type check struct {
	name     string
	fn       func(context.Context) error
	critical bool
}

// New returns a Checker with no checks, logging failing checks to logger.
func New(logger *slog.Logger) *Checker {
	return &Checker{logger: logger, timeout: checkTimeout}
}

// Register adds a readiness check. A failing critical check makes /readyz answer 503; a failing
// non-critical one is only reported. Registering a name again replaces the earlier check in place.
// fn should return when its context is done; one that does not is counted as failing at the check
// timeout and left to finish on its own.
func (c *Checker) Register(name string, fn func(context.Context) error, critical bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := check{name: name, fn: fn, critical: critical}
	if i := slices.IndexFunc(c.checks, func(x check) bool { return x.name == name }); i >= 0 {
		c.checks[i] = ch
		return
	}
	c.checks = append(c.checks, ch)
}

// Live answers 200 {"status":"ok"} while the process runs.
func (c *Checker) Live() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// checkResult is one check in the /readyz body. It holds no error text.
type checkResult struct {
	Name     string `json:"name"`
	Critical bool   `json:"critical"`
	Status   string `json:"status"` // ok or failing
}

type readyBody struct {
	Status string        `json:"status"` // ready or not_ready
	Checks []checkResult `json:"checks"`
}

// Ready runs every check concurrently, each bounded by the check timeout, and answers 200 when
// every critical check passes, else 503. The body lists each check's status in registration
// order; a failing check's error is logged, not returned.
func (c *Checker) Ready() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		checks := slices.Clone(c.checks)
		c.mu.Unlock()

		errs := c.run(r.Context(), checks)

		body := readyBody{Status: "ready", Checks: make([]checkResult, len(checks))}
		for i, ch := range checks {
			res := checkResult{Name: ch.name, Critical: ch.critical, Status: "ok"}
			if errs[i] != nil {
				res.Status = "failing"
				if ch.critical {
					body.Status = "not_ready"
				}
				c.logger.LogAttrs(r.Context(), slog.LevelWarn, "readiness check failing",
					slog.String("check", ch.name), slog.Bool("critical", ch.critical),
					slog.String("error", errs[i].Error()))
			}
			body.Checks[i] = res
		}
		code := http.StatusOK
		if body.Status != "ready" {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, body)
	})
}

// run runs checks concurrently, each bounded by the check timeout, and returns their errors in order.
func (c *Checker) run(ctx context.Context, checks []check) []error {
	errs := make([]error, len(checks))
	var wg sync.WaitGroup
	for i, ch := range checks {
		wg.Go(func() { errs[i] = c.runOne(ctx, ch.fn) })
	}
	wg.Wait()
	return errs
}

// runOne runs fn bounded by the check timeout. When the timeout passes first, it returns the
// context's error without waiting for fn, so a check that ignores its context cannot hold /readyz.
func (c *Checker) runOne(ctx context.Context, fn func(context.Context) error) error {
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	done := make(chan error, 1) // buffered, so an abandoned check's goroutine can still finish
	go func() { done <- fn(cctx) }()
	select {
	case err := <-done:
		return err
	case <-cctx.Done():
		return cctx.Err()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // the status is sent; a failed write cannot be reported
}
