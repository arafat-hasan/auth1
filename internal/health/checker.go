package health

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/uptrace/bun"

	"github.com/arafat-hasan/auth1/internal/app/repo"
)

const goroutineThreshold = 10_000

// BuildInfo carries compile-time metadata injected via -ldflags.
type BuildInfo struct {
	Version   string
	GitCommit string
	BuildDate string
}

type HealthChecker struct {
	db         *bun.DB
	redis      *redis.Client
	amqpURL    string
	outboxRepo repo.OutboxRepository
	startTime  time.Time
	build      BuildInfo
	logger     *logrus.Logger
}

func NewHealthChecker(
	db *bun.DB,
	redis *redis.Client,
	amqpURL string,
	outboxRepo repo.OutboxRepository,
	logger *logrus.Logger,
	build BuildInfo,
) *HealthChecker {
	return &HealthChecker{
		db:         db,
		redis:      redis,
		amqpURL:    amqpURL,
		outboxRepo: outboxRepo,
		startTime:  time.Now(),
		build:      build,
		logger:     logger,
	}
}

// ── Response types ────────────────────────────────────────────────────────────

type LivezResponse struct {
	Status     string `json:"status"`
	Goroutines int    `json:"goroutines"`
	Reason     string `json:"reason,omitempty"`
}

type ReadyzCheckResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type ReadyzResponse struct {
	Status string                       `json:"status"`
	Checks map[string]ReadyzCheckResult `json:"checks"`
}

type HealthCheckDetail struct {
	Status    string  `json:"status"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

type MemoryStats struct {
	AllocMB      float64 `json:"alloc_mb"`
	SysMB        float64 `json:"sys_mb"`
	HeapInUseMB  float64 `json:"heap_in_use_mb"`
	GCRuns       uint32  `json:"gc_runs"`
}

type OutboxStats struct {
	PendingCount int `json:"pending_count"`
	FailedCount  int `json:"failed_count"`
}

type HealthResponse struct {
	Status        string                        `json:"status"`
	Version       string                        `json:"version"`
	GitCommit     string                        `json:"git_commit"`
	BuildDate     string                        `json:"build_date"`
	UptimeSeconds float64                       `json:"uptime_seconds"`
	Goroutines    int                           `json:"goroutines"`
	Memory        MemoryStats                   `json:"memory"`
	Checks        map[string]HealthCheckDetail  `json:"checks"`
	Outbox        OutboxStats                   `json:"outbox"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Livez godoc
// @Summary     Liveness probe
// @Description Returns 200 if the process is running and goroutines are below threshold. No external dependency checks.
// @Tags        health
// @Produce     json
// @Success     200 {object} LivezResponse
// @Failure     503 {object} LivezResponse
// @Router      /livez [get]
func (h *HealthChecker) Livez(w http.ResponseWriter, r *http.Request) {
	goroutines := runtime.NumGoroutine()
	resp := LivezResponse{Goroutines: goroutines}

	status := http.StatusOK
	if goroutines > goroutineThreshold {
		resp.Status = "fail"
		resp.Reason = "goroutine count exceeds threshold"
		status = http.StatusServiceUnavailable
	} else {
		resp.Status = "ok"
	}

	writeJSON(w, status, resp)
}

// Readyz godoc
// @Summary     Readiness probe
// @Description Returns 200 only when all hard dependencies (DB, Redis, RabbitMQ) are reachable. 503 on any failure.
// @Tags        health
// @Produce     json
// @Success     200 {object} ReadyzResponse
// @Failure     503 {object} ReadyzResponse
// @Router      /readyz [get]
func (h *HealthChecker) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	results := h.runDependencyChecks(ctx)

	overall := "ok"
	for _, v := range results {
		if v.Status == "fail" {
			overall = "fail"
			break
		}
	}

	resp := ReadyzResponse{Status: overall, Checks: results}
	status := http.StatusOK
	if overall == "fail" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

// Health godoc
// @Summary     Comprehensive diagnostics
// @Description Full system metrics: dependency latencies, memory usage, goroutine count, uptime, build info, and outbox queue lag.
// @Tags        health
// @Produce     json
// @Success     200 {object} HealthResponse
// @Failure     503 {object} HealthResponse
// @Router      /health [get]
func (h *HealthChecker) Health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	checkDetails, overall := h.runDetailedChecks(ctx)

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	mem := MemoryStats{
		AllocMB:     mbFromBytes(memStats.Alloc),
		SysMB:       mbFromBytes(memStats.Sys),
		HeapInUseMB: mbFromBytes(memStats.HeapInuse),
		GCRuns:      memStats.NumGC,
	}

	outbox := h.collectOutboxStats(ctx)

	resp := HealthResponse{
		Status:        overall,
		Version:       h.build.Version,
		GitCommit:     h.build.GitCommit,
		BuildDate:     h.build.BuildDate,
		UptimeSeconds: time.Since(h.startTime).Seconds(),
		Goroutines:    runtime.NumGoroutine(),
		Memory:        mem,
		Checks:        checkDetails,
		Outbox:        outbox,
	}

	status := http.StatusOK
	if overall == "fail" {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, resp)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

func (h *HealthChecker) runDependencyChecks(ctx context.Context) map[string]ReadyzCheckResult {
	type namedResult struct {
		name string
		res  ReadyzCheckResult
	}

	ch := make(chan namedResult, 3)
	var wg sync.WaitGroup

	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fn()
			r := ReadyzCheckResult{Status: "ok"}
			if err != nil {
				r.Status = "fail"
				r.Error = err.Error()
			}
			ch <- namedResult{name, r}
		}()
	}

	run("db", func() error { return h.pingDB(ctx) })
	run("redis", func() error { return h.pingRedis(ctx) })
	run("rabbitmq", func() error { return h.pingAMQP() })

	wg.Wait()
	close(ch)

	results := make(map[string]ReadyzCheckResult, 3)
	for r := range ch {
		results[r.name] = r.res
	}
	return results
}

func (h *HealthChecker) runDetailedChecks(ctx context.Context) (map[string]HealthCheckDetail, string) {
	type namedResult struct {
		name string
		res  HealthCheckDetail
	}

	ch := make(chan namedResult, 3)
	var wg sync.WaitGroup

	measure := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			err := fn()
			latency := time.Since(start).Seconds() * 1000
			d := HealthCheckDetail{Status: "ok", LatencyMs: latency}
			if err != nil {
				d.Status = "fail"
				d.LatencyMs = 0
				d.Error = err.Error()
			}
			ch <- namedResult{name, d}
		}()
	}

	measure("db", func() error { return h.pingDB(ctx) })
	measure("redis", func() error { return h.pingRedis(ctx) })
	measure("rabbitmq", func() error { return h.pingAMQP() })

	wg.Wait()
	close(ch)

	details := make(map[string]HealthCheckDetail, 3)
	overall := "ok"
	for r := range ch {
		details[r.name] = r.res
		if r.res.Status == "fail" {
			overall = "fail"
		}
	}
	return details, overall
}

func (h *HealthChecker) pingDB(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return h.db.PingContext(checkCtx)
}

func (h *HealthChecker) pingRedis(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return h.redis.Ping(checkCtx).Err()
}

func (h *HealthChecker) pingAMQP() error {
	done := make(chan error, 1)
	go func() {
		conn, err := amqp.Dial(h.amqpURL)
		if err != nil {
			done <- err
			return
		}
		conn.Close()
		done <- nil
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		return context.DeadlineExceeded
	}
}

func (h *HealthChecker) collectOutboxStats(ctx context.Context) OutboxStats {
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var (
		pending, failed int
		wg              sync.WaitGroup
		mu              sync.Mutex
	)

	count := func(status string, dest *int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := h.outboxRepo.CountByStatus(checkCtx, status)
			if err != nil {
				h.logger.WithError(err).Warn("health: outbox count failed")
				return
			}
			mu.Lock()
			*dest = n
			mu.Unlock()
		}()
	}

	count("pending", &pending)
	count("failed", &failed)
	wg.Wait()

	return OutboxStats{PendingCount: pending, FailedCount: failed}
}

func mbFromBytes(b uint64) float64 {
	return float64(b) / (1024 * 1024)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// header already sent; nothing useful we can do
	}
}
