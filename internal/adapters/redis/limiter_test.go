package redis_test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/arafat-hasan/auth1/internal/adapters/redis"
	"github.com/arafat-hasan/auth1/internal/app"
	"github.com/arafat-hasan/auth1/internal/config"
	"github.com/arafat-hasan/auth1/internal/telemetry"
	"github.com/arafat-hasan/auth1/internal/testing/fakes"
	"github.com/arafat-hasan/auth1/internal/testing/redistest"
)

var start = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

// rig is a limiter on a Redis server with a fake clock and its counters on a manual reader.
type rig struct {
	limiter *redis.Limiter
	client  *goredis.Client
	clock   *fakes.Clock
	reader  *sdkmetric.ManualReader
	prefix  string
}

func newRig(t *testing.T, addr string) *rig {
	t.Helper()
	client, err := redis.Open(config.Redis{Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	reader := sdkmetric.NewManualReader()
	m := telemetry.NewMetrics(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	r := &rig{client: client, clock: fakes.NewClock(start), reader: reader, prefix: redistest.Prefix(t)}
	o := redis.Options{Prefix: r.prefix, Clock: r.clock}
	if o.Limited, err = m.Counter("auth1_rate_limited_total"); err != nil {
		t.Fatal(err)
	}
	if o.Errors, err = m.Counter("auth1_rate_limiter_errors_total"); err != nil {
		t.Fatal(err)
	}
	r.limiter = redis.NewLimiter(client, o)
	return r
}

// sums returns each counter's data points as "name{k=v}" → value.
func (r *rig) sums(t *testing.T) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			if s, ok := met.Data.(metricdata.Sum[int64]); ok {
				for _, dp := range s.DataPoints {
					var labels []string
					for _, kv := range dp.Attributes.ToSlice() {
						labels = append(labels, string(kv.Key)+"="+kv.Value.String())
					}
					out[met.Name+"{"+strings.Join(labels, ",")+"}"] += dp.Value
				}
			}
		}
	}
	return out
}

func (r *rig) hit(t *testing.T, rule app.Rule, key string, limit app.RateLimit) app.RateDecision {
	t.Helper()
	d, err := r.limiter.Hit(context.Background(), rule, key, limit)
	if err != nil {
		t.Fatalf("Hit: %v", err)
	}
	return d
}

func TestHitWindow(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	limit := app.RateLimit{Limit: 3, Window: time.Minute}
	for i := range 3 {
		if d := r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit); !d.Allowed {
			t.Fatalf("hit %d refused", i+1)
		}
		r.clock.Advance(10 * time.Second)
	}
	// Hits at 0s, 10s and 20s; now 30s. The window has room again at 60s.
	d := r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit)
	if d.Allowed || d.RetryAfter != 30*time.Second {
		t.Fatalf("fourth hit = %+v, want refused with RetryAfter 30s", d)
	}
	r.clock.Advance(29 * time.Second)
	if d := r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit); d.Allowed {
		t.Fatalf("at 59s = %+v, want refused: the first hit is still in the window", d)
	}
	r.clock.Advance(time.Second)
	if d := r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit); !d.Allowed {
		t.Fatalf("at 60s = %+v, want allowed: the first hit has left the window", d)
	}
	// Refused hits were not counted: the window holds 10s, 20s and 60s, so it is full again.
	if d := r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit); d.Allowed || d.RetryAfter != 10*time.Second {
		t.Fatalf("at 60s again = %+v, want refused with RetryAfter 10s", d)
	}
}

func TestHitKeyLayout(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	r.hit(t, app.RuleGlobalIP, "192.0.2.1", app.RateLimit{Limit: 5, Window: time.Minute})
	key := r.prefix + "rl:global_ip:192.0.2.1"
	ctx := context.Background()
	n, err := r.client.ZCard(ctx, key).Result()
	if err != nil || n != 1 {
		t.Fatalf("ZCARD %s = %d, %v; want 1", key, n, err)
	}
	ttl, err := r.client.PTTL(ctx, key).Result()
	if err != nil || ttl <= 0 || ttl > time.Minute {
		t.Fatalf("PTTL %s = %v, %v; want within (0, 1m]", key, ttl, err)
	}
}

func TestHitSameMicrosecond(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	limit := app.RateLimit{Limit: 2, Window: time.Minute}
	r.hit(t, app.RuleSendIP, "k", limit)
	r.hit(t, app.RuleSendIP, "k", limit)
	if d := r.hit(t, app.RuleSendIP, "k", limit); d.Allowed {
		t.Fatal("third hit in one microsecond allowed: two hits at one instant must both count")
	}
}

func TestHitRulesIndependent(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	limit := app.RateLimit{Limit: 1, Window: time.Minute}
	r.hit(t, app.RuleSignInIP, "192.0.2.1", limit)
	if d := r.hit(t, app.RuleResumeIP, "192.0.2.1", limit); !d.Allowed {
		t.Error("another rule's window was shared")
	}
	if d := r.hit(t, app.RuleSignInIP, "192.0.2.2", limit); !d.Allowed {
		t.Error("another key's window was shared")
	}
}

func TestSlash64SharesWindow(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	rules := map[app.Rule]app.RateLimit{}
	for _, rule := range app.Rules() {
		rules[rule] = app.RateLimit{Limit: 1, Window: time.Minute}
	}
	limits, err := app.NewRateLimits(r.limiter, rules)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := limits.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8:1:2::1")); err != nil {
		t.Fatalf("first address: %v", err)
	}
	if err := limits.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8:1:2:ffff::9")); err == nil {
		t.Fatal("a second address in the same /64 was allowed: they must share one window")
	}
	if err := limits.CheckIP(ctx, app.RuleGlobalIP, netip.MustParseAddr("2001:db8:1:3::1")); err != nil {
		t.Fatalf("an address in another /64: %v", err)
	}
}

func TestHitCountsRefusals(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	limit := app.RateLimit{Limit: 1, Window: time.Minute}
	r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit)
	r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit)
	r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit)
	got := r.sums(t)
	if got["auth1_rate_limited_total{rule=global_ip}"] != 2 || len(got) != 1 {
		t.Fatalf("counters = %v, want only auth1_rate_limited_total{rule=global_ip} = 2", got)
	}
}

func TestHitRedisDown(t *testing.T) {
	t.Parallel()
	srv := redistest.NewServer(t)
	r := newRig(t, srv.Addr())
	limit := app.RateLimit{Limit: 1, Window: time.Minute}
	r.hit(t, app.RuleGlobalIP, "192.0.2.1", limit)
	srv.Stop(t)

	begin := time.Now()
	if _, err := r.limiter.Hit(context.Background(), app.RuleGlobalIP, "192.0.2.1", limit); err == nil {
		t.Fatal("Hit with Redis stopped succeeded")
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Errorf("Hit with Redis stopped took %v, want it bounded by the call timeout", elapsed)
	}
	if got := r.sums(t)["auth1_rate_limiter_errors_total{}"]; got != 1 {
		t.Errorf("auth1_rate_limiter_errors_total = %d, want 1", got)
	}
}

func TestHitBlackholed(t *testing.T) {
	t.Parallel()
	// 192.0.2.0/24 (TEST-NET-1) is not routed, so the dial hangs until its timeout.
	r := newRig(t, "192.0.2.1:6379")
	begin := time.Now()
	if _, err := r.limiter.Hit(context.Background(), app.RuleGlobalIP, "k", app.RateLimit{Limit: 1, Window: time.Minute}); err == nil {
		t.Fatal("Hit against an unreachable address succeeded")
	}
	if elapsed := time.Since(begin); elapsed > time.Second {
		t.Errorf("Hit took %v, want it bounded by the call timeout", elapsed)
	}
}

func TestOpenReadsPassword(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := redis.Open(config.Redis{Address: "localhost:6379", PasswordFile: config.NewSecretFile(path)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if got := c.Options().Password; got != "s3cret" {
		t.Errorf("password = %q, want the file's trimmed contents", got)
	}
	if _, err := redis.Open(config.Redis{Address: "x", PasswordFile: config.NewSecretFile(filepath.Join(t.TempDir(), "none"))}); err == nil {
		t.Error("Open with a missing password file succeeded")
	}
}

func TestPing(t *testing.T) {
	t.Parallel()
	srv := redistest.NewServer(t)
	r := newRig(t, srv.Addr())
	ping := redis.Ping(r.client, time.Second)
	if err := ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	srv.Stop(t)
	if err := ping(context.Background()); err == nil {
		t.Fatal("Ping with Redis stopped succeeded")
	}
}

// TestHitCallerCancelled: a request whose own context has ended (the client went away) is not a
// Redis failure, so it does not count towards the "Redis down" alert.
func TestHitCallerCancelled(t *testing.T) {
	t.Parallel()
	r := newRig(t, redistest.Addr(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.limiter.Hit(ctx, app.RuleGlobalIP, "k", app.RateLimit{Limit: 1, Window: time.Minute}); err == nil {
		t.Fatal("Hit with a cancelled context succeeded")
	}
	if got := r.sums(t)["auth1_rate_limiter_errors_total{}"]; got != 0 {
		t.Errorf("auth1_rate_limiter_errors_total = %d, want 0 for the caller's own cancellation", got)
	}
}
