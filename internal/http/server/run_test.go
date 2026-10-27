package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// runAsync starts Run and returns a channel receiving its result.
func runAsync(ctx context.Context, ls []Listener, s Shutdown) <-chan error {
	done := make(chan error, 1)
	go func() { done <- Run(ctx, slog.New(slog.DiscardHandler), ls, s) }()
	return done
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
		return nil
	}
}

func TestRunDrainsInFlight(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("done"))
	})
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	var drains atomic.Int32
	done := runAsync(ctx, []Listener{{Name: "main", Listener: ln, Handler: h}},
		Shutdown{Drain: func() { drains.Add(1) }, DrainDelay: 50 * time.Millisecond, Timeout: 5 * time.Second})

	type result struct {
		code int
		body string
		err  error
	}
	got := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/") //nolint:noctx // test server
		if err != nil {
			got <- result{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		got <- result{code: resp.StatusCode, body: string(b), err: err}
	}()

	<-started
	cancel()
	r := <-got
	if r.err != nil || r.code != http.StatusOK || r.body != "done" {
		t.Errorf("in-flight request: %d %q %v", r.code, r.body, r.err)
	}
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run: %v", err)
	}
	if n := drains.Load(); n != 1 {
		t.Errorf("Drain called %d times, want 1", n)
	}
}

func TestRunWaitsDrainDelay(t *testing.T) {
	t.Parallel()

	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	done := runAsync(ctx, []Listener{{Name: "main", Listener: ln, Handler: http.NotFoundHandler()}},
		Shutdown{Drain: func() { close(drained) }, DrainDelay: 300 * time.Millisecond, Timeout: time.Second})
	cancel()
	<-drained
	start := time.Now()
	// During the delay the listener still accepts.
	resp, err := http.Get("http://" + ln.Addr().String() + "/") //nolint:noctx // test server
	if err != nil {
		t.Fatalf("request during the drain delay: %v", err)
	}
	_ = resp.Body.Close()
	if err := waitRun(t, done); err != nil {
		t.Errorf("Run: %v", err)
	}
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Errorf("Run returned %v after draining began, want about 300ms", d)
	}
}

func TestRunShutdownTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	started := make(chan struct{})
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	})
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := runAsync(ctx, []Listener{{Name: "main", Listener: ln, Handler: h}},
		Shutdown{Timeout: 100 * time.Millisecond})
	go func() {
		resp, err := http.Get("http://" + ln.Addr().String() + "/") //nolint:noctx // test server
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	<-started
	start := time.Now()
	cancel()
	err := waitRun(t, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run = %v, want an error wrapping context.DeadlineExceeded", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Run took %v after the signal", d)
	}
}

func TestRunServeError(t *testing.T) {
	t.Parallel()

	good := listen(t)
	bad := listen(t)
	_ = bad.Close()
	var drains atomic.Int32
	done := runAsync(context.Background(), []Listener{
		{Name: "main", Listener: good, Handler: http.NotFoundHandler()},
		{Name: "metrics", Listener: bad, Handler: http.NotFoundHandler()},
	}, Shutdown{Drain: func() { drains.Add(1) }, DrainDelay: time.Hour, Timeout: time.Second})

	err := waitRun(t, done)
	if err == nil || !errors.Is(err, net.ErrClosed) {
		t.Errorf("Run = %v, want the metrics listener's error", err)
	}
	if _, err := net.DialTimeout("tcp", good.Addr().String(), time.Second); err == nil {
		t.Error("the main server still accepts after the other failed")
	}
	if drains.Load() != 0 {
		t.Error("a failed server triggered the drain")
	}
}
